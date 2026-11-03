// apkllm-web analysis worker.
//
// Every engine call is synchronous in wasm; a large APK (thousands of entries,
// deflate heads for each) can take a second or more, so the engine lives on
// this worker and the main thread only renders. The APK is written to MEMFS
// once per load and every native call takes its path — the same contract as
// apkllm's Python binding (_apk_core), whose functions wasm_module.cpp mirrors.
//
// Protocol (postMessage; each call carries an opaque `id` the worker echoes):
//   main → worker: { id, type: "init",    buildSha: string }
//                  { id, type: "load",    bytes: Uint8Array }
//                      → { tamper, signing, content }   (the manifest-independent reads)
//                  { id, type: "gate",    extractNativeLibs: bool|null, targetSdk: number|null,
//                                         pageSize: number, arscScope: bool|null }
//                      → installGate(...) + checks[]      (re-run whenever the user changes an input)
//                      (result.extract = the four-reader decompression plan over it)
//                  { id, type: "extract", name: string }
//                      → extractEntry(...) with .data transferred
//                  { id, type: "bundle",  indices: number[] (into the gate's entries), source: {name,size}, params: <gate params> }
//                      → { blob, counts, total }  — every named entry through
//                        extractEntry (its OWN mapped reader), packed into a STORED zip
//   worker → main: { id, ok: true,  result }
//                  { id, ok: false, error: string }
//                  { id, progress: { done, total } }   (bundle only; any number, before the result)
//   main → worker: { type: "cancel" }   (no reply; aborts a running bundle → "cancelled")
//
// The domain layer (domain.js — apkllm's Python policy ported) runs here too,
// so the main thread receives finished report objects.

let BUILD_SHA = "";
let CREATE = null;
let Module = null;
let initPromise = null;
const VFS = "/input.apk";
let loaded = false;

function bootstrap() {
  const qs = BUILD_SHA ? "?v=" + BUILD_SHA : "";
  importScripts("domain.js" + qs, "apkllm.js" + qs);
  CREATE = self.createApkllm;   // emscripten MODULARIZE export
}

function ensureInit() {
  if (Module) return Promise.resolve();
  if (initPromise) return initPromise;
  if (!CREATE) bootstrap();
  const qs = BUILD_SHA ? "?v=" + BUILD_SHA : "";
  initPromise = CREATE({ locateFile: f => f + qs }).then(m => { Module = m; });
  return initPromise;
}

// Always a STRING. An emscripten CppException carries only excPtr; translate it
// while the exception object is still alive, and never leak {"excPtr":N}.
function describeError(err) {
  if (err == null) return "unknown error";
  if (typeof err === "string") return err;
  // emcc 4.x with -fexceptions throws the bare excPtr NUMBER; newer builds wrap it as {excPtr}.
  const ptr = typeof err === "number" ? err : (err && typeof err.excPtr === "number") ? err.excPtr : null;
  if (ptr != null && Module && typeof Module.getExceptionMessage === "function") {
    try {
      const r = Module.getExceptionMessage(ptr);
      if (Array.isArray(r)) { const msg = r.filter(Boolean).map(String).join(": "); if (msg) return msg; }
      if (typeof r === "string" && r) return r;
    } catch (_) { /* already freed */ }
  }
  if (ptr != null) return "wasm exception (excPtr=" + ptr + ")";
  if (err.message) return String(err.message);
  if (err.name) return String(err.name);
  return Object.prototype.toString.call(err);
}

function writeInput(bytes) {
  try { Module.FS.unlink(VFS); } catch (_) {}
  Module.FS.writeFile(VFS, bytes);
  loaded = true;
}

// The three manifest-independent reads, once per load. entryHeads is bounded per
// entry (the engine stops each reader after HEAD_BYTES), so this is the whole
// archive's worth of device-produced heads.
function load(bytes) {
  writeInput(bytes);
  const D = self.ApkllmDomain;
  const tamper = Module.tamperScan(VFS);
  if (tamper.ok) tamper.checks = D.tamperChecks(tamper);
  const signing = Module.locateSigningBlock(VFS);
  const heads = Module.entryHeads(VFS, D.HEAD_BYTES);
  const content = D.contentMap(heads, D.HEAD_BYTES);
  // the raw device-produced heads ride along (parallel to content.entries) for the hex view
  if (content.ok) content.heads = heads.entries.map(h => ({ name: h.name, disposition: h.disposition, complete: h.complete, head: h.head }));
  return { tamper, signing, content };
}

function gate(p) {
  if (!loaded) throw new Error("no APK loaded");
  const r = Module.installGate(VFS, p.extractNativeLibs ?? null, p.targetSdk ?? null,
                               p.pageSize ?? 4096, p.arscScope ?? null);
  if (r.ok) {
    r.checks = self.ApkllmDomain.containerChecks(r);
    r.extract = self.ApkllmDomain.extractReport(r);
  }
  return r;
}

const MAX_ENTRY = 512 * 1024 * 1024;   // same cap as apkllm.container.extract_entry
function extract(name) {
  if (!loaded) throw new Error("no APK loaded");
  return Module.extractEntry(VFS, name, MAX_ENTRY);
}

// ── bulk extraction → one zip ───────────────────────────────────────────
// The bytes come ONLY from extractEntry, i.e. each entry's own mapped device reader
// (four-reader model): {0,8} → real libziparchive inflate/copy; a forged method → raw
// stored for AssetManager classes only, while the strict readers (ART dex,
// NativeLibraryHelper, generic libziparchive) reject and the entry is recorded as a
// failure with the engine's reason — never re-read with another reader's algorithm.
// The output zip is plain packaging (STORED, CRC-32) of those bytes plus
// apkllm-extract.json; it is not a reader and never touches the input archive.
const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; }
  return t;
})();
function crc32(b) {
  let c = 0xffffffff;
  for (let i = 0; i < b.length; i++) c = CRC_TABLE[(c ^ b[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

// Entry names are attacker-controlled. Every output path is built to unpack safely on
// Linux, macOS and Windows alike:
//   - no absolute paths, no "." / ".." segments, no backslashes, control or reserved
//     characters, no trailing dot/space (Windows strips them), no DOS device stems
//     (CON, NUL, COM1, CONIN$…, also "nul .txt"), no "~" (an NTFS 8.3 alias like
//     ABCDEF~1.TXT would open a sibling's long name) — escaped as %XX, never dropped;
//   - every segment ≤ 200 UTF-8 bytes (filesystems cap a name at 255) — a longer one is
//     cut and suffixed ~<hash>; the whole path ≤ 1024 bytes (the zip field caps it at
//     65535) — a deeper one is flattened to %LONGPATH~<hash>/<leaf>;
//   - two paths that would land on the SAME file on a case-insensitive / normalizing
//     filesystem (full case folding incl. σ/ς and µ/μ, NFC/NFD, default-ignorable code
//     points HFS+ skips), or a file where a directory is needed and vice versa, are a
//     clash: the later one goes to collisions/<n>/, a namespace nothing else uses.
//   Windows Explorer's built-in unzip stops at 260-character paths; deep trees need 7-Zip
//   or long-path support (nothing escapes or collides either way).
// Every entry lands under files/; the original name → output path mapping is in the manifest.
const ENC = new TextEncoder();
const SEG_MAX = 200;
const DOS_DEVICE = /^(con|prn|aux|nul|com[0-9¹²³]|lpt[0-9¹²³]|conin\$|conout\$) *(\.|$)/i;
function fnv1a(str) {
  let h = 0x811c9dc5;
  for (const b of ENC.encode(str)) h = Math.imul(h ^ b, 0x01000193) >>> 0;
  return h.toString(16).padStart(8, "0");
}
function capSegment(seg) {
  if (ENC.encode(seg).length <= SEG_MAX) return seg;
  let cut = "";
  for (const ch of seg) { if (ENC.encode(cut + ch).length > SEG_MAX - 9) break; cut += ch; }
  return cut + "~" + fnv1a(seg);
}
function safeSegment(s) {
  if (s === "..") return "%2E%2E";
  s = s.replace(/[\x00-\x1f\x7f:*?"<>|%~]/g, c => "%" + c.charCodeAt(0).toString(16).padStart(2, "0").toUpperCase());
  s = s.replace(/[. ]+$/, m => Array.from(m, c => c === "." ? "%2E" : "%20").join(""));
  if (DOS_DEVICE.test(s)) s = "%" + s.charCodeAt(0).toString(16).toUpperCase() + s.slice(1);
  return capSegment(s);
}
const PATH_MAX = 1024;   // whole relative path; a deeper one is flattened to %LONGPATH~<hash>/<leaf>
function safePath(name) {
  const segs = name.replace(/\\/g, "/").split("/").filter(s => s !== "" && s !== ".").map(safeSegment);
  if (!segs.length) return "%EMPTY";
  const rel = segs.join("/");
  return ENC.encode(rel).length <= PATH_MAX ? rel : "%LONGPATH~" + fnv1a(name) + "/" + segs[segs.length - 1];
}
function pathClaimer() {
  const files = new Set(), dirs = new Set(); let n = 0;
  const key = (p) => p.normalize("NFC").replace(/\p{Default_Ignorable_Code_Point}/gu, "").toUpperCase().toLowerCase();
  const parents = (p) => { const out = []; let i = -1; while ((i = p.indexOf("/", i + 1)) !== -1) out.push(p.slice(0, i)); return out; };
  const clash = (p, asDir) => { const k = key(p); return files.has(k) || (!asDir && dirs.has(k)) || parents(k).some(d => files.has(d)); };
  const record = (p, asDir) => { const k = key(p); (asDir ? dirs : files).add(k); for (const d of parents(k)) dirs.add(d); };
  return (rel, asDir = false) => {
    let p = "files/" + rel;
    if (clash(p, asDir)) p = "collisions/" + (++n) + "/" + rel;
    record(p, asDir);
    return p;
  };
}

const ZIP_MAX_ENTRIES = 0xfffe;   // EOCD record count; 0xffff is the Zip64 sentinel and there is no Zip64 record
function zipWriter() {
  const parts = [], cd = [];
  let off = 0, count = 0;
  const LIMIT = 0xffffffff;
  const tooBig = () => new Error("bundle exceeds ZIP32 limits (4 GiB) — select fewer entries");
  return {
    add(path, data) {
      const name = ENC.encode(path), crc = crc32(data);
      if (name.length > 0xffff) throw new Error("output path too long: " + path.slice(0, 80));
      if (count >= ZIP_MAX_ENTRIES) throw new Error(`bundle exceeds ZIP32 limits (${ZIP_MAX_ENTRIES} entries)`);
      if (data.length >= LIMIT || off + 30 + name.length + data.length >= LIMIT) throw tooBig();
      const lfh = new DataView(new ArrayBuffer(30));
      lfh.setUint32(0, 0x04034b50, true); lfh.setUint16(4, 20, true); lfh.setUint16(6, 0x0800, true);  // UTF-8 names
      lfh.setUint16(8, 0, true); lfh.setUint16(10, 0, true); lfh.setUint16(12, 0x21, true);             // STORED, 1980-01-01
      lfh.setUint32(14, crc, true); lfh.setUint32(18, data.length, true); lfh.setUint32(22, data.length, true);
      lfh.setUint16(26, name.length, true); lfh.setUint16(28, 0, true);
      const c = new DataView(new ArrayBuffer(46));
      c.setUint32(0, 0x02014b50, true); c.setUint16(4, 20, true); c.setUint16(6, 20, true); c.setUint16(8, 0x0800, true);
      c.setUint16(10, 0, true); c.setUint16(12, 0, true); c.setUint16(14, 0x21, true);
      c.setUint32(16, crc, true); c.setUint32(20, data.length, true); c.setUint32(24, data.length, true);
      c.setUint16(28, name.length, true); c.setUint32(42, off, true);
      parts.push(new Uint8Array(lfh.buffer), name, data);
      cd.push(new Uint8Array(c.buffer), name);
      off += 30 + name.length + data.length; count++;
    },
    finish() {
      const cdSize = cd.reduce((n, b) => n + b.length, 0);
      if (off + cdSize >= LIMIT) throw tooBig();
      const e = new DataView(new ArrayBuffer(22));
      e.setUint32(0, 0x06054b50, true); e.setUint16(8, count, true); e.setUint16(10, count, true);
      e.setUint32(12, cdSize, true); e.setUint32(16, off, true);
      return new Blob([...parts, ...cd, new Uint8Array(e.buffer)], { type: "application/zip" });
    },
  };
}

async function sha256hex(data) {
  if (!self.crypto || !crypto.subtle) return null;   // insecure context (file://): skip, CRC-32 still in the zip
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", data));
  return Array.from(d, x => x.toString(16).padStart(2, "0")).join("");
}

// Why an entry produced no file — kept apart so a demo limit is never shown as a device verdict:
//   name_unaddressable the entry cannot be looked up by its name: names cross the binding
//                     as U+FFFD-replaced text (apkllm's string API, native Python alike), so
//                     an invalid-UTF-8 name misses (FindEntry: Entry not found), and two raw
//                     names that decode alike cannot be told apart — the device reader is
//                     never consulted
//   reader_rejected   its mapped STRICT reader rejects it (forged method ∉ {0,8}) — the
//                     device would not load it either; no faithful bytes exist
//   extract_failed    anything else: apkllm's own guards (512 MiB cap, implausible deflate
//                     expansion, extent past EOF) or a corrupt stream (zlib / CRC error)
function failureCause(error) {
  if (/^FindEntry: Entry not found/.test(error || "")) return "name_unaddressable";
  if (/mapped strict reader rejects/.test(error || "")) return "reader_rejected";
  return "extract_failed";
}

// Bytes held at once: every extracted entry stays referenced until the Blob is built
// (which copies them again), so cap the total well below what a tab can hold.
const BUNDLE_BUDGET = 1024 * 1024 * 1024;
let bundleCancel = 0;   // bumped by a "cancel" message (handled OUTSIDE the queue)

async function bundle(msg, progress, myCancel) {
  if (!loaded) throw new Error("no APK loaded");
  const g = gate(msg.params || {});
  if (!g.ok) throw new Error("libziparchive refused to open the container: " + g.error);
  // msg.indices index the gate's entry list (its order does not depend on the manifest inputs).
  // One manifest row per gate entry: names arrive as decoded text, so two raw names that decode
  // alike would otherwise fold into one row (libziparchive itself refuses a true CD duplicate).
  const plan = g.extract.entries;
  const idx = [...new Set(msg.indices)].filter(i => Number.isInteger(i) && i >= 0 && i < plan.length);
  if (idx.length + 1 > ZIP_MAX_ENTRIES) throw new Error(`${idx.length} entries — a ZIP32 bundle holds at most ${ZIP_MAX_ENTRIES - 1} plus the manifest; select fewer`);
  const nameCount = new Map();
  for (const e of plan) nameCount.set(e.name, (nameCount.get(e.name) ?? 0) + 1);
  const zip = zipWriter(), claim = pathClaimer(), rows = [];
  const counts = { files: 0, directories: 0, reader_rejected: 0, name_unaddressable: 0, extract_failed: 0 };
  let held = 0, last = 0;
  for (let k = 0; k < idx.length; k++) {
    if (bundleCancel !== myCancel) throw new Error("cancelled");
    const p = plan[idx[k]], name = p.name;
    const row = { index: idx[k], name, class: p.class, reader: p.reader, method: p.method,
                  plan_disposition: p.disposition, device_loads: p.device_loads };
    if (nameCount.get(name) > 1) {
      row.ok = false; row.failure = "name_unaddressable";
      row.error = `${nameCount.get(name)} entries decode to this same name — a by-name lookup cannot tell which one it returns`;
      counts.name_unaddressable++;
    } else {
      const r = Module.extractEntry(VFS, name, MAX_ENTRY);
      if (r.ok && name.endsWith("/") && r.data.length === 0) {
        // an explicit directory entry: a directory in the tree, not a 0-byte file
        row.ok = true; row.read = r.disposition; row.size = 0; row.kind = "directory";
        row.path = claim(safePath(name), true) + "/";
        zip.add(row.path, new Uint8Array(0)); counts.directories++;
      } else if (r.ok) {
        held += r.data.length;
        if (held > BUNDLE_BUDGET) throw new Error(`extracted bytes passed the ${BUNDLE_BUDGET / 1048576} MiB in-browser bundle budget — select fewer entries (or use "bytes" per entry)`);
        row.ok = true; row.read = r.disposition; row.size = r.data.length; row.kind = "file";
        row.sha256 = await sha256hex(r.data);
        row.path = claim(safePath(name));
        zip.add(row.path, r.data); counts.files++;
      } else {
        row.ok = false; row.failure = failureCause(r.error); row.error = r.error; counts[row.failure]++;
      }
    }
    rows.push(row);
    const now = Date.now();
    if (now - last > 100) { last = now; progress(k + 1, idx.length); await new Promise(r => setTimeout(r, 0)); }  // a task turn lets "cancel" in
  }
  progress(idx.length, idx.length);
  const manifest = {
    tool: "apkllm-web", build: BUILD_SHA, source: msg.source || null,
    inputs: { extract_native_libs: g.extract_native_libs, target_sdk: g.target_sdk, in_base_asset_manager: g.in_base_asset_manager, page_size: g.page_size },
    rule: "each entry is materialized only by its own mapped device reader (four-reader model: " +
          "NativeLibraryHelper / ART.DexFileLoader strict, AssetManager lenient, libziparchive generic strict); " +
          "read = stored | inflate | lenient_stored. ok=false entries have no file and a failure cause: " +
          "reader_rejected (its strict reader rejects a forged method — the device would not load it), " +
          "name_unaddressable (the entry name is not valid UTF-8 or decodes like another entry's, so the by-name lookup cannot reach it — not a reader verdict), " +
          "extract_failed (apkllm's own guards or a corrupt stream — see error)",
    entries_total: idx.length, counts, entries: rows,
  };
  zip.add("apkllm-extract.json", ENC.encode(JSON.stringify(manifest, null, 1)));
  return { blob: zip.finish(), counts, total: rows.length };
}

// Messages run strictly one at a time: bundle awaits (sha256) between engine calls, and a
// "load" interleaved there would swap /input.apk under the remaining extractEntry calls.
let queue = Promise.resolve();
// "cancel" is the one message that must NOT wait in the queue: it stops a running bundle
// (checked between entries) so a newly dropped file is not stuck behind it.
self.onmessage = (e) => {
  if (e.data.type === "cancel") { bundleCancel++; return; }
  const cancelAt = bundleCancel;   // a cancel posted after this message still reaches it while queued
  queue = queue.then(() => handle(e, cancelAt));
};

async function handle(e, cancelAt) {
  const { id, type } = e.data;
  try {
    if (type === "init") {
      BUILD_SHA = e.data.buildSha || "";
      await ensureInit();
      self.postMessage({ id, ok: true, result: { schemeV2: Module.SCHEME_V2 } });
      return;
    }
    await ensureInit();
    let result, transfer = [];
    if (type === "load") result = load(e.data.bytes);
    else if (type === "gate") result = gate(e.data);
    else if (type === "extract") {
      result = extract(e.data.name);
      if (result.ok && result.data) transfer = [result.data.buffer];
    }
    else if (type === "bundle") result = await bundle(e.data, (done, total) => self.postMessage({ id, progress: { done, total } }), cancelAt);
    else throw new Error("unknown message type: " + type);
    self.postMessage({ id, ok: true, result }, transfer);
  } catch (err) {
    self.postMessage({ id, ok: false, error: describeError(err) });
  }
}
