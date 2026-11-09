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
//                      → { tamper, signing, traces, content, input: {md5, sha256, size} }   (the manifest-independent reads)
//                  { id, type: "gate",    extractNativeLibs: bool|null, targetSdk: number|null,
//                                         pageSize: number, arscScope: bool|null }
//                      → installGate(...) + checks[]      (re-run whenever the user changes an input)
//                      (result.extract = the four-reader decompression plan over it)
//                  { id, type: "extract", name: string, name_hex: string|null }
//                      → extractEntry(...) with .data transferred
//                  { id, type: "bundle",  indices: number[] (into the gate's entries), source: {name,size}, params: <gate params> }
//                      → { blob, counts, total, input_md5 }  — every named entry through
//                        extractEntry (its OWN mapped reader), packed into a STORED zip
//                  { id, type: "single",  index: number, source: {name,size}, params: <gate params> }
//                      → { ok, blob, base, md5, entry, same } | { ok: false, entry }  — one entry,
//                        named as the bundle would ({md5} or {md5}.{sha256}; base = the zip's name)
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

// The manifest-independent reads, once per load. entryHeads is bounded per
// entry (the engine stops each reader after HEAD_BYTES), so this is the whole
// archive's worth of device-produced heads.
let INPUT = null;   // { md5, sha256, size } of the loaded APK — names its {md5}.json report
async function load(bytes) {
  INPUT = { md5: md5hex(bytes), sha256: await sha256hex(bytes), size: bytes.length };
  writeInput(bytes);
  const D = self.ApkllmDomain;
  const tamper = Module.tamperScan(VFS);
  if (tamper.ok) tamper.checks = D.tamperChecks(tamper);
  const signing = D.signingBlock(Module.signingBlockPairs(VFS, D.PAIRS_CAP, D.PAIR_IDS));
  const traces = D.buildTraces(INPUT.sha256, Module.entryNames(VFS, "META-INF/", D.V1_SIG_EXT, D.TRACE_LIST_CAP),
                               Module.entryHeads(VFS, D.TRACE_HEAD, [D.MANIFEST, D.APP_METADATA]));
  const heads = Module.entryHeads(VFS, D.HEAD_BYTES, null);
  const content = D.contentMap(heads, D.HEAD_BYTES);
  // the raw device-produced heads ride along (parallel to content.entries) for the hex view
  if (content.ok) content.heads = heads.entries.map(h => ({ name: h.name, disposition: h.disposition, complete: h.complete, head: h.head }));
  return { tamper, signing, traces, content, input: INPUT };
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
// An entry's lookup key: its raw name bytes when name_hex is set (a lossy name — the JS string is
// U+FFFD-replaced and would match nothing, #40), else the string (strict UTF-8, encoded exactly).
function nameKey(name, nameHex) {
  if (!nameHex) return name;
  const b = new Uint8Array(nameHex.length / 2);
  for (let k = 0; k < b.length; k++) b[k] = parseInt(nameHex.substr(2 * k, 2), 16);
  return b;
}
function extract(name, nameHex) {
  if (!loaded) throw new Error("no APK loaded");
  return Module.extractEntry(VFS, nameKey(name, nameHex), MAX_ENTRY);
}

// ── bulk extraction → one zip ───────────────────────────────────────────
// The bytes come ONLY from extractEntry, i.e. each entry's own mapped device reader
// (four-reader model): {0,8} → real libziparchive inflate/copy; a forged method → raw
// stored for AssetManager classes only, while the strict readers (ART dex,
// NativeLibraryHelper, generic libziparchive) reject and the entry is recorded as a
// failure with the engine's reason — never re-read with another reader's algorithm.
// The output zip is plain packaging (STORED, CRC-32) of those bytes as {md5}.bin plus the
// {input md5}.json report; it is not a reader and never touches the input archive.
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

// Output naming = apkllm's (unwrap: {md5}.apk + {input md5}.json): an extracted entry is
// stored as {md5}.bin — named by its CONTENT, never by the attacker-controlled entry name, so
// no name can traverse, collide, alias or overflow anything. Identical content is one file;
// an md5 collision (same md5, different sha256) ⇒ {md5}.{sha256}.bin, never an overwrite.
// The report JSON maps every entry name → file (+ md5 / sha256 / reader / read disposition).
const ENC = new TextEncoder();

// MD5 (RFC 1321). WebCrypto has no MD5; it is used here as a content NAME (apkllm's
// convention), never for integrity — sha256 sits next to it in the report.
const MD5_S = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
const MD5_K = Array.from({ length: 64 }, (_, i) => Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32) >>> 0);
function md5hex(bytes) {
  // streamed over 64-byte blocks with a 16-word scratch: no input-sized allocation
  const n = bytes.length, w = new Uint32Array(16), tail = new Uint8Array(128);
  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  const block = (buf, off) => {
    for (let k = 0; k < 16; k++) { const q = off + k * 4; w[k] = (buf[q] | buf[q + 1] << 8 | buf[q + 2] << 16 | buf[q + 3] << 24) >>> 0; }
    let a = a0, b = b0, c = c0, d = d0;
    for (let i = 0; i < 64; i++) {
      let f, g;
      if (i < 16) { f = (b & c) | (~b & d); g = i; }
      else if (i < 32) { f = (d & b) | (~d & c); g = (5 * i + 1) & 15; }
      else if (i < 48) { f = b ^ c ^ d; g = (3 * i + 5) & 15; }
      else { f = c ^ (b | ~d); g = (7 * i) & 15; }
      const t = d; d = c; c = b;
      const x = (a + f + MD5_K[i] + w[g]) | 0, s = MD5_S[(i >> 4) * 4 + (i & 3)];
      b = (b + ((x << s) | (x >>> (32 - s)))) | 0; a = t;
    }
    a0 = (a0 + a) | 0; b0 = (b0 + b) | 0; c0 = (c0 + c) | 0; d0 = (d0 + d) | 0;
  };
  const full = n - (n % 64);
  for (let off = 0; off < full; off += 64) block(bytes, off);
  const rest = n - full; tail.set(bytes.subarray(full));
  tail[rest] = 0x80;
  const end = rest < 56 ? 64 : 128, bits = n * 8;
  for (let k = 0; k < 8; k++) tail[end - 8 + k] = Math.floor(bits / 2 ** (8 * k)) & 0xff;
  block(tail, 0); if (end === 128) block(tail, 64);
  let hex = "";
  for (const v of [a0, b0, c0, d0]) for (let k = 0; k < 4; k++) hex += ((v >>> (k * 8)) & 0xff).toString(16).padStart(2, "0");
  return hex;
}
// SHA-256 (FIPS 180-4) for when WebCrypto is absent (an insecure origin): sha256 is what tells
// an md5 collision from identical content, so it must never be missing.
const SHA_K = new Uint32Array([0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);
function sha256js(bytes) {
  const n = bytes.length, w = new Uint32Array(64), h = new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]);
  const rotr = (x, k) => (x >>> k) | (x << (32 - k));
  const block = (buf, off) => {
    for (let k = 0; k < 16; k++) { const q = off + k * 4; w[k] = (buf[q] << 24 | buf[q + 1] << 16 | buf[q + 2] << 8 | buf[q + 3]) >>> 0; }
    for (let k = 16; k < 64; k++) {
      const s0 = rotr(w[k - 15], 7) ^ rotr(w[k - 15], 18) ^ (w[k - 15] >>> 3), s1 = rotr(w[k - 2], 17) ^ rotr(w[k - 2], 19) ^ (w[k - 2] >>> 10);
      w[k] = (w[k - 16] + s0 + w[k - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, hh] = h;
    for (let k = 0; k < 64; k++) {
      const t1 = (hh + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + SHA_K[k] + w[k]) >>> 0;
      const t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
      hh = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
  };
  const full = n - (n % 64), tail = new Uint8Array(128);
  for (let off = 0; off < full; off += 64) block(bytes, off);
  const rest = n - full; tail.set(bytes.subarray(full)); tail[rest] = 0x80;
  const end = rest < 56 ? 64 : 128, bits = n * 8;
  for (let k = 0; k < 8; k++) tail[end - 1 - k] = Math.floor(bits / 2 ** (8 * k)) & 0xff;
  block(tail, 0); if (end === 128) block(tail, 64);
  return Array.from(h, v => v.toString(16).padStart(8, "0")).join("");
}
// {md5}.bin per distinct content; the same md5 with another sha256 ⇒ {md5}.{sha256}.bin
function contentNamer() {
  const byMd5 = new Map();   // md5 → Map(sha256 → file)
  return (md5, sha256) => {
    const shas = byMd5.get(md5) ?? new Map(); byMd5.set(md5, shas);
    if (shas.has(sha256)) return { file: shas.get(sha256), fresh: false };
    const file = shas.size === 0 ? `${md5}.bin` : `${md5}.${sha256}.bin`;
    shas.set(sha256, file);
    return { file, fresh: true, collision: shas.size > 1 };
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
  if (!self.crypto?.subtle) return sha256js(data);   // insecure origin: WebCrypto is absent, never return null
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", data));
  return Array.from(d, x => x.toString(16).padStart(2, "0")).join("");
}

// Why an entry produced no file — kept apart so a demo limit is never shown as a device verdict:
//   name_unaddressable the lookup missed (FindEntry: Entry not found). A lossy name is looked up
//                     by its raw bytes (name_hex, #40), so this no longer follows from the name
//                     alone; it is kept for a lookup that still misses
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

const RULE = "each entry is materialized only by its own mapped device reader (four-reader model: " +
  "NativeLibraryHelper / ART.DexFileLoader strict, AssetManager lenient, libziparchive generic strict); " +
  "read = stored | inflate | lenient_stored. ok=false entries have no file and a failure cause: " +
  "reader_rejected (its strict reader rejects a forged method — the device would not load it), " +
  "name_unaddressable (the lookup missed — not a reader verdict; a name that is not valid UTF-8 is looked up by its raw bytes, name_hex), " +
  "extract_failed (apkllm's own guards or a corrupt stream — see error)";
const NAMING = "apkllm naming: a file is {md5}.bin of its CONTENT (never the entry name); identical content is one file; " +
  "an md5 collision ⇒ {md5}.{sha256}.bin; entries[].name → entries[].file is the mapping";
const reportHead = (g, msg) => ({
  tool: "apkllm-web", build: BUILD_SHA,
  input: { name: msg.source?.name ?? null, size: INPUT.size, md5: INPUT.md5, sha256: INPUT.sha256 },
  inputs: { extract_native_libs: g.extract_native_libs, target_sdk: g.target_sdk, in_base_asset_manager: g.in_base_asset_manager, page_size: g.page_size },
  rule: RULE, naming: NAMING,
});

// One gate entry through its own reader → a report row (+ the bytes when delivered).
async function extractRow(plan, i, nameCount) {
  const p = plan[i], name = p.name;
  const row = { index: i, name, name_hex: p.name_hex ?? null, class: p.class, reader: p.reader, method: p.method,
                plan_disposition: p.disposition, device_loads: p.device_loads };
  if (nameCount.get(keyOf(p)) > 1) {
    row.ok = false; row.failure = "name_unaddressable";
    row.error = `${nameCount.get(keyOf(p))} entries share these exact name bytes — a lookup cannot tell which one it returns`;
    return { row };
  }
  const r = Module.extractEntry(VFS, nameKey(name, p.name_hex), MAX_ENTRY);
  if (!r.ok) { row.ok = false; row.failure = failureCause(r.error); row.error = r.error; return { row }; }
  row.ok = true; row.read = r.disposition; row.size = r.data.length;
  if (name.endsWith("/") && r.data.length === 0) { row.kind = "directory"; row.file = null; return { row }; }
  row.kind = "file"; row.md5 = md5hex(r.data); row.sha256 = await sha256hex(r.data);
  return { row, data: r.data };
}
// One key per distinct raw name: the hex for a lossy name, the string otherwise (two entries can
// share a rendering, never their bytes — libziparchive refuses a duplicate name at open).
const keyOf = (e) => e.name_hex ? "x:" + e.name_hex : "s:" + e.name;
const nameCounts = (plan) => { const m = new Map(); for (const e of plan) m.set(keyOf(e), (m.get(keyOf(e)) ?? 0) + 1); return m; };

async function bundle(msg, progress, myCancel) {
  if (!loaded) throw new Error("no APK loaded");
  const g = gate(msg.params || {});
  if (!g.ok) throw new Error("libziparchive refused to open the container: " + g.error);
  // msg.indices index the gate's entry list (its order does not depend on the manifest inputs).
  // One report row per gate entry: rows are keyed by raw name bytes (name_hex, #40), so two names
  // that render alike stay two rows (libziparchive itself refuses a true CD duplicate).
  const plan = g.extract.entries;
  // archive order: of two different contents sharing an md5, the one met first gets {md5}.bin —
  // the same rule single() applies, so a file has one name however it was downloaded
  const idx = [...new Set(msg.indices)].filter(i => Number.isInteger(i) && i >= 0 && i < plan.length).sort((a, b) => a - b);
  if (idx.length + 1 > ZIP_MAX_ENTRIES) throw new Error(`${idx.length} entries — a ZIP32 bundle holds at most ${ZIP_MAX_ENTRIES - 1} plus the report; select fewer`);
  const nameCount = nameCounts(plan);
  const zip = zipWriter(), nameOf = contentNamer(), rows = [];
  const counts = { extracted: 0, files: 0, same_content: 0, md5_collisions: 0, directories: 0, reader_rejected: 0, name_unaddressable: 0, extract_failed: 0 };
  let held = 0, last = 0;
  for (let k = 0; k < idx.length; k++) {
    if (bundleCancel !== myCancel) throw new Error("cancelled");
    const { row, data } = await extractRow(plan, idx[k], nameCount);
    if (!row.ok) counts[row.failure]++;
    else if (row.kind === "directory") counts.directories++;
    else {
      counts.extracted++;
      const n = nameOf(row.md5, row.sha256);
      row.file = n.file;
      if (n.fresh) {
        held += data.length;
        if (held > BUNDLE_BUDGET) throw new Error(`extracted bytes passed the ${BUNDLE_BUDGET / 1048576} MiB in-browser bundle budget — select fewer entries (or use "bytes" per entry)`);
        zip.add(n.file, data); counts.files++;
        if (n.collision) counts.md5_collisions++;
      } else counts.same_content++;
    }
    rows.push(row);
    const now = Date.now();
    if (now - last > 100) { last = now; progress(k + 1, idx.length); await new Promise(r => setTimeout(r, 0)); }  // a task turn lets "cancel" in
  }
  progress(idx.length, idx.length);
  const report = { ...reportHead(g, msg), entries_total: idx.length, counts, entries: rows };
  zip.add(`${INPUT.md5}.json`, ENC.encode(JSON.stringify(report, null, 1)));
  return { blob: zip.finish(), counts, total: rows.length, input_md5: INPUT.md5 };
}

// One entry → a zip of {file} + its JSON, named exactly as in a whole-archive bundle. The name
// depends on the OTHER entries: of different contents sharing an md5 the first in archive order
// is {md5}.bin, later ones {md5}.{sha256}.bin — so every entry that could share this md5 is
// checked. An md5 match needs equal length, so that is every other deliverable entry of the
// same size (identical-content twins included, which the JSON then lists too: two downloads of
// one content produce the same {file} and the same JSON). Past the sibling budget the
// collision-proof {md5}.{sha256}.bin name is used and the JSON says the siblings were unchecked.
const SIBLING_MAX = 4096, SIBLING_BYTES = 256 * 1024 * 1024;
async function single(msg) {
  if (!loaded) throw new Error("no APK loaded");
  const g = gate(msg.params || {});
  if (!g.ok) throw new Error("libziparchive refused to open the container: " + g.error);
  const plan = g.extract.entries, i = msg.index;
  if (!Number.isInteger(i) || i < 0 || i >= plan.length) throw new Error("no such entry");
  const nc = nameCounts(plan);
  const { row, data } = await extractRow(plan, i, nc);
  if (!row.ok || row.kind === "directory") return { ok: false, entry: row };
  const size = g.entries[i].uncompressed_size;
  const sibs = plan.map((_, k) => k).filter(k => k !== i && g.entries[k].uncompressed_size === size && plan[k].deliverable && nc.get(keyOf(plan[k])) === 1);
  const same = [row];                 // entries with this exact content (md5 AND sha256)
  const firstOf = new Map([[row.sha256, i]]);   // sha256 → first index, for contents sharing this md5
  let checked = sibs.length <= SIBLING_MAX && sibs.length * size <= SIBLING_BYTES;
  if (checked) for (const k of sibs) {
    const r = await extractRow(plan, k, nc);
    if (!r.row.ok || r.row.kind !== "file" || r.row.md5 !== row.md5) continue;
    if (!(firstOf.get(r.row.sha256) <= k)) firstOf.set(r.row.sha256, k);
    if (r.row.sha256 === row.sha256) same.push(r.row);
  }
  const mine = firstOf.get(row.sha256);
  const plain = checked && [...firstOf.values()].every(k => k >= mine);
  const base = plain ? row.md5 : `${row.md5}.${row.sha256}`;
  const file = `${base}.bin`;
  for (const r of same) r.file = file;
  same.sort((a, b) => a.index - b.index);
  const zip = zipWriter();
  zip.add(file, data);
  zip.add(`${base}.json`, ENC.encode(JSON.stringify({ ...reportHead(g, msg), file, md5: row.md5, sha256: row.sha256,
    md5_siblings: checked ? { checked: sibs.length, other_contents: firstOf.size - 1 } : { checked: false, reason: `over the sibling budget (${sibs.length} same-size entries) — collision-proof {md5}.{sha256} name used` },
    entries: same }, null, 1)));
  return { ok: true, blob: zip.finish(), base, md5: row.md5, entry: row, same: same.length };
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
      self.postMessage({ id, ok: true, result: {} });
      return;
    }
    await ensureInit();
    let result, transfer = [];
    if (type === "load") result = await load(e.data.bytes);
    else if (type === "gate") result = gate(e.data);
    else if (type === "extract") {
      result = extract(e.data.name, e.data.name_hex);
      if (result.ok && result.data) transfer = [result.data.buffer];
    }
    else if (type === "single") result = await single(e.data);
    else if (type === "bundle") result = await bundle(e.data, (done, total) => self.postMessage({ id, progress: { done, total } }), cancelAt);
    else throw new Error("unknown message type: " + type);
    self.postMessage({ id, ok: true, result }, transfer);
  } catch (err) {
    self.postMessage({ id, ok: false, error: describeError(err) });
  }
}
