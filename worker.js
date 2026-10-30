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
//                  { id, type: "extract", name: string }
//                      → extractEntry(...) with .data transferred
//   worker → main: { id, ok: true,  result }
//                  { id, ok: false, error: string }
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
  if (r.ok) r.checks = self.ApkllmDomain.containerChecks(r);
  return r;
}

function extract(name) {
  if (!loaded) throw new Error("no APK loaded");
  return Module.extractEntry(VFS, name, 512 * 1024 * 1024);
}

self.onmessage = async (e) => {
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
    else throw new Error("unknown message type: " + type);
    self.postMessage({ id, ok: true, result }, transfer);
  } catch (err) {
    self.postMessage({ id, ok: false, error: describeError(err) });
  }
};
