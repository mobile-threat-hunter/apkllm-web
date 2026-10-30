// Cross-check the web stack (apkllm.wasm + domain.js — what the worker runs) against
// apkllm's native Python layer on the same APKs.
//
//   1. native:  cd ~/Project/apkllm && PYTHONPATH=src .venv/bin/python -P \
//                 ~/Project/apkllm-web/wasm-build/xcheck.py /tmp/native.json APK...
//   2. wasm:    node xcheck.mjs /tmp/native.json
//
// Compares, per APK: content_map entries (content_type / category / detail /
// unknown_kind / entropy / size_validated / encrypted_flag / role & extension
// mismatch) + summary + checks; tamper_report findings + checks; install_gate
// (native dict + checks) for every input combination xcheck.py ran. Any
// difference is a bug in the port (domain.js) or the binding (wasm_module.cpp).
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { argv } from "node:process";

const require = createRequire(import.meta.url);
require("../domain.js");
const D = globalThis.ApkllmDomain;
const createApkllm = (await import("./build/apkllm.js")).default;

const native = JSON.parse(readFileSync(argv[2], "utf8"));
const m = await createApkllm();
const VFS = "/input.apk";
let diffs = 0;

function diff(where, a, b) {
  const ja = JSON.stringify(a), jb = JSON.stringify(b);
  if (ja !== jb) { diffs++; console.log(`  DIFF ${where}\n    native: ${jb?.slice(0, 300)}\n    wasm:   ${ja?.slice(0, 300)}`); }
}
// Python repr differences that are not semantic: None→null handled by JSON; floats compared with tolerance.
function cmpEntry(where, w, n) {
  for (const k of ["name", "class", "method", "disposition", "content_type", "category", "detail", "unknown_kind", "size_validated", "encrypted_flag", "role_mismatch", "extension_mismatch", "error"])
    diff(`${where}.${k}`, w[k] ?? null, n[k] ?? null);
  const ew = w.entropy, en = n.entropy;
  if ((ew == null) !== (en == null) || (ew != null && Math.abs(ew - en) > 0.0015)) diff(`${where}.entropy`, ew, en);
}
// libziparchive iterates its hash table, keyed by std::hash<std::string_view> — libc++
// hashes with murmur2 on a 32-bit size_t (wasm32) and CityHash64 on 64-bit, so the
// ENTRY ORDER legitimately differs between the wasm build and the x86-64 native build
// (the wasm order is a 32-bit device's). Compare entries by name, never by index.
const byName = (xs) => { const m = new Map(); for (const x of xs) m.set(x.name, (m.get(x.name) || []).concat([x])); return m; };
const sortedObj = (o) => Object.fromEntries(Object.entries(o).sort());
function cmpChecks(where, w, n) {
  diff(`${where}.length`, w.length, n.length);
  for (let i = 0; i < Math.min(w.length, n.length); i++) {
    const a = w[i], b = n[i];
    for (const k of ["id", "ok", "severity", "reason"]) diff(`${where}[${a.id}].${k}`, a[k], b[k]);
    diff(`${where}[${a.id}].detail`, a.detail ?? null, b.detail ?? null);
  }
}

for (const [path, n] of Object.entries(native)) {
  console.log("---", path);
  try { m.FS.unlink(VFS); } catch (_) {}
  m.FS.writeFile(VFS, new Uint8Array(readFileSync(path)));

  // content
  const heads = m.entryHeads(VFS, D.HEAD_BYTES);
  const c = D.contentMap(heads, D.HEAD_BYTES);
  diff("content.ok", c.ok, n.content.ok);
  if (c.ok && n.content.ok) {
    diff("content.entry_count", c.entry_count, n.content.entry_count);
    const normSum = (s) => ({ ...s, by_content_type: sortedObj(s.by_content_type), by_category: sortedObj(s.by_category), unknown_by_kind: sortedObj(s.unknown_by_kind) });
    const sumW = normSum(c.summary), sumN = normSum(n.content.summary);
    diff("content.summary", sumW, sumN);
    // check detail.sample is in iteration order too — compare as a name-sorted list
    const normChecks = (cs) => cs.map(x => x.detail?.sample ? { ...x, detail: { ...x.detail, sample: [...x.detail.sample].sort((a, b) => a.name < b.name ? -1 : 1) } } : x);
    cmpChecks("content.checks", normChecks(c.checks), normChecks(n.content.checks));
    const nm = byName(n.content.entries);
    diff("content.names", [...byName(c.entries).keys()].sort(), [...nm.keys()].sort());
    for (const e of c.entries) { const nn = (nm.get(e.name) || []).find(x => x.method === e.method && x.content_type === e.content_type) || (nm.get(e.name) || [])[0]; if (nn) cmpEntry(`content[${e.name}]`, e, nn); }
  } else diff("content.error", c.error, n.content.error);

  // tamper
  const t = m.tamperScan(VFS);
  diff("tamper.ok", t.ok, n.tamper.ok);
  if (t.ok && n.tamper.ok) {
    for (const k of ["eocd_offset", "central_dir_offset", "central_dir_size", "cd_records", "signing_block_present", "libziparchive_would_open"]) diff(`tamper.${k}`, t[k], n.tamper[k]);
    diff("tamper.findings", t.findings, n.tamper.findings);
    diff("tamper.entries", t.entries, n.tamper.entries);
    cmpChecks("tamper.checks", D.tamperChecks(t), n.tamper.checks);
  } else diff("tamper.error", t.error, n.tamper.error);

  // install gate, every case
  for (const [key, ng] of Object.entries(n.gate)) {
    const [enl, tsdk, scope, page] = key.split("|").map(x => x === "None" ? null : x === "True" ? true : x === "False" ? false : Number(x));
    const g = m.installGate(VFS, enl, tsdk, page, scope);
    const w = `gate[${key}]`;
    diff(`${w}.ok`, g.ok, ng.ok);
    if (!g.ok || !ng.ok) { diff(`${w}.error`, g.error, ng.error); continue; }
    for (const k of ["installable", "installable_if_extract_false", "installable_if_extract_true", "needs_manifest", "consistent_extract_native_libs", "extract_native_libs", "target_sdk", "in_base_asset_manager", "page_size", "entry_count"])
      diff(`${w}.${k}`, g[k], ng[k]);
    diff(`${w}.exceptions`, g.exceptions.map(i => g.entries[i].name).sort(), ng.exceptions.map(i => ng.entries[i].name).sort());
    const gm = byName(ng.entries);
    diff(`${w}.names`, [...byName(g.entries).keys()].sort(), [...gm.keys()].sort());
    for (const e of g.entries) { const nn = (gm.get(e.name) || [])[0]; if (nn) diff(`${w}[${e.name}]`, e, nn); }
    const normG = (cs) => cs.map(x => x.detail ? { ...x, detail: Object.fromEntries(Object.entries(x.detail).map(([k, v]) => [k, Array.isArray(v) ? [...v].sort() : v])) } : x);
    cmpChecks(`${w}.checks`, normG(D.containerChecks(g)), normG(ng.checks));
  }
}

if (diffs) { console.error(diffs, "difference(s)"); process.exit(1); }
console.log("ALL MATCH");
