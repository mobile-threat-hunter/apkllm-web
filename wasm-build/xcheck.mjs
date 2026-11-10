// Cross-check the web stack (apkllm.wasm + domain.js — what the worker runs) against
// apkllm's native Python layer on the same APKs.
//
//   1. native:  cd ~/Project/apkllm && PYTHONPATH=src .venv/bin/python -P \
//                 ~/Project/apkllm-web/wasm-build/xcheck.py /tmp/native.json APK... [--frost-key B64]
//   2. wasm:    node xcheck.mjs /tmp/native.json
//
// Since apkllm #67 every report is the engine's on both sides (pybind11 / embind convert the same
// Value), so they are compared whole, key order included — except where the platform legitimately
// differs: libziparchive iterates its hash table, keyed by std::hash<std::string_view>, which libc++
// computes with murmur2 on a 32-bit size_t (wasm32) and CityHash64 on 64-bit. So per-entry rows
// are compared by name (never by index), a histogram's tie order is not compared, and past build
// traces' 64-name cap WHICH v1 signer files are kept differs (only the total and count are compared).
// A JS object also lists integer-like keys first (app-metadata: compared sorted). Any other
// difference is a bug in the binding (wasm_module.cpp) or domain.js.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { argv } from "node:process";

const require = createRequire(import.meta.url);
require("../domain.js");
const D = globalThis.ApkllmDomain;
const createApkllm = (await import("./build/apkllm.js")).default;

const native = JSON.parse(readFileSync(argv[2], "utf8"));
const keysets = native._frost_keysets; delete native._frost_keysets;
const m = await createApkllm();
const VFS = "/input.apk";
let diffs = 0;

// JSON.stringify keeps -0 as 0 and both sides' floats are the engine's: exact
function diff(where, a, b) {
  const ja = JSON.stringify(a), jb = JSON.stringify(b);
  if (ja !== jb) { diffs++; console.log(`  DIFF ${where}\n    native: ${jb?.slice(0, 300)}\n    wasm:   ${ja?.slice(0, 300)}`); }
}
const byName = (xs) => { const m = new Map(); for (const x of xs) m.set(x.name, (m.get(x.name) || []).concat([x])); return m; };
const sortedObj = (o) => Object.fromEntries(Object.entries(o).sort());
// every row of `w` must equal one row of `n` with its name (several when names decode alike)
function cmpRows(where, w, n) {
  diff(`${where}.length`, w.length, n.length);
  const nm = byName(n);
  diff(`${where}.names`, [...byName(w).keys()].sort(), [...nm.keys()].sort());
  for (const e of w) {
    const cs = nm.get(e.name) || [];
    const hit = cs.find(x => JSON.stringify(x) === JSON.stringify(e));
    if (!hit) diff(`${where}[${e.name}]`, e, cs.find(x => x.name_hex === e.name_hex) || cs[0]);
  }
}
// a whole report: rows by name, the named histograms sorted, everything else exact (key order too)
function cmpReport(where, w, n, rows = "entries", hists = []) {
  diff(`${where}.keys`, Object.keys(w), Object.keys(n));
  if (!w.ok || !n.ok) { diff(where, w, n); return; }
  for (const k of Object.keys(n)) {
    if (k === rows) cmpRows(`${where}.${k}`, w[k], n[k]);
    else if (k === "summary") {
      diff(`${where}.summary.keys`, Object.keys(w.summary), Object.keys(n.summary));
      for (const s of Object.keys(n.summary))
        diff(`${where}.summary.${s}`, hists.includes(s) ? sortedObj(w.summary[s]) : w.summary[s], hists.includes(s) ? sortedObj(n.summary[s]) : n.summary[s]);
    } else diff(`${where}.${k}`, w[k], n[k]);
  }
}
const GATE_ARGS = (key) => {
  const [enl, tsdk, page, f] = JSON.parse(key);
  const defaulted = !("apk_role" in f);
  return [VFS, enl, tsdk, page, defaulted ? "base" : f.apk_role, defaulted,
          f.isolated_splits ?? null, f.feature_split ?? null, f.config_for_split ?? null];
};
const der = (b64) => Uint8Array.from(Buffer.from(b64, "base64"));

for (const [path, n0] of Object.entries(native)) {
  console.log("---", path);
  // an engine error names the file it opened: the native path there, the MEMFS file here
  const n = JSON.parse(JSON.stringify(n0).split(JSON.stringify(path).slice(1, -1)).join(VFS));
  try { m.FS.unlink(VFS); } catch (_) {}
  m.FS.writeFile(VFS, new Uint8Array(readFileSync(path)));

  cmpReport("content", m.contentMap(VFS, D.HEAD_BYTES), n.content, "entries", ["by_content_type", "by_category", "unknown_by_kind"]);
  // the raw walk is the CD's own order on both sides (not libziparchive's hash table): exact
  diff("tamper", m.tamperReport(VFS), n.tamper);

  for (const [key, ng] of Object.entries(n.gate)) {
    const args = GATE_ARGS(key);
    const g = m.installGate(...args);
    cmpReport(`gate[${key}]`, { ...g, exceptions: g.ok ? g.exceptions.map(i => g.entries[i].name).sort() : undefined },
              { ...ng, exceptions: ng.ok ? ng.exceptions.map(i => ng.entries[i].name).sort() : undefined });
    cmpReport(`extract[${key}]`, m.extractPlan(...args, true), n.extract_report[key], "entries", ["by_disposition", "by_reader"]);
  }

  // device-faithful bytes, every entry, via its own mapped reader
  for (const [name, ne] of Object.entries(n.extracted)) {   // "x:<name_hex>" | "s:<name>"
    const key = name.startsWith("x:") ? Uint8Array.from(name.slice(2).match(/../g) || [], h => parseInt(h, 16)) : name.slice(2);
    const r = m.extractEntry(VFS, key, 512 * 1024 * 1024);
    const we = r.ok ? { ok: true, disposition: r.disposition, size: r.data.length, sha256: createHash("sha256").update(r.data).digest("hex") } : { ok: false, error: r.error };
    // the entry extractEntry reports is the one asked for (its own name_hex, #40)
    if (r.ok) diff(`extracted[${name}].name_hex`, r.name_hex ? "x:" + r.name_hex : "s:" + r.name, name);
    diff(`extracted[${name}]`, we, ne);
  }
  console.log(`  ${Object.keys(n.extracted).length} entries extracted & compared`);

  // signing block — exact, key order included (domain.js builds the same insertion order)
  diff("signing_block", D.signingBlock(m.signingBlockPairs(VFS, D.PAIRS_CAP, D.PAIR_IDS)), n.signing_block);
  // signer certificates (#58) — exact, key order included
  diff("signing_certs", m.signingCerts(VFS), n.signing_certs);
  // frosting (#59) — exact, under every key set the native side ran
  const sbW = D.signingBlock(m.signingBlockPairs(VFS, D.PAIRS_CAP, D.PAIR_IDS)), trW = m.tamperReport(VFS);
  keysets.forEach((ks, i) => {
    const raw = m.frosting(VFS, ks.map(der));
    diff(`frosting[keyset ${i}]`, raw, n.frosting[i]);
    diff(`frosting_view[keyset ${i}]`, D.frostingView(raw, sbW, trW, i === 0 ? "builtin" : "caller"), n.frosting_view[i]);
  });
  diff("frosting.default_key", D.FROSTING_KEYS_DEFAULT, keysets[0]);

  const normBT = (b) => {
    const o = { ...b };
    for (const k of ["app_metadata", "unreadable"]) if (o[k]) o[k] = sortedObj(o[k]);
    if (o.v1_signer_files_total > 64) o.v1_signer_files = o.v1_signer_files.length;
    return o;
  };
  const bt = m.buildTraces(VFS), nb = n.build_traces;
  diff("build_traces", normBT(bt), normBT(nb));
  if (bt.app_metadata) diff("build_traces.app_metadata.order", Object.keys(bt.app_metadata).filter(k => !/^(0|[1-9]\d*)$/.test(k)), Object.keys(nb.app_metadata).filter(k => !/^(0|[1-9]\d*)$/.test(k)));
}

if (diffs) { console.error(diffs, "difference(s)"); process.exit(1); }
console.log("ALL MATCH");
