// Node smoke test for apkllm.wasm. Verifies the single-threaded build opens
// real APKs through libziparchive under MEMFS and that every function the
// binding exports (the surface index.html will consume) returns the shape
// module.cpp gives Python. Ground truth for the numbers is the native apkllm
// Python API on the same files — this only checks self-consistency.
//
//   node smoke.mjs [apk ...]      (defaults to dexllm's test_apk fixtures)
import { readFileSync } from "node:fs";
import { argv } from "node:process";
import createApkllm from "./build/apkllm.js";

const DEFAULT_TESTS = [
  "/home/nyahumi/Project/dexllm/test_apk/APK/app-prod-debug.apk",
  "/home/nyahumi/Project/dexllm/test_apk/APK/multidex.apk",
  "/home/nyahumi/Project/dexllm/test_apk/APK/a2dp.Vol_137.apk",
  "/home/nyahumi/Project/dexllm/test_apk/APK/CertChain.apk",
  // not a zip at all — every function must fail SOFTLY (ok=false), never throw
  "/home/nyahumi/Project/dexllm/test_apk/APK/classes.dex",
];
const TESTS = argv.length > 2 ? argv.slice(2) : DEFAULT_TESTS;
// Ground truth for the synthesized fixtures (apkllm tests/test_checks.py + native tamper_scan).
const EXPECT_FINDINGS = {
  dup: ["duplicate_entry_name"],
  janus: ["janus", "cd_entry_count_mismatch"],
  cdforge: ["cd_lfh_method_mismatch", "method_forgery"],
  readers: ["cd_lfh_method_mismatch", "method_forgery"],
  many: ["cd_lfh_method_mismatch", "method_forgery"],
  bury: ["duplicate_entry_name", "method_forgery"],
  lfhlong: ["lfh_name_mismatch"],
};
// Four-reader rule on readers.apk: exactly the forged entries whose mapped reader is STRICT
// fail extractEntry; the AssetManager ones are read raw (lenient_stored).
const EXPECT_EXTRACT = {
  readers: { rejected: ["META-INF/F.SF", "classes3.dex", "data.bin", "lib/arm64-v8a/libf.so"],
             lenient: ["assets/f.bin", "res/raw/f.bin"] },
};
const EXPECT_WOULD_OPEN = { dup: false, janus: false, cdforge: true, ctor: true, shortbad: true, tail: true, readers: true, many: true, bury: false, lfhlong: false };

const m = await createApkllm();
console.log("engine loaded, ABI", m.abi());
// signing.FROSTING_KEYS_DEFAULT (domain.js carries the same)
const FROST_KEY = Uint8Array.from(atob("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZH2+1+E07dnErAD3L6BbTnaohU0bbXriNlJI7VxJU+LjdSwPyXR5pomARAMoyPkMksLz/gitUPtFuJoPL2ziEw=="), c => c.charCodeAt(0));
// module.cpp's argument list: path, extract_native_libs, target_sdk, page_size, apk_role, role_defaulted, isolated, feature, config_for
const GATE = (path) => [path, null, null, 4096, "base", true, null, null, null];

let failures = 0;
const fail = (msg) => { console.log("  FAIL:", msg); failures++; };
const VFS = "/input.apk";

for (const path of TESTS) {
  console.log("---", path);
  const buf = readFileSync(path);
  try { m.FS.unlink(VFS); } catch (_) {}
  m.FS.writeFile(VFS, new Uint8Array(buf));
  // No "is it a zip" heuristic here: a tampered container (Janus has DEX at offset 0
  // and a valid ZIP tail; Master-Key has a PK head libziparchive refuses) is exactly
  // where head magic and the device reader disagree. The checks below are the
  // structural relations the engine itself guarantees between its readers.

  let gate;
  try {
    gate = m.installGate(...GATE(VFS));
  } catch (e) {
    const msg = (typeof e === "number" && m.getExceptionMessage) ? m.getExceptionMessage(e) : e;
    fail(`installGate threw: ${msg}`); continue;
  }
  console.log("  installGate ok=", gate.ok, gate.ok
    ? `entries=${gate.entry_count} installable=${gate.installable} needs_manifest=${gate.needs_manifest} consistent=${JSON.stringify(gate.consistent_extract_native_libs)} exceptions=${gate.exceptions.length}`
    : `error=${gate.error}`);
  if (gate.ok) {
    // Tri-state contract: installable is null exactly when the engine says a manifest
    // input is still needed (an APK with no native libs resolves without one — the
    // native Python binding returns installable=True / needs_manifest=False there too).
    if ((gate.installable === null) !== gate.needs_manifest) fail(`installable=${gate.installable} but needs_manifest=${gate.needs_manifest}`);
    if (gate.entries.length !== gate.entry_count) fail("entries.length != entry_count");
    const dex = gate.entries.find(e => e.class === "dex");
    if (dex) console.log("  first dex:", dex.name, "method=", dex.method, "gate=", dex.gate, "passes=", dex.passes);
    // the engine decides the checks and the role echo (#67)
    if (!Array.isArray(gate.checks) || gate.checks.length !== 4) fail(`installGate checks: ${JSON.stringify(gate.checks?.map(c => c.id))}`);
    if (gate.apk_role !== "base" || gate.apk_role_source !== "default") fail(`role echo ${gate.apk_role}/${gate.apk_role_source}`);
    const plan = m.extractPlan(...GATE(VFS), true);
    if (!plan.ok || plan.entries.length !== gate.entry_count || plan.checks.length !== 2) fail("extractPlan: not one row per gate entry, or not its two checks");
    const split = m.installGate(VFS, null, null, 4096, "split", false, null, null, null);
    if (!split.ok || split.apk_role !== "split") fail("installGate apk_role=split not echoed");
  }

  const heads = m.entryHeads(VFS, 8, null);
  console.log("  entryHeads ok=", heads.ok, heads.ok ? `entries=${heads.entries.length}` : `error=${heads.error}`);
  // both go through libziparchive's OpenArchive — they open or refuse together
  if (heads.ok !== gate.ok) fail(`entryHeads ok=${heads.ok} but installGate ok=${gate.ok}`);
  if (heads.ok) {
    if (heads.entries.length !== gate.entry_count) fail("entryHeads count != installGate count");
    const dexHead = heads.entries.find(e => e.class === "dex" && e.method_known !== false && e.disposition !== "rejected");
    if (dexHead) {
      const magic = Buffer.from(dexHead.head.subarray(0, 4)).toString("latin1");
      console.log("  dex head magic:", JSON.stringify(magic), "disposition=", dexHead.disposition, "complete=", dexHead.complete);
      if (magic !== "dex\n") fail(`dex head magic ${JSON.stringify(magic)}`);
      if (!(dexHead.head instanceof Uint8Array)) fail("head is not a Uint8Array");
    }
  }

  if (gate.ok) {
    // a deliverable dex extracts (a forged-method dex is the strict reader's reject: EXPECT_EXTRACT)
    const dex = gate.entries.find(e => e.class === "dex" && e.method_known);
    if (dex) {
      const ex = m.extractEntry(VFS, dex.name, 512 * 1024 * 1024);
      console.log("  extractEntry", dex.name, "ok=", ex.ok, ex.ok ? `disposition=${ex.disposition} bytes=${ex.data.length}` : `error=${ex.error}`);
      if (!ex.ok) fail("extractEntry failed on dex");
      else if (ex.data.length !== dex.uncompressed_size) fail(`extracted ${ex.data.length} != uncompressed_size ${dex.uncompressed_size}`);
    }
    const missing = m.extractEntry(VFS, "does/not/exist", 1024);
    if (missing.ok) fail("extractEntry on a missing name returned ok");
  }

  const sc = m.signingCerts(VFS);   // #58: certificates as present
  console.log("  signingCerts ok=", sc.ok, sc.ok
    ? `v2=${sc.v2 ? sc.v2.signers.length : "-"} v3=${sc.v3 ? sc.v3.signers.length : "-"} v1=${sc.v1.files.length}/${sc.v1.files_total} first=${sc.v2?.signers?.[0]?.certs?.[0]?.subject?.display ?? "-"}`
    : `error=${sc.error}`);
  if (sc.ok) {
    for (const k of ["v2", "v3", "v31", "source_stamp"]) for (const g of sc[k]?.signers ?? [])
      for (const c of g.certs) if (!/^[0-9a-f]{64}$/.test(c.sha256)) fail(`${k} certificate without a sha256`);
    if (sc.v1.files_total < sc.v1.files.length) fail("v1 files_total < listed v1 files");
    if (sc.unverified !== true || sc.rendering !== "jdk17_x500principal_rfc2253") fail("signingCerts unverified / rendering");
  }
  const sb = m.signingBlockPairs(VFS, 256, [0x7109871a, 0xf05368c0]);
  console.log("  signingBlockPairs ok=", sb.ok, sb.ok
    ? `framing_found=${sb.framing_found} pairs=${(sb.pairs ?? []).map(b => "0x" + b.id.toString(16)).join(",") || "-"} total=${sb.pairs_total ?? "-"}`
    : `error=${sb.error}`);
  if (sb.ok && sb.framing_found) {
    if (sb.pairs_total < sb.pairs.length) fail("pairs_total < listed pairs");
    if (sb.tracked.length !== 2) fail("tracked is not one row per tracked ID");
    for (const t of sb.tracked) { const k = sb.pairs.filter(p => p.id === t.id).length; if (sb.pairs_total === sb.pairs.length && t.count !== k) fail(`tracked 0x${t.id.toString(16)} count ${t.count} != ${k} listed`); }
  }
  const bt = m.buildTraces(VFS);
  console.log("  buildTraces ok=", bt.ok, bt.ok ? `v1_files=${bt.v1_signer_files_total} created_by=${JSON.stringify(bt.manifest_main?.created_by ?? null)}` : `error=${bt.error}`);
  // one direction only: the gate's full iteration can fail on an entry (Next: Inconsistent
  // information) that a META-INF/ prefix walk never reaches (lfhlong) — native does the same
  if (gate.ok && !bt.ok) fail(`buildTraces ok=false but installGate opened it: ${bt.error}`);
  if (bt.ok && !/^[0-9a-f]{64}$/.test(bt.file_sha256)) fail("buildTraces without a file sha256");
  if (bt.ok && gate.ok) {
    const want = gate.entries.filter(e => e.name.startsWith("META-INF/") && [".SF", ".RSA", ".DSA", ".EC"].some(x => e.name.endsWith(x))).length;
    if (bt.v1_signer_files_total !== want) fail(`buildTraces v1 total ${bt.v1_signer_files_total} != ${want} matching gate entries`);
    const mf = m.entryHeads(VFS, 4096, ["META-INF/MANIFEST.MF"]);
    if (!mf.ok || mf.entries.length !== gate.entries.filter(e => e.name === "META-INF/MANIFEST.MF").length) fail("entryHeads name filter: wrong entry set");
  }

  const cm = m.contentMap(VFS, 512);
  console.log("  contentMap ok=", cm.ok, cm.ok ? `entries=${cm.entry_count} types=${JSON.stringify(cm.summary.by_content_type)}` : `error=${cm.error}`);
  if (cm.ok !== heads.ok) fail(`contentMap ok=${cm.ok} but entryHeads ok=${heads.ok}`);
  // the worker pairs content rows with entryHeads rows by index: the two walks must align
  if (cm.ok && heads.ok && cm.entries.some((e, i) => heads.entries[i]?.name !== e.name || heads.entries[i]?.name_hex !== e.name_hex)) fail("contentMap rows do not align with entryHeads rows");
  if (cm.ok && cm.checks.length !== 2) fail("contentMap: not its two checks");

  const fr = m.frosting(VFS, [FROST_KEY]);
  console.log("  frosting ok=", fr.ok, fr.ok ? `play_result=${fr.play_result} present=${fr.present} signature=${fr.signature} digest=${fr.file_digest_match} catalog=${fr.protobuf?.catalog?.length ?? "-"}` : `error=${fr.error}`);
  if (!fr.ok) fail(`frosting failed: ${fr.error}`);
  else {
    if (fr.protobuf !== null && fr.signature !== true) fail("frosting protobuf without a verified signature");
    if (fr.present === false && fr.play_result !== "NO_FROSTING_BLOCK") fail(`no frosting pair but play_result ${fr.play_result}`);
  }
  const noKey = m.frosting(VFS, []);
  if (noKey.ok !== false) fail("frosting with no key did not refuse");

  const ts = m.tamperReport(VFS);
  if (ts.ok && (ts.checks?.length !== 2 || !ts.summary)) fail("tamperReport without its summary / two checks");
  console.log("  tamperReport ok=", ts.ok, ts.ok
    ? `cd_records=${ts.cd_records} would_open=${ts.libziparchive_would_open} findings=${ts.findings.length}${ts.findings.length ? " " + JSON.stringify(ts.findings.map(f => f.id)) : ""}`
    : `error=${ts.error}`);
  // both key on the ZIP tail (EOCD) — they find it or not together, at the same offset
  if (ts.ok !== sb.ok) fail(`tamperReport ok=${ts.ok} but signingBlockPairs ok=${sb.ok}`);
  if (ts.ok && sb.ok && ts.signing_block_present !== sb.framing_found) fail("signing_block_present disagree");
  // the raw walker's prediction of the device reader must match what libziparchive did
  if (ts.ok && ts.libziparchive_would_open !== gate.ok) fail(`tamper predicts would_open=${ts.libziparchive_would_open} but installGate ok=${gate.ok}`);
  if (!ts.ok && gate.ok) fail("no ZIP tail for the raw walker, yet libziparchive opened it");
  if (ts.ok && gate.ok && ts.cd_records !== gate.entry_count) fail(`tamperReport cd_records ${ts.cd_records} != installGate ${gate.entry_count}`);
  // tamper_fixtures.py shapes: the findings path must actually fire, not just not crash
  const base = path.split("/").pop().replace(/\.apk$/, "");
  if (ts.ok && EXPECT_FINDINGS[base]) {
    const ids = new Set(ts.findings.map(f => f.id));
    for (const id of EXPECT_FINDINGS[base]) if (!ids.has(id)) fail(`${base}.apk: expected finding ${id}, got ${JSON.stringify([...ids])}`);
  }
  if (ts.ok && EXPECT_WOULD_OPEN[base] !== undefined && ts.libziparchive_would_open !== EXPECT_WOULD_OPEN[base]) fail(`${base}.apk: would_open=${ts.libziparchive_would_open}`);
  if (gate.ok && EXPECT_EXTRACT[base]) {
    const rejected = [], lenient = [];
    for (const e of gate.entries) {
      const x = m.extractEntry(VFS, e.name, 512 * 1024 * 1024);
      if (!x.ok) rejected.push(e.name); else if (x.disposition === "lenient_stored") lenient.push(e.name);
    }
    const want = EXPECT_EXTRACT[base];
    if (JSON.stringify(rejected.sort()) !== JSON.stringify(want.rejected)) fail(`${base}.apk: extract rejected ${JSON.stringify(rejected)}`);
    if (JSON.stringify(lenient.sort()) !== JSON.stringify(want.lenient)) fail(`${base}.apk: lenient_stored ${JSON.stringify(lenient)}`);
    console.log("  four-reader extract: rejected", rejected.length, "lenient", lenient.length);
  }
}

if (failures) { console.error(failures, "check(s) failed"); process.exit(1); }
console.log("ALL OK");
