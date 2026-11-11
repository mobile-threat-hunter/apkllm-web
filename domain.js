// domain.js — the part of apkllm's Python layer that still lives in Python, mirrored for the demo.
//
// Since apkllm #67 every container report is decided whole in the C++ engine (install_gate,
// extract_map / extract_report, tamper_report, content_map, build_traces, signing_certs) and
// the wasm binding converts it one to one — nothing here re-derives those. What remains is
// what container.py / signing.py still own:
//
//   container.signing_block   → signingBlock (naming the pair IDs over signing_block_pairs)
//   signing.FROSTING_KEYS_DEFAULT → the built-in key the frosting check is run with (#59)
//   signing.frosting          → frostingView (the claim rules + container view over the raw check)
//
// Verified against the Python layer by wasm-build/xcheck.{py,mjs}. Plain script (no modules)
// so the worker can importScripts() it and node can require() it for the cross-check.
(function (root) {
"use strict";

// module.cpp's ABI this page is written against (12 = frosting, apkllm #59): the worker refuses
// an apkllm.wasm with another, so a stale cached engine never feeds this page a different shape.
const ENGINE_ABI = 13;
const HEAD_BYTES = 512;   // magic.HEAD_BYTES: content_map's head per entry

// ── container.signing_block ───────────────────────────────────────────────
// The APK Signing Block's pair IDs apkllm can name (container._PAIR_NAMES, same order — the
// native `tracked` list and so `named` follow it). AOSP IDs are the apksig constants; the two
// "observed" IDs come from measured samples (apkllm #25), not from AOSP.
const PAIR_NAMES = new Map([
  [0x7109871a, ["v2", "aosp"]],
  [0xf05368c0, ["v3", "aosp"]],
  [0x1b93ad61, ["v31", "aosp"]],
  [0x2b09189e, ["source_stamp_v1", "aosp"]],
  [0x6dff800d, ["source_stamp_v2", "aosp"]],
  [0x42726577, ["verity_padding", "aosp"]],
  [0x2146444e, ["play_frosting", "observed"]],
  [0x504b4453, ["agp_dependency_info", "observed"]],
]);
const PAIR_IDS = [...PAIR_NAMES.keys()];
const PAIRS_CAP = 256;   // container._PAIRS_CAP: pairs listed per call (+ the exact total)
const idHex = (id) => "0x" + (id >>> 0).toString(16).padStart(8, "0");

// signing_block(path) over the engine's signingBlockPairs(path, PAIRS_CAP, PAIR_IDS).
function signingBlock(r) {
  if (!r.ok) return r;
  const gates = { cd_contiguous: r.cd_contiguous, zip64_locator_present: r.zip64_locator_present };
  if (!r.framing_found) return { ok: true, found: false, reason: r.error ?? "", ...gates };
  const walk_error = "malformed_entry" in r ? { entry: r.malformed_entry, reason: r.malformed_reason } : null;
  const pairs = [], seen = new Map();
  for (const p of r.pairs) {
    const [name, source] = PAIR_NAMES.get(p.id) ?? [null, null];
    pairs.push({ id: p.id, id_hex: idHex(p.id), name, name_source: source, offset: p.offset, size: p.size });
    seen.set(p.id, (seen.get(p.id) ?? 0) + 1);
  }
  const named = {}, dups = new Set();
  for (const t of r.tracked) {
    if (t.count === 0) continue;
    named[PAIR_NAMES.get(t.id)[0]] = { id_hex: idHex(t.id), count: t.count, first_entry: t.first_entry,
                                       first_offset: t.first_offset, first_size: t.first_size };
    if (t.count > 1) dups.add(idHex(t.id));
  }
  for (const [id, n] of seen) if (n > 1 && !PAIR_NAMES.has(id)) dups.add(idHex(id));
  return {
    ok: true, found: true, ...gates,
    block_offset: r.block_offset, block_size: r.block_size,
    walk_error, pairs, pairs_total: r.pairs_total, pairs_cut: r.pairs_total - pairs.length,
    named, duplicate_ids: [...dups].sort(),
    unknown_ids: [...new Set(pairs.filter(x => x.name === null).map(x => x.id_hex))].sort(),
  };
}

// ── signing.frosting (#59) ──────────────────────────────────────────────────
// signing.FROSTING_KEYS_DEFAULT: Play's frosting verification key (SPKI SHA-256 7c5ce2a4…,
// recovered from Play signatures), base64 DER SubjectPublicKeyInfo — the engine takes the DER.
const FROSTING_KEYS_DEFAULT = [
  "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZH2+1+E07dnErAD3L6BbTnaohU0bbXriNlJI7VxJU+Lj" +
  "dSwPyXR5pomARAMoyPkMksLz/gitUPtFuJoPL2ziEw==",
];
const frostingKeys = () => FROSTING_KEYS_DEFAULT.map(k => Uint8Array.from(atob(k), c => c.charCodeAt(0)));

// signing.frosting's view over the engine's raw check (signing.py frosting / _frosting_view /
// _proto_signed, key for key): `signature` from Play's own result; `file_digest_match` only once the
// signature verified, and lowered to null (`digest_reason`) when the container gives Play's view and
// the device's different bytes; `uncovered_pairs` / `uncovered_signer_schemes` = what the digest does
// not bind (every pair but the first v2 one — a v3 / v3.1 signer above all); the protobuf only under
// a verified signature that parsed. `sb` = signingBlock(...) and `tr` = the engine's tamper_report of
// the same bytes (Python reads both again; MEMFS has no other writer, so no file_changed here).
const FROSTING_SIGNED = new Set(["SUCCESS", "DIGEST_MISMATCH", "MALFORMED_FROSTING"]);
const FROSTING_FORGED = new Set(["SIGNATURE_DIDNT_VERIFY", "SIGNATURE_UPDATE_FAILED"]);
const FROSTING_VIEW_FINDINGS = ["eocd_selection_divergence", "second_eocd", "janus", "prepended_data"];
const protoSigned = (result) => FROSTING_SIGNED.has(result) && result !== "MALFORMED_FROSTING";
function frostingContainerView(raw, sb, tr) {
  if (!(sb.ok && tr.ok)) return ["container_unreadable", null, 0, null];
  const uncovered = [];
  let v2Seen = false;
  for (const p of sb.pairs ?? []) {   // Python reads sb["pairs"]: a block Play found, signing_block finds too
    if (p.id === 0x7109871a && !v2Seen) { v2Seen = true; continue; }
    uncovered.push(p.id_hex);
  }
  const named = sb.named ?? {};
  const signers = ["v3", "v31"].filter(n => n in named);
  const ids = new Set(tr.findings.map(f => f.id));
  let why = null;
  if (tr.eocd_offset !== raw.eocd_offset) why = "eocd_views_differ";
  else why = FROSTING_VIEW_FINDINGS.find(fid => ids.has(fid)) ?? null;
  if (why === null && sb.found && !sb.cd_contiguous) why = "cd_not_contiguous";
  if (why === null && !tr.libziparchive_would_open) why = "device_reader_refuses";
  return [why, uncovered, sb.pairs_cut ?? 0, signers];
}
function frostingView(raw, sb, tr, keysSource = "builtin") {
  if (raw.ok !== true) return { ok: false, error: raw.error };   // Python raises VerifierUnavailable
  const result = raw.play_result;
  const signature = FROSTING_SIGNED.has(result) ? true : FROSTING_FORGED.has(result) ? false : null;
  const claim = raw.file_digest_match;
  const out = {
    ok: true, frosting_keys_source: keysSource,
    play_result: result, uncaught: raw.uncaught, reason: result === "SUCCESS" ? null : (result || "uncaught"),
    present: raw.present, signature,
    digest_claim_matches: claim, file_digest_match: signature === true ? claim : null, digest_reason: null,
    key_index: raw.key_index, key_spki_sha256: raw.key_spki_sha256, entry_index: raw.entry_index,
    // #83: where the selected signature is and the P-256 keys recovered from it — candidates, never trusted keys
    signed_region: raw.signed_region, signature_len: raw.signature_len, signature_hex: raw.signature_hex,
    recovered_keys: raw.recovered_keys,
    covered: null, uncovered_pairs: null, uncovered_pairs_cut: 0, uncovered_signer_schemes: null,
    duplicate_frosting_pairs: Math.max(0, (raw.frosting_pairs || 0) - 1),
    duplicate_v2_pairs: Math.max(0, (raw.v2_pairs || 0) - 1),
    eocd_offset: raw.eocd_offset, block_offset: raw.block_offset,
    protobuf: protoSigned(result) ? raw.protobuf : null,
    protobuf_reason: protoSigned(result) ? null : "unverified",
  };
  if (result === "MALFORMED_FROSTING") out.protobuf_reason = raw.protobuf_reason;
  if (claim !== null) {
    if (signature !== true) out.digest_reason = "signature_not_verified";
    out.covered = { entries_cd_eocd: true, v2: raw.v2_in_digest };
    const [why, uncovered, cut, signers] = frostingContainerView(raw, sb, tr);
    out.uncovered_pairs = uncovered; out.uncovered_pairs_cut = cut;
    out.uncovered_signer_schemes = signers;
    if (why !== null && out.file_digest_match === true) { out.file_digest_match = null; out.digest_reason = why; }
  }
  return out;
}

root.ApkllmDomain = { ENGINE_ABI, HEAD_BYTES, PAIR_NAMES, PAIR_IDS, PAIRS_CAP, signingBlock,
                      FROSTING_KEYS_DEFAULT, frostingKeys, frostingView };
})(typeof self !== "undefined" ? self : globalThis);
