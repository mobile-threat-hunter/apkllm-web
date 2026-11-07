// domain.js — apkllm's thin Python domain layer, ported to JS for the browser demo.
//
// The wasm engine (apkllm.js) exposes the NATIVE facts exactly as apkllm's
// _apk_core does. Everything in this file is the pure policy apkllm layers on
// top in Python, mirrored function-for-function so the web demo shows the same
// labels and checks the Python API reports:
//
//   src/apkllm/magic.py       → SIGNATURES / classify / unknownKind / entropy
//   src/apkllm/container.py   → contentMap (per-entry typing + role/extension
//                               mismatch + checks), containerChecks (install-gate
//                               checks), tamperChecks, extractReport
//                               (_disposition + extract_map + extract_report: the
//                               four-reader decompression plan)
//
// Keep it a faithful port: same signature order, same reasons, same tri-state
// (true / false / null) semantics. Verified against the Python layer by
// wasm-build/xcheck.{py,mjs}. Plain script (no modules) so the worker can
// importScripts() it and node can require() it for the cross-check.
(function (root) {
"use strict";

// ── magic.py ──────────────────────────────────────────────────────────────
const HEAD_BYTES = 512;

const ELF_MACHINE = { 3: "x86", 8: "mips", 40: "arm", 62: "x86_64", 183: "aarch64", 243: "riscv" };

const u16 = (b, o) => b[o] | (b[o + 1] << 8);
const u32 = (b, o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
const u16be = (b, o) => (b[o] << 8) | b[o + 1];
const u32be = (b, o) => ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
const latin1 = (b) => { let s = ""; for (const c of b) s += String.fromCharCode(c); return s; };
// ignoreBOM: Python's bytes.decode keeps a leading U+FEFF; TextDecoder would eat it.
const utf8lenient = new TextDecoder("utf-8", { ignoreBOM: true });
// Python `b[at:at+n] == sig`: a short slice never equals the full signature.
function eq(b, at, sig) {
  if (b.length < at + sig.length) return false;
  for (let i = 0; i < sig.length; i++) if (b[at + i] !== sig.charCodeAt(i)) return false;
  return true;
}
const isDigit = (c) => c >= 0x30 && c <= 0x39;

function probeDex(b) {
  // AOSP: art/libdexfile/dex/standard_dex_file.cc:26 kDexMagic "dex\n" + 3-digit version + \0
  if (eq(b, 0, "dex\n") && b.length >= 8 && isDigit(b[4]) && isDigit(b[5]) && isDigit(b[6]) && b[7] === 0)
    return { version: latin1(b.subarray(4, 7)) };
  return null;
}
function probeElf(b) {
  // AOSP: bionic/linker/linker_phdr.cpp:272 — memcmp(e_ident, ELFMAG, SELFMAG)
  if (!eq(b, 0, "\x7fELF")) return null;
  const d = {};
  if (b.length >= 20) {
    d.class = { 1: 32, 2: 64 }[b[4]] ?? null;
    const little = b[5] === 1;
    const machine = little ? u16(b, 18) : u16be(b, 18);
    d.machine = ELF_MACHINE[machine] ?? machine;
  }
  return d;
}
function probeZip(b) {
  // AOSP: ART dispatches on this before any name (dex_file_loader.cc:372; file_magic.cc:64).
  if (eq(b, 0, "PK\x05\x06")) return { empty: true };
  if (!eq(b, 0, "PK\x03\x04")) return null;
  const d = {};
  if (b.length >= 10) {
    const gpb = u16(b, 6), method = u16(b, 8);
    d.first_entry_method = method;
    d.first_entry_encrypted = Boolean(gpb & 1) || method === 99;
  }
  if (b.length >= 30) {
    const n = u16(b, 26);
    d.first_entry_name = utf8lenient.decode(b.subarray(30, 30 + Math.min(n, 256)));
    if (30 + n > b.length || n > 256) d.first_entry_name_truncated = true;
  }
  return d;
}
// AOSP: androidfw/ResourceTypes.h:242-243 — ResChunk_header {u16 type, u16 headerSize}
const probeChunk = (kind, headerSize) => (b) =>
  (b.length >= 4 && u16(b, 0) === kind && u16(b, 2) === headerSize) ? {} : null;
const probePrefix = (sig, at = 0) => (b) => eq(b, at, sig) ? {} : null;
const probeRiff = (form) => (b) => (eq(b, 0, "RIFF") && eq(b, 8, form)) ? {} : null;
const FTYP = {
  heic: "heif", heix: "heif", hevc: "heif", mif1: "heif", msf1: "heif",
  avif: "avif", avis: "avif",
  "3gp4": "3gp", "3gp5": "3gp", "3gp6": "3gp", "3g2a": "3gp",
  "M4A ": "m4a", "M4B ": "m4a",
  "qt  ": "quicktime",
};
const probeFtyp = (kind) => (b) => {
  if (!eq(b, 4, "ftyp") || b.length < 12) return null;
  const brand = latin1(b.subarray(8, 12));
  return ((Object.hasOwn(FTYP, brand) ? FTYP[brand] : "mp4") === kind) ? { brand } : null;
};
function probeClass(b) {
  if (eq(b, 0, "\xca\xfe\xba\xbe") && b.length >= 8) {
    const major = u16be(b, 6);
    if (major >= 45 && major <= 100) return { major };
  }
  return null;
}
function probeMachoFat(b) {
  if (eq(b, 0, "\xca\xfe\xba\xbe") && b.length >= 8) {
    const n = u32be(b, 4);
    if (n > 0 && n < 32) return { fat: true };
  }
  return null;
}
const probeGzip = (b) => eq(b, 0, "\x1f\x8b\x08") ? {} : null;
const probeBmp = (b) => (eq(b, 0, "BM") && b.length >= 10 && u32(b, 6) === 0) ? {} : null;
function probeIco(b) {
  if ((eq(b, 0, "\x00\x00\x01\x00") || eq(b, 0, "\x00\x00\x02\x00")) && b.length >= 6) {
    const n = u16(b, 4);
    return (n > 0 && n < 256) ? {} : null;
  }
  return null;
}
function probeMp3Frame(b) {
  if (b.length >= 3 && b[0] === 0xff && (b[1] & 0xe6) === 0xe2) {
    const br = b[2] >> 4, sr = (b[2] >> 2) & 3;
    return (br !== 0 && br !== 15 && sr !== 3) ? {} : null;
  }
  return null;
}
const probeAac = (b) => (b.length >= 2 && b[0] === 0xff && (b[1] & 0xf6) === 0xf0) ? {} : null;
function probePe(b) {
  if (!eq(b, 0, "MZ") || b.length < 64) return null;
  const lfanew = u32(b, 60);
  if (lfanew + 4 <= b.length) return eq(b, lfanew, "PE\x00\x00") ? {} : null;
  return { pe_header_unchecked: true };
}
function probeDer(b, size) {
  if (eq(b, 0, "\x30\x82") && b.length >= 4) return (u16be(b, 2) + 4 === size) ? {} : null;
  return null;
}
const probeZlib = (b) => (b.length >= 2 && b[0] === 0x78 && (b[1] === 0x01 || b[1] === 0x5e || b[1] === 0x9c || b[1] === 0xda)) ? {} : null;
const probeSfnt = (tag) => (b) => {
  if (!eq(b, 0, tag) || b.length < 8) return null;
  const n = u16be(b, 4);
  if (n < 1 || n > 256) return null;
  const floorLog2 = 31 - Math.clz32(n);  // n.bit_length() - 1
  return u16be(b, 6) === 16 * (1 << floorLog2) ? {} : null;
};
const probeTar = (b) => eq(b, 257, "ustar") ? {} : null;
const probeTextSig = (...sigs) => (b) => {
  let s = (b.length >= 3 && b[0] === 0xef && b[1] === 0xbb && b[2] === 0xbf) ? b.subarray(3) : b;
  let i = 0;
  while (i < s.length && (s[i] === 0x20 || s[i] === 0x09 || s[i] === 0x0d || s[i] === 0x0a)) i++;
  s = s.subarray(i);
  // bytes.lower() is ASCII-only
  const lower = new Uint8Array(s.length);
  for (let k = 0; k < s.length; k++) { const c = s[k]; lower[k] = (c >= 0x41 && c <= 0x5a) ? c + 32 : c; }
  return sigs.some(x => eq(lower, 0, x)) ? {} : null;
};

// (content_type, category, probe) — order matters only where signatures overlap.
const SIGNATURES = [
  // Android / ART / framework
  ["dex", "android", probeDex],
  ["vdex", "android", probePrefix("vdex")],            // AOSP: art/runtime/vdex_file.h:123
  ["art_image", "android", probePrefix("art\n")],      // AOSP: art/runtime/oat/image.cc:37
  ["art_profile", "android", probePrefix("pro\x00")],  // AOSP: profile_compilation_info.cc:71
  ["art_profile_metadata", "android", probePrefix("prm\x00")],
  ["axml", "android", probeChunk(0x0003, 8)],
  ["arsc", "android", probeChunk(0x0002, 12)],
  ["abx", "android", probePrefix("ABX\x00")],
  ["aapt2_container", "android", probePrefix("AAPT")],
  ["android_bootimg", "android", probePrefix("ANDROID!")],
  ["android_sparse_image", "android", probePrefix("\x3a\xff\x26\xed")],
  // executables / bytecode
  ["elf", "executable", probeElf],
  ["pe", "executable", probePe],
  ["macho", "executable", probePrefix("\xcf\xfa\xed\xfe")],
  ["macho", "executable", probePrefix("\xce\xfa\xed\xfe")],
  ["macho", "executable", probePrefix("\xfe\xed\xfa\xcf")],
  ["macho", "executable", probePrefix("\xfe\xed\xfa\xce")],
  ["java_class", "executable", probeClass],
  ["macho", "executable", probeMachoFat],
  ["wasm", "executable", probePrefix("\x00asm")],
  ["hermes_bytecode", "executable", probePrefix("\xc6\x1f\xbc\x03\xc1\x03\x19\x1f")],
  ["lua_bytecode", "executable", probePrefix("\x1bLua")],
  ["luajit_bytecode", "executable", probePrefix("\x1bLJ")],
  ["xamarin_compressed_assembly", "executable", probePrefix("XALZ")],
  ["xamarin_assembly_blob", "executable", probePrefix("XABA")],
  // archives / compression
  ["zip", "archive", probeZip],
  ["gzip", "archive", probeGzip],
  ["bzip2", "archive", probePrefix("BZh")],
  ["xz", "archive", probePrefix("\xfd7zXZ\x00")],
  ["zstd", "archive", probePrefix("\x28\xb5\x2f\xfd")],
  ["lz4", "archive", probePrefix("\x04\x22\x4d\x18")],
  ["7z", "archive", probePrefix("7z\xbc\xaf\x27\x1c")],
  ["rar", "archive", probePrefix("Rar!\x1a\x07")],
  ["cab", "archive", probePrefix("MSCF")],
  ["ar", "archive", probePrefix("!<arch>\n")],
  ["tar", "archive", probeTar],
  ["zlib", "archive", probeZlib],
  // images
  ["png", "image", probePrefix("\x89PNG\r\n\x1a\n")],
  ["jpeg", "image", probePrefix("\xff\xd8\xff")],
  ["gif", "image", probePrefix("GIF87a")],
  ["gif", "image", probePrefix("GIF89a")],
  ["webp", "image", probeRiff("WEBP")],
  ["heif", "image", probeFtyp("heif")],
  ["avif", "image", probeFtyp("avif")],
  ["bmp", "image", probeBmp],
  ["ico", "image", probeIco],
  ["tiff", "image", probePrefix("II*\x00")],
  ["tiff", "image", probePrefix("MM\x00*")],
  ["psd", "image", probePrefix("8BPS")],
  ["ktx", "image", probePrefix("\xabKTX 11\xbb")],
  ["ktx2", "image", probePrefix("\xabKTX 20\xbb")],
  ["pkm", "image", probePrefix("PKM ")],
  ["astc", "image", probePrefix("\x13\xab\xa1\x5c")],
  ["dds", "image", probePrefix("DDS ")],
  // audio / video
  ["ogg", "media", probePrefix("OggS")],
  ["flac", "media", probePrefix("fLaC")],
  ["wav", "media", probeRiff("WAVE")],
  ["avi", "media", probeRiff("AVI ")],
  ["mp3", "media", probePrefix("ID3")],
  ["mp3", "media", probeMp3Frame],
  ["aac", "media", probeAac],
  ["amr", "media", probePrefix("#!AMR")],
  ["midi", "media", probePrefix("MThd")],
  ["mkv_webm", "media", probePrefix("\x1a\x45\xdf\xa3")],
  ["flv", "media", probePrefix("FLV\x01")],
  ["3gp", "media", probeFtyp("3gp")],
  ["m4a", "media", probeFtyp("m4a")],
  ["quicktime", "media", probeFtyp("quicktime")],
  ["mp4", "media", probeFtyp("mp4")],
  // fonts
  ["ttf", "font", probeSfnt("\x00\x01\x00\x00")],
  ["ttf", "font", probeSfnt("true")],
  ["otf", "font", probeSfnt("OTTO")],
  ["ttc", "font", probePrefix("ttcf")],
  ["woff", "font", probePrefix("wOFF")],
  ["woff2", "font", probePrefix("wOF2")],
  // documents
  ["pdf", "document", probePrefix("%PDF-")],
  ["ole2", "document", probePrefix("\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")],
  ["rtf", "document", probePrefix("{\\rtf")],
  // data / keys
  ["sqlite", "data", probePrefix("SQLite format 3\x00")],
  ["realm", "data", probePrefix("T-DB", 16)],
  ["tflite", "data", probePrefix("TFL3", 4)],
  ["unity_bundle", "data", probePrefix("UnityFS\x00")],
  ["unity_bundle", "data", probePrefix("UnityWeb\x00")],
  ["unity_bundle", "data", probePrefix("UnityRaw\x00")],
  ["jks", "key", probePrefix("\xfe\xed\xfe\xed")],
  ["jceks", "key", probePrefix("\xce\xce\xce\xce")],
  ["der", "key", probeDer],
  ["pem", "key", probeTextSig("-----begin ")],
  // text formats with a fixed opening
  ["xml", "text_format", probeTextSig("<?xml")],
  ["svg", "text_format", probeTextSig("<svg")],
  ["html", "text_format", probeTextSig("<!doctype html", "<html")],
  ["script", "text_format", probeTextSig("#!")],
];
const CATEGORY = {};
for (const [t, c] of SIGNATURES) if (!(t in CATEGORY)) CATEGORY[t] = c;

function classify(head, size) {
  const total = size == null ? head.length : size;
  for (const [kind, , probe] of SIGNATURES) {
    let d = null;
    try { d = probe(head, total); } catch (_) { d = null; }
    if (d !== null) return [kind, d];
  }
  return ["unknown", {}];
}

// Python: strict UTF-8 decode, tolerating only a CUT head's trailing incomplete sequence.
const utf8strict = new TextDecoder("utf-8", { fatal: true });
function utf8expectedLen(lead) {
  if (lead >= 0xf0 && lead <= 0xf4) return 4;
  if (lead >= 0xe0) return 3;
  if (lead >= 0xc2) return 2;
  return 0;
}
function unknownKind(head, size) {
  if (size === 0) return "empty";
  if (head.length === 0) return "binary";
  const s = (head.length >= 3 && head[0] === 0xef && head[1] === 0xbb && head[2] === 0xbf) ? head.subarray(3) : head;
  let text;
  try { text = utf8strict.decode(s); }
  catch (_) {
    const truncated = head.length < size;
    text = null;
    if (truncated) {
      // CPython raises "unexpected end of data" (the only reason Python tolerates, and only
      // at e.start >= len(s) - 3) when a VALID lead byte (C2–F4) in the last 3 bytes is
      // followed by only valid continuation bytes — fewer than it needs. Any other
      // defect ("invalid start byte" / "invalid continuation byte") is binary.
      for (let k = Math.max(0, s.length - 3); k < s.length; k++) {
        const lead = s[k], need = utf8expectedLen(lead);
        if (!need || lead > 0xf4 || k + need <= s.length) continue;
        let ok = true;
        for (let j = k + 1; j < s.length; j++) {
          const c = s[j];
          let lo = 0x80, hi = 0xbf;
          if (j === k + 1) {
            if (lead === 0xe0) lo = 0xa0; else if (lead === 0xed) hi = 0x9f;
            else if (lead === 0xf0) lo = 0x90; else if (lead === 0xf4) hi = 0x8f;
          }
          if (c < lo || c > hi) { ok = false; break; }
        }
        if (ok) { try { text = utf8strict.decode(s.subarray(0, k)); } catch (_) { text = null; } }
        break;
      }
    }
    if (text === null) return "binary";
  }
  for (const ch of text) {
    if (ch === "\t" || ch === "\r" || ch === "\n" || ch === "\f" || ch === "\v") continue;
    const cp = ch.codePointAt(0);
    if (cp < 0x20 || (cp >= 0x7f && cp <= 0x9f)) return "binary";   // Cc
    if (cp >= 0xd800 && cp <= 0xdfff) return "binary";               // Cs (lone surrogate)
  }
  return "text";
}

function entropy(head) {
  const n = head.length;
  if (!n) return 0;
  const counts = new Uint32Array(256);
  for (const c of head) counts[c]++;
  let h = 0;
  for (const c of counts) if (c) { const p = c / n; h -= p * Math.log2(p); }
  return h;
}

// ── container.py ─────────────────────────────────────────────────────────
function check(id, ok, severity, reason, detail) {
  const c = { id, ok, severity, reason };
  if (detail) c.detail = detail;
  return c;
}

const ROLE_EXPECTS = {
  dex: ["dex"],                 // ART opens root classes*.dex and checks kDexMagic
  manifest: ["axml"],           // AssetManager → ResXMLTree::setTo checks RES_XML_TYPE
  resources_arsc: ["arsc"],     // ResTable checks RES_TABLE_TYPE
  native_lib: ["elf"],          // linker ElfReader::VerifyElfHeader
};
const EXT_EXPECTS = {
  dex: ["dex"], so: ["elf"], jar: ["zip"], apk: ["zip"], zip: ["zip"], aar: ["zip"],
  png: ["png"], jpg: ["jpeg"], jpeg: ["jpeg"], gif: ["gif"], webp: ["webp"], bmp: ["bmp"],
  ico: ["ico", "png", "bmp"], heic: ["heif"], avif: ["avif"],
  mp3: ["mp3"], ogg: ["ogg"], wav: ["wav"], flac: ["flac"], aac: ["aac"], amr: ["amr"], mid: ["midi"],
  mp4: ["mp4", "quicktime", "3gp", "m4a"], m4a: ["m4a", "mp4"], "3gp": ["3gp", "mp4"],
  webm: ["mkv_webm"], mkv: ["mkv_webm"],
  ttf: ["ttf"], otf: ["otf", "ttf"], ttc: ["ttc"], woff: ["woff"], woff2: ["woff2"],
  pdf: ["pdf"], doc: ["ole2"], xls: ["ole2"], ppt: ["ole2"], docx: ["zip"], xlsx: ["zip"], pptx: ["zip"],
  db: ["sqlite"], sqlite: ["sqlite"], gz: ["gzip"], "7z": ["7z"], class: ["java_class"],
  tflite: ["tflite"], prof: ["art_profile"], profm: ["art_profile_metadata"],
  rsa: ["der"], dsa: ["der"], ec: ["der"], bks: [],
};
function ext(name) {
  const base = name.slice(name.lastIndexOf("/") + 1);
  const dot = base.indexOf(".", 1);
  return dot === -1 ? "" : base.slice(base.lastIndexOf(".") + 1).toLowerCase();
}

// container.content_map over an entry_heads() result (the native call already made).
function contentMap(r, headBytes) {
  if (!r.ok) return r;
  const entries = [];
  for (const e of r.entries) {
    const head = e.head, size = e.uncompressed_size;
    const readable = e.disposition === "stored" || e.disposition === "inflate" || e.disposition === "lenient_stored";
    const [ctype, detail] = readable ? classify(head, size) : ["unknown", {}];
    const item = {
      name: e.name, name_hex: e.name_hex, class: e.class, method: e.method, disposition: e.disposition,
      content_type: ctype, category: CATEGORY[ctype] ?? "unknown", detail,
      entropy: readable ? Math.round(entropy(head) * 1000) / 1000 : null,
      size_validated: Boolean(e.complete) && (e.disposition === "stored" || e.disposition === "inflate"),
      encrypted_flag: Boolean(e.gpbf & 1),
    };
    if (ctype === "unknown") item.unknown_kind = readable ? unknownKind(head, size) : "unreadable";
    if (e.error !== undefined) item.error = e.error;
    const want = ROLE_EXPECTS[e.class];
    item.role_mismatch = want === undefined ? false : (!readable ? null : !want.includes(ctype));
    // Python dict.get() has no prototype chain: "x.constructor" / "x.__proto__" must miss.
    const x = ext(e.name);
    const extWant = Object.hasOwn(EXT_EXPECTS, x) ? EXT_EXPECTS[x] : undefined;
    item.extension_mismatch = extWant === undefined ? false : (!readable ? null : !extWant.includes(ctype));
    entries.push(item);
  }
  const byType = {}, byCat = {}, byUnknown = {};
  for (const it of entries) {
    byType[it.content_type] = (byType[it.content_type] ?? 0) + 1;
    byCat[it.category] = (byCat[it.category] ?? 0) + 1;
    if ("unknown_kind" in it) byUnknown[it.unknown_kind] = (byUnknown[it.unknown_kind] ?? 0) + 1;
  }
  const sortDesc = (o) => Object.fromEntries(Object.entries(o).sort((a, b) => b[1] - a[1]));
  const roleBad = entries.filter(it => it.role_mismatch === true);
  const roleUnk = entries.filter(it => it.role_mismatch === null);
  const extBad = entries.filter(it => it.extension_mismatch === true);
  const extUnk = entries.filter(it => it.extension_mismatch === null);
  const summary = {
    by_content_type: sortDesc(byType), by_category: sortDesc(byCat), unknown_by_kind: byUnknown,
    role_mismatch: roleBad.length, role_indeterminate: roleUnk.length,
    extension_mismatch: extBad.length, extension_indeterminate: extUnk.length,
  };
  const sample = (items) => items.slice(0, 20).map(it => ({ name: it.name, name_hex: it.name_hex, content_type: it.content_type }));
  const plural = (n) => n === 1 ? "y" : "ies";
  const checks = [
    check("content.role_consistent",
      roleBad.length ? false : (roleUnk.length ? null : true),
      "suspicious",
      roleBad.length
        ? `${roleBad.length} device-routed entr${plural(roleBad.length)} (classes*.dex / manifest / resources.arsc / lib/**.so) hold content other than their role's format`
        : (roleUnk.length
          ? `${roleUnk.length} device-routed entries could not be read by their reader`
          : "every device-routed entry carries its role's magic"),
      (roleBad.length || roleUnk.length) ? { count: roleBad.length, unreadable: roleUnk.length, sample: sample(roleBad) } : null),
    check("content.extension_consistent",
      extBad.length ? false : (extUnk.length ? null : true),
      "info",
      extBad.length
        ? `${extBad.length} entr${plural(extBad.length)} whose extension disagrees with the content magic (decoy / hidden / encrypted payload candidates)`
        : (extUnk.length
          ? `${extUnk.length} entries with a known extension could not be read by their reader`
          : "every entry with a known extension carries that format's magic"),
      (extBad.length || extUnk.length) ? { count: extBad.length, unreadable: extUnk.length, sample: sample(extBad) } : null),
  ];
  return { ok: true, head_bytes: headBytes, entry_count: entries.length, summary, checks, entries };
}

// container._named (#40): a detail list of names, plus an aligned `<key>_hex` when any is lossy.
function named(key, es) {
  const out = { [key]: es.map(e => e.name) };
  if (es.some(e => e.name_hex)) out[key + "_hex"] = es.map(e => e.name_hex);
  return out;
}

// container._container_checks over an install_gate() result.
function containerChecks(r) {
  const entries = r.entries;
  const declared = r.extract_native_libs;              // true / false / null
  const consistent = r.consistent_extract_native_libs;  // subset of ["false","true"]
  const badLibs = r.exceptions.filter(i => entries[i].class === "native_lib").map(i => entries[i]);
  const forgedLibs = entries.filter(e => e.class === "native_lib" && !e.method_known);
  const ifFalse = r.installable_if_extract_false, ifTrue = r.installable_if_extract_true;
  let nlOk;
  if (declared === true) nlOk = ifTrue;
  else if (declared === false) nlOk = ifFalse;
  else if (ifFalse && ifTrue) nlOk = true;
  else if (!ifFalse && !ifTrue) nlOk = false;
  else nlOk = null;
  const ridesTrue = declared === true || (declared === null && nlOk === false);
  const failing = ridesTrue ? forgedLibs : badLibs;
  let nlReason;
  if (nlOk === true) nlReason = "native libs install (STORED+page-aligned, or extracted under extractNativeLibs=true)";
  else if (nlOk === false) nlReason = `${failing.length} native lib(s) fail install — INSTALL_FAILED_INVALID_APK` + (declared === null ? " under BOTH extractNativeLibs values (forged method ∉ {0,8})" : "");
  else nlReason = `${failing.length} native lib(s) compressed/unaligned — INSTALL_FAILED_INVALID_APK IF extractNativeLibs=false (declared value unknown)`;
  const checks = [check("container.native_lib_gate", nlOk, "install_fatal", nlReason,
    (failing.length && nlOk !== true) ? named("failing", failing) : null)];

  const badDex = entries.filter(e => e.class === "dex" && !e.method_known);
  checks.push(check("container.dex_gate", badDex.length === 0, "load_fatal",
    badDex.length ? `${badDex.length} dex with forged compression method — will not load` : "all dex method ∈ {0,8}",
    badDex.length ? named("forged", badDex) : null));

  const pyList = (xs) => "[" + xs.map(x => `'${x}'`).join(", ") + "]";  // Python's repr of the list
  let enlOk, enlReason;
  if (declared === null) {
    enlOk = null;
    enlReason = `extractNativeLibs not supplied (axmlllm) — container consistent with ${pyList(consistent)}; needs_manifest=${r.needs_manifest ? "True" : "False"}`;
  } else {
    const d = declared ? "true" : "false";
    enlOk = consistent.includes(d);
    enlReason = enlOk
      ? `declared extractNativeLibs=${d} is consistent with the container`
      : `declared extractNativeLibs=${d} but container only consistent with ${pyList(consistent)} — declared-vs-consumed divergence`;
  }
  checks.push(check("container.extract_native_libs", enlOk, "warning", enlReason));

  const arsc = entries.find(e => e.class === "resources_arsc");
  let arscOk, arscReason, detail = null;
  if (!arsc) { arscOk = true; arscReason = "no resources.arsc"; }
  else if (arsc.passes) { arscOk = true; arscReason = arsc.reason || "resources.arsc STORED & 4-byte aligned (mmap in place)"; }
  else {
    arscOk = arsc.conditional ? null : false;
    arscReason = arsc.reason;
    if (arsc.needs.length) detail = { needs: [...arsc.needs] };
  }
  checks.push(check("container.resources_arsc_gate", arscOk, "install_fatal", arscReason, detail));
  return checks;
}

// container._tamper_checks over a tamper_scan() result.
function tamperChecks(r) {
  const findings = r.findings;
  const tamper = findings.filter(f => f.severity === "tamper");
  const suspicious = findings.filter(f => f.severity === "suspicious");
  const info = findings.filter(f => f.severity === "info");
  const significant = tamper.concat(suspicious);
  const wouldOpen = r.libziparchive_would_open;
  const blocking = [...new Set(tamper.map(f => f.id))].sort();
  return [
    check("container.device_reader_opens", wouldOpen, "install_fatal",
      wouldOpen
        ? "the device's own ZIP reader (libziparchive) would open this container"
        : `the device's ZIP reader would REFUSE this container at open, or the offending entry at lookup (${blocking.join(", ") || "structural"}) — whatever runs was resolved by a DIFFERENT reader (present-vs-consumed split)`,
      !wouldOpen ? { blocking } : null),
    check("container.no_container_tampering", significant.length === 0, "warning",
      significant.length === 0
        ? "no present-vs-consumed container tampering found" + (info.length ? ` (${info.length} informational zip64 note(s))` : "")
        : `${tamper.length} tampering + ${suspicious.length} suspicious present-vs-consumed divergence(s): ` + significant.map(f => `${f.id}(${f.entry || "file"})`).join("; "),
      findings.length ? { findings } : null),
  ];
}

// Which of the four device readers (apk-decompression-model) consumes each class.
const READER = {
  native_lib: "NativeLibraryHelper",  // installer, strict (NativeLibraryHelper.cpp:310)
  dex: "ART.DexFileLoader",           // strict (dex_file_loader.cc:521)
  manifest: "AssetManager",           // lenient (AssetsProvider.cpp:199)
  resource: "AssetManager",           // lenient
  resources_arsc: "AssetManager",     // lenient read + strict install gate (targetSdk)
  meta: "libziparchive",              // generic strict (zip_archive.cc:1605)
  other: "libziparchive",
};

// container._disposition — how the DEVICE reader for this entry's class handles it.
function disposition(e, enl, pageSize) {
  const method = e.method, off = e.data_offset, klass = e.class;
  const known = method === 0 || method === 8;
  const diverges = !known;
  let disp, loads;
  if (klass === "native_lib") {
    if (!known) [disp, loads] = ["rejected", false];
    else if (enl === true) [disp, loads] = ["extract_to_file", true];
    else if (method === 0 && off % pageSize === 0) [disp, loads] = ["mmap_in_place", true];
    else if (enl === false) [disp, loads] = ["rejected", false];
    else [disp, loads] = ["rejected_if_false", null];
  } else if (klass === "dex") {
    if (!known) [disp, loads] = ["rejected", false];
    else if (method === 0 && off % 4 === 0) [disp, loads] = ["mmap_in_place", true];
    else [disp, loads] = ["extract_to_memory", true];
    if (known && !e.primary_multidex) loads = null;
  } else if (klass === "resources_arsc") {
    const needs = e.needs || [];
    if (method !== 8 && off % 4 === 0) [disp, loads] = ["mmap_in_place", true];
    else if (e.passes ?? true) [disp, loads] = method === 8 ? ["inflate", true] : ["stored_passthrough", true];
    else if (e.install_fatal) [disp, loads] = ["rejected", false];
    else if (needs.length && needs.every(n => n === "target_sdk")) [disp, loads] = ["rejected_if_target_ge_30", null];
    else if (needs.includes("target_sdk")) [disp, loads] = ["rejected_if_in_base_and_target_ge_30", null];
    else [disp, loads] = ["rejected_if_in_base_asset_manager", null];
  } else if (klass === "manifest" || klass === "resource") {
    [disp, loads] = method === 8 ? ["inflate", true] : ["stored_passthrough", true];
  } else {
    if (method === 8) [disp, loads] = ["inflate", true];
    else if (method === 0) [disp, loads] = ["stored_passthrough", true];
    else [disp, loads] = ["rejected", false];
  }
  const needsStr = (e.needs || []).join(", ");
  let reason = "";
  if (diverges) reason = `method ${method} ∉ {0,8} — strict readers reject; AssetManager treats as stored`;
  else if (disp === "rejected") reason = klass === "resources_arsc" && e.reason ? e.reason : "device reader rejects this entry (would not load/install)";
  else if (disp === "rejected_if_false") reason = "rejected IF extractNativeLibs=false, else extracted — needs axmlllm";
  else if (disp === "rejected_if_target_ge_30") reason = "resources.arsc compressed/unaligned — INSTALL_PARSE_FAILED IF targetSdk>29 (needs axmlllm)";
  else if (disp === "rejected_if_in_base_asset_manager") reason = "resources.arsc compressed/unaligned — INSTALL_PARSE_FAILED (targetSdk>29) IF this APK is in the base AssetManager (needs " + needsStr + ")";
  else if (disp === "rejected_if_in_base_and_target_ge_30") reason = "resources.arsc compressed/unaligned — INSTALL_PARSE_FAILED IF targetSdk>29 AND in the base AssetManager (needs " + needsStr + ")";
  else if (klass === "dex" && !e.primary_multidex) reason = "non-primary dex — not ART-auto-loaded; secondary-dex candidate (DexClassLoader)";
  // deliverable = the mapped reader ATTEMPTS extraction (structural; extractEntry is the ground truth)
  const deliverable = known || klass === "manifest" || klass === "resource" || klass === "resources_arsc";
  return { reader: READER[klass], disposition: disp, diverges, device_loads: loads, deliverable, reason };
}

// container.extract_report over an install_gate() result (extract_map folded in). The
// role-echo keys are the Python wrapper's; the demo takes arsc_scope directly (see gate),
// so it matches extract_report fed the CORE gate (xcheck.py does exactly that): the
// wrapper's role-fact needs and " [in_base_asset_manager_reason]" arsc suffixes are absent.
function extractReport(g) {
  if (!g.ok) return g;
  const entries = g.entries.map(e => {
    const d = disposition(e, g.extract_native_libs, g.page_size);
    return { name: e.name, name_hex: e.name_hex, class: e.class, method: e.method, primary_multidex: e.primary_multidex, ...d,
             decompresses: e.method === 8 && d.deliverable };
  });
  const byDisp = {}, byReader = {};
  for (const e of entries) {
    byDisp[e.disposition] = (byDisp[e.disposition] ?? 0) + 1;
    byReader[e.reader] = (byReader[e.reader] ?? 0) + 1;
  }
  const brief = (e) => ({ name: e.name, name_hex: e.name_hex, reader: e.reader, method: e.method });
  const forged = entries.filter(e => e.diverges).map(brief);
  const undeliverable = entries.filter(e => !e.deliverable).map(brief);
  const plural = (n) => n === 1 ? "y" : "ies";
  const summary = {
    by_disposition: byDisp, by_reader: byReader,
    will_inflate: entries.filter(e => e.decompresses).length,
    stored_or_mmap: entries.filter(e => e.method === 0).length,
    diverges: forged.length, undeliverable: undeliverable.length,
    device_rejected: entries.filter(e => e.device_loads === false).length,
  };
  const checks = [
    check("extract.method_forgery", !forged.length, "warning",
      forged.length
        ? `${forged.length} entr${plural(forged.length)} with method ∉ {0,8} — forge-the-method evasion (breaks generic unzip; device reads via its reader)`
        : "no method forgery — every entry method ∈ {0,8}",
      forged.length ? { forged } : null),
    check("extract.all_deliverable", !undeliverable.length, "warning",
      undeliverable.length
        ? `${undeliverable.length} entr${plural(undeliverable.length)} its mapped strict reader will NOT attempt (forged non-{0,8} method) — extract_entry raises without attempting`
        : "no entry is structurally undeliverable; every entry's mapped reader will ATTEMPT extraction — but a method-8 stream that is corrupt/mislabeled (e.g. forged 0→8) still fails at extract_entry (verified there, not here)",
      undeliverable.length ? { undeliverable } : null),
  ];
  return { ok: true, extract_native_libs: g.extract_native_libs, target_sdk: g.target_sdk,
           entry_count: entries.length, summary, checks, entries };
}

root.ApkllmDomain = { HEAD_BYTES, SIGNATURES, CATEGORY, classify, unknownKind, entropy,
                      contentMap, containerChecks, tamperChecks, READER, extractReport };
})(typeof self !== "undefined" ? self : globalThis);
