// wasm_module.cpp — embind binding mirroring apkllm's native/binding/module.cpp
// (the pybind11 _apk_core) for the apkllm-web in-browser demo. ADAPTER ONLY:
// same functions, same field names, same tri-state semantics — it calls the
// container layer and marshals results to JS; no parsing/verdict policy lives
// here (the faithfulness boundary).
//
// Single-threaded WASM build (GitHub Pages can't serve the COOP/COEP headers
// SharedArrayBuffer needs). The APK is written to MEMFS by the caller and
// every function takes its path, exactly like the Python binding.
//
// JS API (module-level functions, all return plain JS objects):
//   installGate(path, extractNativeLibs: boolean|null, targetSdk: number|null,
//               pageSize: number, arscScope: boolean|null)
//   extractEntry(path, name, maxBytes)      // name: string, or Uint8Array of raw bytes (name_hex)
//                                           // .data is a Uint8Array copy
//   entryHeads(path, n, names: string[]|null) // each .head is a Uint8Array copy
//   entryNames(path, prefix, suffixes: string[], cap)
//   signingBlockPairs(path, cap, track: number[])
//   signingCerts(path)                      // #58: signer certificates as present, unverified
//   tamperScan(path)
// (embind checks the argument count: every argument is passed, null for Python's None default.)
//
// Differences forced by the JS side, none of them policy:
//   - Python None ⇄ JS null/undefined for the tri-state inputs and outputs.
//   - 64-bit integers cross as JS numbers (double). ZIP offsets/sizes are
//     < 2^53 for any APK a browser can hold, so this is lossless in practice.
//   - Entry names are attacker-controlled bytes (libziparchive accepts overlong /
//     surrogate / 5-byte sequences). embind's own std::string→JS conversion is
//     NOT the U+FFFD contract module.cpp's SafeStr gives Python: for strings
//     ≤16 bytes emscripten's UTF8ToString uses a non-validating hand decoder
//     (C0 80 → NUL, ED A0 80 → lone surrogate, F8.. swallows following bytes),
//     and the TextDecoder path it uses for longer strings eats a leading BOM.
//     So every attacker-controlled string crosses as raw bytes and is decoded
//     here by a WHATWG TextDecoder("utf-8", {ignoreBOM:true}) — non-fatal
//     replacement matches Python's errors="replace" byte-for-byte (verified in
//     review on the overlong / surrogate / 5-byte / truncated cases).
//   - A lossy name also carries name_hex (module.cpp's LossyHex, here StrictUtf8 — CPython's
//     strict decoder); extractEntry takes those bytes back as a Uint8Array where Python takes bytes.

#include <emscripten/bind.h>
#include <emscripten/val.h>

#include <android/log.h>

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "apksig.h"
#include "certs.h"
#include "container.h"
#include "tamper.h"

using emscripten::function;
using emscripten::typed_memory_view;
using emscripten::val;

namespace {

// liblog's host logger (__android_log_stderr_logger → filestream_logger → GetThreadId)
// has no branch for a platform that is none of __BIONIC__/__APPLE__/__linux__/_WIN32,
// so under emscripten GetThreadId() falls off its end and clang emits `unreachable`:
// the FIRST ALOGW libziparchive prints (e.g. "Found duplicate entry" on a Master-Key
// APK — i.e. exactly the tampered inputs this demo exists for) traps the whole module.
// Replace it through liblog's own public hook, not by patching AOSP: a minimal
// stderr logger, installed by a static initializer before any binding can run.
void WasmStderrLogger(const __android_log_message* m) {
    static const char kPrio[] = "XXVDIWEF";
    int p = m->priority;
    if (p < 0 || p >= static_cast<int>(sizeof(kPrio) - 1)) p = ANDROID_LOG_FATAL;
    std::fprintf(stderr, "%c %s: %s\n", kPrio[p], m->tag ? m->tag : "", m->message ? m->message : "");
}
struct InstallLogger {
    InstallLogger() { __android_log_set_logger(&WasmStderrLogger); }
} g_install_logger;

// uint64 → JS number. See the header comment on range.
double Num(uint64_t v) { return static_cast<double>(v); }
double Num(int64_t v) { return static_cast<double>(v); }

// Copy bytes out of a std::string into a fresh Uint8Array owned by JS.
// `new Uint8Array(view)` copies, so the view over wasm memory never outlives
// the std::string it points into.
val Bytes(const std::string& s) {
    return val::global("Uint8Array").new_(val(typed_memory_view(
        s.size(), reinterpret_cast<const uint8_t*>(s.data()))));
}

// SafeStr equivalent (see header): raw bytes → JS string with U+FFFD replacement.
val SafeStr(const std::string& s) {
    static val decoder = [] {
        val opts = val::object();
        opts.set("ignoreBOM", true);
        return val::global("TextDecoder").new_(std::string("utf-8"), opts);
    }();
    return decoder.call<val>("decode", Bytes(s));
}

// Strict UTF-8 as CPython's decoder (errors="strict") judges it — Unicode Table 3-7 well-formed
// sequences: no overlong, no surrogate (ED A0..BF), nothing above U+10FFFF, no 5/6-byte lead.
bool StrictUtf8(const std::string& s) {
    const auto* p = reinterpret_cast<const unsigned char*>(s.data());
    size_t n = s.size(), i = 0;
    auto cont = [&](size_t k, unsigned lo = 0x80, unsigned hi = 0xBF) {
        return k < n && p[k] >= lo && p[k] <= hi;
    };
    while (i < n) {
        unsigned c = p[i];
        if (c < 0x80) { i += 1; continue; }
        if (c >= 0xC2 && c <= 0xDF && cont(i + 1)) { i += 2; continue; }
        if (c == 0xE0 && cont(i + 1, 0xA0) && cont(i + 2)) { i += 3; continue; }
        if (((c >= 0xE1 && c <= 0xEC) || c == 0xEE || c == 0xEF) && cont(i + 1) && cont(i + 2)) { i += 3; continue; }
        if (c == 0xED && cont(i + 1, 0x80, 0x9F) && cont(i + 2)) { i += 3; continue; }
        if (c == 0xF0 && cont(i + 1, 0x90) && cont(i + 2) && cont(i + 3)) { i += 4; continue; }
        if (c >= 0xF1 && c <= 0xF3 && cont(i + 1) && cont(i + 2) && cont(i + 3)) { i += 4; continue; }
        if (c == 0xF4 && cont(i + 1, 0x80, 0x8F) && cont(i + 2) && cont(i + 3)) { i += 4; continue; }
        return false;
    }
    return true;
}

// module.cpp's LossyHex (#24): the raw name bytes in lowercase hex when the decoded name is lossy
// (not strict UTF-8), else null — the key extractEntry takes back as a Uint8Array.
val NameHex(const std::string& s) {
    if (StrictUtf8(s)) return val::null();
    static const char kHex[] = "0123456789abcdef";
    std::string h;
    h.reserve(s.size() * 2);
    for (unsigned char c : s) {
        h.push_back(kHex[c >> 4]);
        h.push_back(kHex[c & 0xF]);
    }
    return val(h);
}

val Strings(const std::vector<std::string>& v) {
    val arr = val::array();
    for (size_t i = 0; i < v.size(); ++i) arr.set(i, v[i]);
    return arr;
}

bool IsNone(const val& v) { return v.isNull() || v.isUndefined(); }

const char* ClassName(apkllm::EntryClass k) {
    switch (k) {
        case apkllm::EntryClass::kNativeLib: return "native_lib";
        case apkllm::EntryClass::kDex: return "dex";
        case apkllm::EntryClass::kManifest: return "manifest";
        case apkllm::EntryClass::kResource: return "resource";
        case apkllm::EntryClass::kResourcesArsc: return "resources_arsc";
        case apkllm::EntryClass::kMeta: return "meta";
        default: return "other";
    }
}

// Enumerate APK entries through real libziparchive and apply the install/load
// gates. extract_native_libs / target_sdk / arsc_scope are the manifest-owned
// inputs the USER supplies in the UI (null = unknown → honest conditional verdict).
val InstallGate(const std::string& path, val extract_native_libs, val target_sdk,
                double page_size, val arsc_scope) {
    apkllm::ExtractNativeLibs extract = apkllm::ExtractNativeLibs::kUnknown;
    if (!IsNone(extract_native_libs)) {
        extract = extract_native_libs.as<bool>() ? apkllm::ExtractNativeLibs::kTrue
                                                 : apkllm::ExtractNativeLibs::kFalse;
    }
    int tsdk = IsNone(target_sdk) ? -1 : target_sdk.as<int>();
    apkllm::ArscScope scope = apkllm::ArscScope::kUnknown;
    if (!IsNone(arsc_scope)) {
        scope = arsc_scope.as<bool>() ? apkllm::ArscScope::kInBase : apkllm::ArscScope::kNotInBase;
    }
    // A negative/fractional page size from JS would wrap to a huge uint64; clamp to 0 so
    // the engine's own "page_size must be > 0" guard reports it.
    uint64_t ps = page_size > 0 ? static_cast<uint64_t>(page_size) : 0;

    val out = val::object();
    apkllm::InstallGate g = apkllm::ComputeInstallGate(path, extract, tsdk, ps, scope);
    out.set("ok", g.ok);
    if (!g.ok) {
        out.set("error", g.error);
        return out;
    }
    if (g.installable_known)
        out.set("installable", g.installable);
    else
        out.set("installable", val::null());
    out.set("installable_if_extract_false", g.installable_if_extract_false);
    out.set("installable_if_extract_true", g.installable_if_extract_true);
    out.set("needs_manifest", g.needs_manifest);
    // Which extractNativeLibs values the container is consistent with — a container
    // FACT re-expressed from the two branch verdicts (module.cpp does the same).
    val consistent_extract = val::array();
    {
        size_t i = 0;
        if (g.installable_if_extract_false) consistent_extract.set(i++, std::string("false"));
        if (g.installable_if_extract_true) consistent_extract.set(i++, std::string("true"));
    }
    out.set("consistent_extract_native_libs", consistent_extract);
    if (g.extract_native_libs == apkllm::ExtractNativeLibs::kUnknown)
        out.set("extract_native_libs", val::null());
    else
        out.set("extract_native_libs", g.extract_native_libs == apkllm::ExtractNativeLibs::kTrue);
    if (g.target_sdk < 0)
        out.set("target_sdk", val::null());
    else
        out.set("target_sdk", g.target_sdk);
    if (g.arsc_scope == apkllm::ArscScope::kUnknown)
        out.set("in_base_asset_manager", val::null());
    else
        out.set("in_base_asset_manager", g.arsc_scope == apkllm::ArscScope::kInBase);
    out.set("page_size", Num(g.page_size));
    out.set("entry_count", static_cast<unsigned>(g.entries.size()));

    val entries = val::array();
    for (size_t i = 0; i < g.entries.size(); ++i) {
        const auto& e = g.entries[i];
        const auto& v = g.verdicts[i];
        val d = val::object();
        d.set("name", SafeStr(e.name));
        d.set("name_hex", NameHex(e.name));
        d.set("class", std::string(ClassName(e.klass)));
        d.set("primary_multidex", e.primary_multidex);
        d.set("method", e.method);
        d.set("data_offset", Num(e.data_offset));
        d.set("compressed_size", Num(e.compressed_size));
        d.set("uncompressed_size", Num(e.uncompressed_size));
        d.set("crc32", e.crc32);
        d.set("has_data_descriptor", e.has_data_descriptor);
        d.set("method_known", v.method_known);
        d.set("aligned_4k", v.aligned_4k);
        d.set("aligned_16k", v.aligned_16k);
        d.set("gate", v.gate);
        d.set("passes", v.passes);
        d.set("install_fatal", v.install_fatal);
        d.set("conditional", v.conditional);
        d.set("reason", v.reason);
        d.set("needs", Strings(v.needs));
        entries.set(i, d);
    }
    out.set("entries", entries);

    val exc = val::array();
    for (size_t i = 0; i < g.exceptions.size(); ++i) exc.set(i, static_cast<unsigned>(g.exceptions[i]));
    out.set("exceptions", exc);
    return out;
}

// Extract ONE entry's device-faithful bytes (the four-reader model). Bytes only.
// `name` is a JS string (encoded UTF-8 — a strict-UTF-8 name) or a Uint8Array of the raw name
// bytes (an entry whose name_hex is set: a JS string cannot carry its bytes). The C++ core
// matches byte for byte either way, as module.cpp does for Python str / bytes.
val ExtractEntry(const std::string& path, val name, double max_bytes) {
    val out = val::object();
    uint64_t cap = max_bytes > 0 ? static_cast<uint64_t>(max_bytes) : 0;
    std::string key;
    if (name.typeOf().as<std::string>() == "string") {
        key = name.as<std::string>();
    } else if (name.instanceof(val::global("Uint8Array"))) {
        std::vector<uint8_t> raw = emscripten::convertJSArrayToNumberVector<uint8_t>(name);
        key.assign(raw.begin(), raw.end());
    } else {
        out.set("ok", false);
        out.set("error", std::string("extractEntry: name must be a string or a Uint8Array"));
        return out;
    }
    apkllm::ExtractedEntry e = apkllm::ExtractEntry(path, key, cap);
    out.set("ok", e.ok);
    out.set("name", SafeStr(e.name));
    out.set("name_hex", NameHex(e.name));
    out.set("class", std::string(ClassName(e.klass)));
    out.set("method", e.method);
    out.set("diverges", e.diverges);
    if (!e.ok) {
        out.set("error", SafeStr(e.error));
        return out;
    }
    out.set("disposition", e.disposition);
    out.set("data", Bytes(e.data));
    return out;
}

// A JS array of strings → std::vector<std::string> (each encoded UTF-8, as pybind11 casts a str).
std::vector<std::string> StringVector(const val& arr) {
    std::vector<std::string> v;
    const unsigned n = arr["length"].as<unsigned>();
    v.reserve(n);
    for (unsigned i = 0; i < n; ++i) v.push_back(arr[i].as<std::string>());
    return v;
}

// Every entry's first n device-produced bytes (one archive open). Bytes only — JS labels them.
// names=null: every entry; an array: only those exact names (libziparchive's own matcher).
val EntryHeads(const std::string& path, double n, val names) {
    val out = val::object();
    size_t want = n > 0 ? static_cast<size_t>(n) : 0;
    std::vector<std::string> only;
    const bool filtered = !IsNone(names);
    if (filtered) only = StringVector(names);
    apkllm::EntryHeads r = apkllm::ReadEntryHeads(path, want, filtered ? &only : nullptr);
    out.set("ok", r.ok);
    if (!r.ok) {
        out.set("error", SafeStr(r.error));
        return out;
    }
    val entries = val::array();
    size_t i = 0;
    for (const auto& h : r.entries) {
        val d = val::object();
        d.set("name", SafeStr(h.name));
        d.set("name_hex", NameHex(h.name));
        d.set("class", std::string(ClassName(h.klass)));
        d.set("method", h.method);
        d.set("gpbf", h.gpbf);
        d.set("uncompressed_size", Num(h.uncompressed_size));
        d.set("disposition", h.disposition);
        d.set("head", Bytes(h.head));
        d.set("complete", h.complete);
        if (!h.error.empty()) d.set("error", SafeStr(h.error));
        entries.set(i++, d);
    }
    out.set("entries", entries);
    return out;
}

// Entry names under `prefix`, as libziparchive iterates them: the first `cap` + the exact total.
val EntryNames(const std::string& path, const std::string& prefix, val suffixes, double cap) {
    val out = val::object();
    size_t keep = cap > 0 ? static_cast<size_t>(cap) : 0;
    apkllm::EntryNames r = apkllm::ListEntryNames(path, prefix, StringVector(suffixes), keep);
    out.set("ok", r.ok);
    if (!r.ok) {
        out.set("error", SafeStr(r.error));
        return out;
    }
    val names = val::array();
    for (size_t i = 0; i < r.names.size(); ++i) names.set(i, SafeStr(r.names[i]));
    out.set("names", names);
    out.set("total", Num(r.total));
    return out;
}

// The APK Signing Block's ID→value pairs, in block order (duplicates kept), as the locator walks
// them: the first `cap` pairs {id, offset (file offset of the value), size} + the exact total, and
// for each `track` ID its whole-walk count + first pair. No value is read or parsed — structural
// only (verification is Java apksig, out of the web demo's scope).
val SigningBlockPairs(const std::string& path, double cap, val track) {
    val out = val::object();
    std::string err;
    auto apk = apkllm::ApkFile::open(path, &err);
    if (!apk) {
        out.set("ok", false);
        out.set("error", SafeStr(err));
        return out;
    }
    auto sections = apkllm::FindZipSections(apk->data(), apk->size());
    if (!sections) {
        out.set("ok", false);
        out.set("error", std::string("ZIP End of Central Directory record not found"));  // apksig ApkUtilsLite wording
        return out;
    }
    out.set("ok", true);
    // The two gates both AOSP readers apply before locating the block (module.cpp: the CD must
    // be immediately followed by the EOCD; the platform refuses ZIP64).
    out.set("cd_contiguous",
            sections->central_dir_offset + sections->central_dir_size == sections->eocd_offset);
    out.set("zip64_locator_present", sections->zip64_locator_present);
    std::vector<uint32_t> ids;
    const unsigned nt = track["length"].as<unsigned>();
    for (unsigned i = 0; i < nt; ++i) ids.push_back(track[i].as<uint32_t>());
    size_t keep = cap > 0 ? static_cast<size_t>(cap) : 0;
    auto sb = apkllm::FindApkSigningBlock(apk->data(), apk->size(), *sections, keep, &ids);
    out.set("framing_found", sb.framing_found);
    if (!sb.framing_found) {
        out.set("error", SafeStr(sb.error));
        return out;
    }
    if (sb.pairs_error_entry > 0) {
        out.set("malformed_entry", sb.pairs_error_entry);
        out.set("malformed_reason", SafeStr(sb.pairs_error));
    }
    out.set("block_offset", Num(sb.block_offset));
    out.set("block_size", Num(sb.block_size));
    val pairs = val::array();
    for (size_t i = 0; i < sb.blocks.size(); ++i) {
        const auto& b = sb.blocks[i];
        val d = val::object();
        d.set("id", b.id);
        d.set("offset", Num(b.value_offset));
        d.set("size", Num(b.value_size));
        pairs.set(i, d);
    }
    out.set("pairs", pairs);
    out.set("pairs_total", Num(sb.blocks_total));
    val tracked = val::array();
    for (size_t i = 0; i < sb.tracked.size(); ++i) {
        const auto& t = sb.tracked[i];
        val d = val::object();
        d.set("id", t.id);
        d.set("count", Num(t.count));
        d.set("first_entry", t.first_entry);
        d.set("first_offset", Num(t.first_value_offset));
        d.set("first_size", Num(t.first_value_size));
        tracked.set(i, d);
    }
    out.set("tracked", tracked);
    return out;
}

// Present-vs-consumed tamper scan (own raw ZIP walker, NOT libziparchive).
// Pure marshalling of the native structs.
val TamperScan(const std::string& path) {
    val out = val::object();
    apkllm::TamperReport r = apkllm::ScanTamper(path);
    out.set("ok", r.ok);
    if (!r.ok) {
        out.set("error", SafeStr(r.error));
        return out;
    }
    out.set("eocd_offset", Num(r.eocd_offset));
    out.set("central_dir_offset", Num(r.cd_offset));
    out.set("central_dir_size", Num(r.cd_size));
    out.set("cd_records", Num(r.cd_records));
    out.set("signing_block_present", r.signing_block_present);
    out.set("libziparchive_would_open", r.libziparchive_would_open);

    val entries = val::array();
    size_t i = 0;
    for (const auto& e : r.entries) {
        val d = val::object();
        d.set("name", SafeStr(e.name));
        d.set("name_hex", NameHex(e.name));
        d.set("cd_record_offset", Num(e.cd_record_offset));
        d.set("cd_method", e.cd_method);
        d.set("cd_gpbf", e.cd_gpbf);
        d.set("cd_crc32", e.cd_crc32);
        d.set("cd_compressed_size", Num(e.cd_compressed_size));
        d.set("cd_uncompressed_size", Num(e.cd_uncompressed_size));
        d.set("lfh_offset", Num(e.lfh_offset));
        d.set("lfh_present", e.lfh_present);
        d.set("lfh_method", e.lfh_method);
        d.set("lfh_gpbf", e.lfh_gpbf);
        d.set("lfh_crc32", e.lfh_crc32);
        d.set("lfh_compressed_size", Num(e.lfh_compressed_size));
        d.set("lfh_uncompressed_size", Num(e.lfh_uncompressed_size));
        d.set("has_data_descriptor", e.has_data_descriptor);
        entries.set(i++, d);
    }
    out.set("entries", entries);

    val findings = val::array();
    i = 0;
    for (const auto& f : r.findings) {
        val d = val::object();
        d.set("id", f.id);
        d.set("entry", SafeStr(f.entry));
        d.set("entry_hex", NameHex(f.entry));
        d.set("severity", f.severity);
        d.set("detail", SafeStr(f.detail));
        findings.set(i++, d);
    }
    out.set("findings", findings);
    return out;
}

}  // namespace

// ── signing_certs (#58) — module.cpp SigningCertsDict / NameDict / CertDict, key for key ──

// A JDK-rendered DN (UTF-16, as Java holds it) → JS string. Always well-formed upstream; a lone
// surrogate would become U+FFFD, as module.cpp's U16Str decodes with errors="replace". Built as
// UTF-8 and decoded by the same TextDecoder as SafeStr (a NUL inside a value survives).
val U16Str(const std::u16string& s) {
    std::string u;
    u.reserve(s.size() * 3);
    auto put = [&](uint32_t c) {
        if (c < 0x80) {
            u += static_cast<char>(c);
        } else if (c < 0x800) {
            u += static_cast<char>(0xC0 | (c >> 6));
            u += static_cast<char>(0x80 | (c & 0x3F));
        } else if (c < 0x10000) {
            u += static_cast<char>(0xE0 | (c >> 12));
            u += static_cast<char>(0x80 | ((c >> 6) & 0x3F));
            u += static_cast<char>(0x80 | (c & 0x3F));
        } else {
            u += static_cast<char>(0xF0 | (c >> 18));
            u += static_cast<char>(0x80 | ((c >> 12) & 0x3F));
            u += static_cast<char>(0x80 | ((c >> 6) & 0x3F));
            u += static_cast<char>(0x80 | (c & 0x3F));
        }
    };
    for (size_t i = 0; i < s.size(); ++i) {
        uint32_t c = s[i];
        if (c >= 0xD800 && c <= 0xDBFF && i + 1 < s.size() && s[i + 1] >= 0xDC00 && s[i + 1] <= 0xDFFF) {
            put(0x10000 + ((c - 0xD800) << 10) + (s[i + 1] - 0xDC00));
            ++i;
        } else if (c >= 0xD800 && c <= 0xDFFF) {
            put(0xFFFD);
        } else {
            put(c);
        }
    }
    return SafeStr(u);
}

val OptStr(const std::string& s) { return s.empty() ? val::null() : SafeStr(s); }

val NameObj(const apkllm::NameAsPresent& n) {
    val d = val::object();
    d.set("rfc2253", n.rendered ? U16Str(n.rfc2253) : val::null());
    d.set("display", n.rendered ? U16Str(n.display) : val::null());
    d.set("jdk_rejects", OptStr(n.jdk_rejects));
    d.set("error", OptStr(n.error));
    val attrs = val::array();
    for (size_t i = 0; i < n.attrs.size(); ++i) {
        const auto& a = n.attrs[i];
        val x = val::object();
        x.set("rdn", a.rdn);
        x.set("oid", SafeStr(a.oid));
        x.set("keyword", OptStr(a.keyword));
        x.set("tag", a.tag);
        x.set("value_size", Num(a.value_size));
        x.set("value_hex", a.value_hex);
        x.set("text", a.has_text ? U16Str(a.text) : val::null());
        attrs.set(i, x);
    }
    d.set("attrs", attrs);
    d.set("attrs_total", Num(n.attrs_total));
    return d;
}

val CertObj(const apkllm::CertAsPresent& c) {
    val d = val::object();
    d.set("size", Num(c.size));
    d.set("sha256", c.sha256);
    d.set("trailing_bytes", Num(c.trailing_bytes));
    d.set("encoding", OptStr(c.encoding));
    d.set("tbs_read", c.tbs_read);
    d.set("error", OptStr(c.error));
    d.set("jdk_rejects", OptStr(c.jdk_rejects));
    d.set("serial", c.serial_present ? SafeStr(c.serial) : val::null());
    d.set("subject", c.tbs_read ? NameObj(c.subject) : val::null());
    d.set("issuer", c.tbs_read ? NameObj(c.issuer) : val::null());
    return d;
}

val CertList(const std::vector<apkllm::CertAsPresent>& certs) {
    val l = val::array();
    for (size_t i = 0; i < certs.size(); ++i) l.set(i, CertObj(certs[i]));
    return l;
}

// A proof-of-rotation attribute as present (apkllm #62) — module.cpp LineageDict, key for key.
val LineageObj(const apkllm::LineageAsPresent& l) {
    val d = val::object();
    d.set("attrs", l.attrs);
    val attr_errors = val::array();
    for (size_t i = 0; i < l.attr_errors.size(); ++i) attr_errors.set(i, OptStr(l.attr_errors[i]));
    d.set("attr_errors", attr_errors);
    d.set("version", l.version_read ? val(l.version) : val::null());
    val nodes = val::array();
    for (size_t i = 0; i < l.nodes.size(); ++i) {
        const auto& n = l.nodes[i];
        val x = val::object();
        x.set("index", n.index);
        x.set("attr", n.attr);
        x.set("flags", n.flags_read ? val(n.flags) : val::null());
        x.set("signed_sig_alg", n.signed_sig_alg_read ? val(n.signed_sig_alg) : val::null());
        x.set("sig_alg", n.error.empty() ? val(n.sig_alg) : val::null());
        x.set("signature_size", n.error.empty() ? val(Num(n.signature_size)) : val::null());
        x.set("cert", n.cert_present ? CertObj(n.cert) : val::null());
        x.set("error", OptStr(n.error));
        nodes.set(i, x);
    }
    d.set("nodes", nodes);
    d.set("nodes_total", Num(l.nodes_total));
    d.set("error", OptStr(l.error));
    return d;
}

val SchemeObj(const apkllm::SchemeResult& s) {
    if (!s.present) return val::null();
    val d = val::object();
    d.set("first_entry", s.first_entry);
    d.set("count", Num(s.count));
    d.set("error", OptStr(s.certs.error));
    val signers = val::array();
    for (size_t i = 0; i < s.certs.signers.size(); ++i) {
        const auto& g = s.certs.signers[i];
        val x = val::object();
        x.set("index", g.index);
        if (g.has_sdk && g.sdk_read) {  // v3 / v3.1 only, and only what was read
            x.set("min_sdk", g.min_sdk);
            x.set("max_sdk", g.max_sdk);
        }
        if (g.has_sdk && g.signed_sdk_read) {
            x.set("signed_min_sdk", g.signed_min_sdk);
            x.set("signed_max_sdk", g.signed_max_sdk);
        }
        x.set("certs", CertList(g.certs));
        x.set("certs_total", Num(g.certs_total));
        if (g.lineage.present) x.set("lineage", LineageObj(g.lineage));
        x.set("error", OptStr(g.error));
        signers.set(i, x);
    }
    d.set("signers", signers);
    d.set("signers_total", Num(s.certs.signers_total));
    return d;
}

val SigningCerts(const std::string& path) {
    apkllm::SigningCerts r = apkllm::ReadSigningCerts(path);
    val out = val::object();
    out.set("ok", r.ok);
    if (!r.ok) {
        out.set("error", SafeStr(r.error));
        return out;
    }
    out.set("file_sha256", r.file_sha256);
    out.set("cd_contiguous", r.cd_contiguous);
    out.set("zip64_locator_present", r.zip64_locator_present);
    out.set("block_found", r.block_found);
    out.set("block_reason", OptStr(r.block_reason));
    out.set("walk_error_entry", r.walk_error_entry ? val(r.walk_error_entry) : val::null());
    out.set("walk_error_reason", OptStr(r.walk_error_reason));
    out.set("v2", SchemeObj(r.v2));
    out.set("v3", SchemeObj(r.v3));
    out.set("v31", SchemeObj(r.v31));
    out.set("source_stamp", SchemeObj(r.stamp));
    out.set("v1_ok", r.v1_ok);
    out.set("v1_error", OptStr(r.v1_error));
    out.set("v1_total", Num(r.v1_total));
    val v1 = val::array();
    for (size_t i = 0; i < r.v1.size(); ++i) {
        const auto& f = r.v1[i];
        val x = val::object();
        x.set("name", SafeStr(f.name));
        x.set("name_hex", NameHex(f.name));
        x.set("sf_present", f.sf_known ? val(f.sf_present) : val::null());
        x.set("read_error", OptStr(f.read_error));
        x.set("error", OptStr(f.pkcs7.error));
        x.set("certs", CertList(f.pkcs7.certs));
        x.set("certs_total", Num(f.pkcs7.certs_total));
        val infos = val::array();
        for (size_t k = 0; k < f.pkcs7.signer_infos.size(); ++k) {
            const auto& v = f.pkcs7.signer_infos[k];
            val y = val::object();
            y.set("sid_kind", v.sid_kind);
            y.set("issuer", v.sid_kind == "issuer_and_serial" ? NameObj(v.issuer) : val::null());
            y.set("serial", v.serial_present ? SafeStr(v.serial) : val::null());
            y.set("match", v.match);
            y.set("cert_index", v.cert_index >= 0 ? val(v.cert_index) : val::null());
            infos.set(k, y);
        }
        x.set("signer_infos", infos);
        x.set("signer_infos_total", Num(f.pkcs7.signer_infos_total));
        v1.set(i, x);
    }
    out.set("v1", v1);
    return out;
}

EMSCRIPTEN_BINDINGS(apkllm_wasm) {
    function("installGate", &InstallGate);
    function("extractEntry", &ExtractEntry);
    function("entryHeads", &EntryHeads);
    function("entryNames", &EntryNames);
    function("signingBlockPairs", &SigningBlockPairs);
    function("signingCerts", &SigningCerts);
    function("tamperScan", &TamperScan);
}
