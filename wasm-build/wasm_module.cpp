// wasm_module.cpp — embind binding mirroring apkllm's native/binding/module.cpp
// (the pybind11 _apk_core) for the apkllm-web in-browser demo. ADAPTER ONLY:
// same functions, same field names, same key order, same tri-state semantics — it
// calls the engine and marshals results to JS; no parsing/verdict policy lives
// here (the faithfulness boundary). Since apkllm #67 every report is decided whole
// in the engine (an ordered apkllm::Value); ToVal converts it one to one, as
// module.cpp's ToPy does.
//
// Single-threaded WASM build (GitHub Pages can't serve the COOP/COEP headers
// SharedArrayBuffer needs). The APK is written to MEMFS by the caller and
// every function takes its path, exactly like the Python binding.
//
// JS API (module-level functions, all return plain JS objects):
//   abi()                                   // module.cpp's ABI (13) — the worker refuses another
//   installGate(path, extractNativeLibs: boolean|null, targetSdk: number|null, pageSize: number,
//               apkRole: "base"|"split"|null, roleDefaulted: boolean,
//               isolatedSplits: boolean|null, featureSplit: boolean|null, configForSplit: boolean|null)
//   extractPlan(path, <the installGate arguments after path>, report: boolean)
//                                           // extract_map (false) / extract_report (true)
//   extractEntry(path, name, maxBytes)      // name: string, or Uint8Array of raw bytes (name_hex)
//                                           // .data is a Uint8Array copy
//   entryHeads(path, n, names: string[]|null) // each .head is a Uint8Array copy
//   contentMap(path, headBytes)
//   tamperReport(path)
//   signingBlockPairs(path, cap, track: number[])
//   buildTraces(path)
//   signingCerts(path)                      // #58: signer certificates as present, unverified
//   frosting(path, keys: Uint8Array[])      // #59: Play's frosting check, keys = DER SPKIs
// (embind checks the argument count: every argument is passed, null for Python's None default.)
//
// Differences forced by the JS side, none of them policy:
//   - Python None ⇄ JS null/undefined for the tri-state inputs and outputs.
//   - 64-bit integers cross as JS numbers when exact (|v| <= 2^53), else as their decimal string:
//     a DECLARED size is attacker-chosen (a ZIP64 extra can claim 2^60), and a double would show
//     other digits than Python's int. No BigInt: it breaks JSON.stringify (reports, copy).
//   - Entry names are attacker-controlled bytes (libziparchive accepts overlong /
//     surrogate / 5-byte sequences). embind's own std::string→JS conversion is
//     NOT the U+FFFD contract module.cpp's SafeStr gives Python: for strings
//     ≤16 bytes emscripten's UTF8ToString uses a non-validating hand decoder
//     (C0 80 → NUL, ED A0 80 → lone surrogate, F8.. swallows following bytes),
//     and the TextDecoder path it uses for longer strings eats a leading BOM.
//     So every string that is not plain ASCII crosses as raw bytes and is decoded
//     here by a WHATWG TextDecoder("utf-8", {ignoreBOM:true}) — non-fatal
//     replacement matches Python's errors="replace" byte-for-byte (verified in
//     review on the overlong / surrogate / 5-byte / truncated cases).
//   - A map key the engine computed (an attacker string: app-metadata keys, a content
//     type histogram) is defined as an own property, so "__proto__" stays a key. A JS
//     object lists integer-like keys first, in ascending order — display only.
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
#include "content_map.h"
#include "frosting.h"
#include "plan.h"
#include "tamper_report.h"
#include "traces.h"
#include "value.h"

using emscripten::function;
using emscripten::typed_memory_view;
using emscripten::val;

namespace {

// module.cpp's ABI: the marshalled shape's version (12 = frosting, apkllm #59; 13 = its signed
// region, signature and recovered keys, #83).
constexpr int kAbi = 13;

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

// 64-bit integer → JS: a number when exact, else its decimal string (see the header comment).
constexpr uint64_t kExact = 1ull << 53;
val Num(uint64_t v) { return v <= kExact ? val(static_cast<double>(v)) : val(std::to_string(v)); }
val Num(int64_t v) {
    const uint64_t mag = v < 0 ? 0 - static_cast<uint64_t>(v) : static_cast<uint64_t>(v);
    return mag <= kExact ? val(static_cast<double>(v)) : val(std::to_string(v));
}

// Copy bytes out of a std::string into a fresh Uint8Array owned by JS.
// `new Uint8Array(view)` copies, so the view over wasm memory never outlives
// the std::string it points into.
val Bytes(const std::string& s) {
    return val::global("Uint8Array").new_(val(typed_memory_view(
        s.size(), reinterpret_cast<const uint8_t*>(s.data()))));
}

// SafeStr equivalent (see header): raw bytes → JS string with U+FFFD replacement. Plain ASCII
// (no NUL) is the same string under every decoder, so it skips the TextDecoder round trip.
val SafeStr(const std::string& s) {
    bool ascii = true;
    for (unsigned char c : s) ascii &= c != 0 && c < 0x80;
    if (ascii) return val(s);
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

bool IsNone(const val& v) { return v.isNull() || v.isUndefined(); }

const char* ClassName(apkllm::EntryClass k) { return apkllm::EntryClassName(k); }

// An attacker-chosen key as an own data property ("__proto__" included — never the prototype).
void DefineKey(val& obj, const val& key, const val& value) {
    val desc = val::object();
    desc.set("value", value);
    desc.set("writable", true);
    desc.set("enumerable", true);
    desc.set("configurable", true);
    val::global("Object").call<void>("defineProperty", obj, key, desc);
}

// An engine-decided result as JS objects, one to one (module.cpp ToPy): a map keeps its keys in
// order, every string is decoded as CPython's UTF-8 "replace". Consumes the tree: each list / map
// is freed once converted, and a generated per-entry list makes each row only as it converts it.
val ToVal(apkllm::Value& v) {
    using K = apkllm::Value::Kind;
    switch (v.kind) {
        case K::kNull: return val::null();
        case K::kBool: return val(v.b);
        case K::kInt: return Num(static_cast<int64_t>(v.i));
        case K::kUInt: return Num(static_cast<uint64_t>(v.u));
        case K::kFloat: return val(v.f);
        case K::kStr: return SafeStr(v.str());
        case K::kList: {
            val l = val::array();
            unsigned k = 0;
            for (auto& x : v.items->list) l.set(k++, ToVal(x));
            for (size_t i = 0; i < v.items->gen_n; i++) {
                apkllm::Value row = v.items->gen(i);
                l.set(k++, ToVal(row));
            }
            v.items.reset();
            return l;
        }
        case K::kMap: {
            val d = val::object();
            for (auto& kv : v.items->map) {
                // an owned key is computed (attacker text possible); a literal one is a fixed name
                bool owned = false;
                for (const auto& o : v.items->owned) owned |= o->c_str() == kv.first;
                if (owned)
                    DefineKey(d, SafeStr(kv.first), ToVal(kv.second));
                else
                    d.set(kv.first, ToVal(kv.second));
            }
            v.items.reset();
            return d;
        }
    }
    return val::null();
}

int Tri(const val& o) { return IsNone(o) ? -1 : (o.as<bool>() ? 1 : 0); }

apkllm::ExtractNativeLibs Enl(const val& o) {
    const int t = Tri(o);
    return t < 0 ? apkllm::ExtractNativeLibs::kUnknown
                 : (t ? apkllm::ExtractNativeLibs::kTrue : apkllm::ExtractNativeLibs::kFalse);
}

// module.cpp Facts: apk_role "base" / anything else = split / null = unknown.
apkllm::RoleFacts Facts(const val& apk_role, bool role_defaulted, const val& isolated,
                        const val& feature, const val& config_for) {
    apkllm::RoleFacts f;
    f.role = IsNone(apk_role) ? apkllm::ApkRole::kUnknown
             : apk_role.as<std::string>() == "base" ? apkllm::ApkRole::kBase
                                                     : apkllm::ApkRole::kSplit;
    f.defaulted = role_defaulted;
    f.isolated_splits = Tri(isolated);
    f.feature_split = Tri(feature);
    f.config_for_split = Tri(config_for);
    return f;
}

// A negative/fractional page size from JS would wrap to a huge uint64; clamp to 0 so the
// engine's own "page_size must be > 0" guard reports it.
uint64_t PageSize(double page_size) { return page_size > 0 ? static_cast<uint64_t>(page_size) : 0; }

// install_gate whole from the engine (#67): the per-entry verdicts, the honest container verdict,
// the base-AssetManager membership the split facts decide, and the checks.
val InstallGate(const std::string& path, val extract_native_libs, val target_sdk, double page_size,
                val apk_role, bool role_defaulted, val isolated_splits, val feature_split,
                val config_for_split) {
    const int tsdk = IsNone(target_sdk) ? -1 : target_sdk.as<int>();
    apkllm::Value v = apkllm::InstallGateValue(
        path, Enl(extract_native_libs), tsdk, PageSize(page_size),
        Facts(apk_role, role_defaulted, isolated_splits, feature_split, config_for_split));
    return ToVal(v);
}

// extract_map (report=false) / extract_report (report=true) whole from the engine (#67).
val ExtractPlan(const std::string& path, val extract_native_libs, val target_sdk, double page_size,
                val apk_role, bool role_defaulted, val isolated_splits, val feature_split,
                val config_for_split, bool report) {
    const int tsdk = IsNone(target_sdk) ? -1 : target_sdk.as<int>();
    apkllm::Value v = apkllm::ExtractPlanValue(
        path, Enl(extract_native_libs), tsdk, PageSize(page_size),
        Facts(apk_role, role_defaulted, isolated_splits, feature_split, config_for_split), report);
    return ToVal(v);
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

// Every entry's first n device-produced bytes (one archive open). Bytes only — the page's hex view.
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

// content_map whole from the engine (#67): the heads, their magic labels, the summary, the checks.
val ContentMap(const std::string& path, double head_bytes) {
    apkllm::Value v = apkllm::ContentMapValue(path, head_bytes > 0 ? static_cast<size_t>(head_bytes) : 0);
    return ToVal(v);
}

// tamper_report whole from the engine (#67): the raw walk, its summary and its checks.
val TamperReport(const std::string& path) {
    apkllm::Value v = apkllm::TamperReportValue(path);
    return ToVal(v);
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

// container.build_traces, decided whole in the engine (#67 step 2) — module.cpp BuildTracesDict.
val BuildTraces(const std::string& path) {
    apkllm::BuildTraces r = apkllm::ReadBuildTraces(path);
    val out = val::object();
    out.set("ok", r.ok);
    if (!r.ok) {
        out.set("error", SafeStr(r.error));
        if (!r.file_sha256.empty()) out.set("file_sha256", r.file_sha256);
        return out;
    }
    out.set("file_sha256", r.file_sha256);
    val files = val::array();
    for (size_t i = 0; i < r.v1_signer_files.size(); ++i) files.set(i, SafeStr(r.v1_signer_files[i]));
    out.set("v1_signer_files", files);
    out.set("v1_signer_files_total", Num(r.v1_signer_files_total));
    if (r.manifest_present) {
        const auto& mm = r.manifest_main;
        val m = val::object();
        m.set("created_by", mm.created_by_present ? SafeStr(mm.created_by) : val::null());
        m.set("built_by", mm.built_by_present ? SafeStr(mm.built_by) : val::null());
        m.set("main_section_complete", mm.main_section_complete);
        out.set("manifest_main", m);
    } else {
        out.set("manifest_main", val::null());
    }
    if (r.app_metadata_present) {
        val meta = val::object();
        for (const auto& [k, v] : r.app_metadata) DefineKey(meta, SafeStr(k), SafeStr(v));
        out.set("app_metadata", meta);
    } else {
        out.set("app_metadata", val::null());
    }
    val unreadable = val::object();
    for (const auto& [k, v] : r.unreadable) DefineKey(unreadable, SafeStr(k), SafeStr(v));
    out.set("unreadable", unreadable);
    return out;
}

// Play's frosting check in the engine (#59): ApkllmFrosting's raw output, key for key. `keys` are
// DER SubjectPublicKeyInfos (Uint8Array each), in Play's key-list order.
val Frosting(const std::string& path, val keys) {
    std::vector<std::string> der;
    const unsigned n = keys["length"].as<unsigned>();
    for (unsigned i = 0; i < n; ++i) {
        std::vector<uint8_t> raw = emscripten::convertJSArrayToNumberVector<uint8_t>(keys[i]);
        der.emplace_back(raw.begin(), raw.end());
    }
    apkllm::Value v = apkllm::CheckFrosting(path, der);
    return ToVal(v);
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

// module.cpp: an int tri-state (1 / 0 / -1) as true / false / null
val TriVal(int t) { return t < 0 ? val::null() : val(t == 1); }

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
    d.set("strict_lengths", TriVal(c.strict_lengths));
    d.set("strict_lengths_at", OptStr(c.strict_lengths_at));
    d.set("tbs_read", c.tbs_read);
    d.set("error", OptStr(c.error));
    d.set("jdk_rejects", OptStr(c.jdk_rejects));
    d.set("serial", c.serial_present ? SafeStr(c.serial) : val::null());
    d.set("subject", c.tbs_read ? NameObj(c.subject) : val::null());
    d.set("issuer", c.tbs_read ? NameObj(c.issuer) : val::null());
    d.set("unverified", c.unverified);
    return d;
}

val CertList(const std::vector<apkllm::CertAsPresent>& certs) {
    val l = val::array();
    for (size_t i = 0; i < certs.size(); ++i) l.set(i, CertObj(certs[i]));
    return l;
}

// A proof-of-rotation attribute as present (apkllm #62; capped per-attribute facts and the leaf
// match, #65) — module.cpp LineageDict, key for key.
val LineageObj(const apkllm::LineageAsPresent& l) {
    val d = val::object();
    d.set("attrs", l.attrs);
    val attr_errors = val::array();
    for (size_t i = 0; i < l.attr_errors.size(); ++i) attr_errors.set(i, OptStr(l.attr_errors[i]));
    d.set("attr_errors", attr_errors);
    val leaf = val::array();
    for (size_t i = 0; i < l.attr_leaf_matches.size(); ++i) leaf.set(i, TriVal(l.attr_leaf_matches[i]));
    d.set("attr_leaf_matches", leaf);
    d.set("attrs_failed", l.attrs_failed);
    d.set("attrs_mismatched", l.attrs_mismatched);
    d.set("version", l.version_read ? val(l.version) : val::null());
    val nodes = val::array();
    for (size_t i = 0; i < l.nodes.size(); ++i) {
        const auto& n = l.nodes[i];
        val x = val::object();
        x.set("index", n.index);
        x.set("attr", n.attr);
        x.set("attr_error", OptStr(n.attr_error));
        x.set("attr_leaf_match", TriVal(n.attr_leaf_match));
        x.set("flags", n.flags_read ? val(n.flags) : val::null());
        x.set("signed_sig_alg", n.signed_sig_alg_read ? val(n.signed_sig_alg) : val::null());
        x.set("sig_alg", n.error.empty() ? val(n.sig_alg) : val::null());
        x.set("signature_size", n.error.empty() ? Num(static_cast<uint64_t>(n.signature_size)) : val::null());
        x.set("cert", n.cert_present ? CertObj(n.cert) : val::null());
        x.set("error", OptStr(n.error));
        if (n.capabilities_known) {
            val caps = val::array();
            for (size_t k = 0; k < n.capabilities.size(); ++k) caps.set(k, n.capabilities[k]);
            x.set("capabilities", caps);
        } else {
            x.set("capabilities", val::null());
        }
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
    d.set("consumed", s.consumed);
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
    out.set("unverified", r.unverified);
    out.set("rendering", std::string(r.rendering));
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
        x.set("indefinite_wrappers", f.pkcs7.indefinite_wrappers);
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
    val v1d = val::object();
    v1d.set("ok", r.v1_ok);
    v1d.set("error", OptStr(r.v1_error));
    v1d.set("reader", std::string(r.v1_reader));
    v1d.set("files", v1);
    v1d.set("files_total", Num(r.v1_total));
    out.set("v1", v1d);
    return out;
}

int Abi() { return kAbi; }

EMSCRIPTEN_BINDINGS(apkllm_wasm) {
    function("abi", &Abi);
    function("installGate", &InstallGate);
    function("extractPlan", &ExtractPlan);
    function("extractEntry", &ExtractEntry);
    function("entryHeads", &EntryHeads);
    function("contentMap", &ContentMap);
    function("tamperReport", &TamperReport);
    function("signingBlockPairs", &SigningBlockPairs);
    function("buildTraces", &BuildTraces);
    function("signingCerts", &SigningCerts);
    function("frosting", &Frosting);
}
