# wasm-build — the emscripten/embind project behind `apkllm.js` / `apkllm.wasm`

apkllm's **container layer** compiled to WebAssembly for the apkllm-web demo: real AOSP
`system/libziparchive` (+ libbase / libutils / liblog / libcutils / incfs host deps,
same source lists as `apkllm/CMakeLists.txt`) and apkllm's `native/container` +
`native/apksig` — the same `apk_native_static` source list: since apkllm #67 every report
(install_gate, extract_plan, tamper_report, content_map with its magic table, build_traces,
signing_certs) is decided whole in the engine as an ordered `Value`, plus the signing-block pair
walk and Play's frosting check (`frosting.cpp`, #59). Certificates hash with AOSP libavb's
portable SHA-256; the frosting check's key parse + ECDSA run on AOSP BoringSSL `crypto`
(`OPENSSL_NO_ASM`, as apkllm builds it). Nothing is
forked — every engine source is pulled from the apkllm / AOSP checkouts at configure
time; this directory owns only the build recipe, a one-header musl shim, and the
embind glue.

Out of scope on purpose: APK signature verification (Java apksig). apkllm's
`bssl_hidden_hooks.h` is not applied to `mem.cc`: under emscripten BoringSSL's allocator hooks are
static NULL pointers (no weak symbols), so they never become imports — and the header would clash.

## Build

```sh
source ~/emsdk/emsdk_env.sh                     # emcc 6.0.0 (libc++ 21: the engine's magic.cpp needs
                                                # floating-point std::from_chars, libc++ >= 20)
embuilder build zlib                            # once per fresh emsdk: a parallel first build races on the port
cd wasm-build
emcmake cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
    -DAPKLLM_ROOT=/home/nyahumi/Project/apkllm   # -DAOSP_ROOT defaults to ~/Project/aosp
cmake --build build --parallel
node smoke.mjs                                  # real APKs from dexllm/test_apk + a non-zip
python3 tamper_fixtures.py /tmp/fx && node smoke.mjs /tmp/fx/*.apk   # tamper findings path
# frosting fixtures (test-key signed: verified / forged / replay / duplicate / > 1024 splits /
# malformed / key index past the list / a signature past 141 bytes / a non-DER one — #83's
# no-keys cases; apkllm #87's container gap / value under 4 bytes / malformed protobuf with a forged
# signature) come from apkllm's tests/frostfix.py — crafted per session
cp build/apkllm.js build/apkllm.wasm ..         # then bump window.__APKLLM_BUILD in index.html
```

Outputs: `build/apkllm.js` (MODULARIZE, `createApkllm`) + `build/apkllm.wasm`.

### Cross-checks (the review gate's "ground truth" step)

```sh
# 1. every number vs the native Python layer on the same APKs
(cd ~/Project/apkllm && PYTHONPATH=src .venv/bin/python -P \
   ~/Project/apkllm-web/wasm-build/xcheck.py /tmp/native.json APK... /tmp/fx/*.apk [--frost-key B64])
node xcheck.mjs /tmp/native.json                # → ALL MATCH
# 2. the page itself in headless Chrome (needs node ≥ 22 for global WebSocket —
#    ~/emsdk/node/22.16.0_64bit/bin/node — and google-chrome on PATH)
~/emsdk/node/22.16.0_64bit/bin/node browser_check.mjs APK [shot.png]   # → BROWSER OK
```

`xcheck` compares, since #67, the engine's own results on both sides — content_map, tamper_report,
install_gate + extract_report (seven manifest / split-fact combinations), build_traces,
signing_certs and frosting (under the built-in key and every `--frost-key`) — whole, key order
included, and `signing_block` as `domain.js` names it. Where the platform legitimately differs it
compares less: libziparchive's iteration order is `std::hash` order, which differs between
wasm32 and x86_64, so entry rows and `exceptions` are compared by name and a histogram's tie order
is not compared; past build_traces' 64-name cap WHICH v1 signer files are kept follows the same
order (only the total and the count are compared); a JS object puts integer-like keys first
(app-metadata compared sorted). It also runs `extract_entry` on every entry on both sides — keyed
`x:<name_hex>` (raw bytes) for a lossy name, else `s:<name>` (sha256 of the device-faithful
bytes, or the identical rejection error).

## Layout

- `CMakeLists.txt` — mirrors apkllm's `ziparchive_static` / `crypto` / `apk_native_static` source
  lists; single-threaded, global `-fexceptions`, `USE_ZLIB=1`,
  `FORCE_FILESYSTEM=1` (MEMFS backs libziparchive's `open()`/`mmap()`).
- `shim/include/sys/cdefs.h` — the only header musl lacks that AOSP includes
  (`__BEGIN_DECLS`); same shim axmlllm-web uses.
- `wasm_module.cpp` — embind functions mirroring `apkllm/native/binding/module.cpp`
  one-to-one (`abi`, `installGate`, `extractPlan`, `extractEntry`, `entryHeads` (+ the `names`
  filter), `contentMap`, `tamperReport`, `signingBlockPairs`, `buildTraces`, `signingCerts`,
  `frosting`; an engine `Value` converted as `ToPy` does — map keys in order, strings as CPython's
  UTF-8 "replace", a computed key defined as an own property; same field names incl. `name_hex` / `entry_hex` for a name that is not strict
  UTF-8, Python `None` ⇄ JS `null`; `extractEntry` takes the name as a string or, for a lossy
  name, a `Uint8Array` of its raw bytes — Python's `bytes`; embind checks the argument count, so
  every argument is passed, `null` where Python takes its `None` default).
- `smoke.mjs` — node smoke test; self-consistency across the functions (contentMap rows align
  with entryHeads rows — the worker pairs them for the hex view; a frosting protobuf only under a
  verified signature). Ground truth is `xcheck`.
- `tamper_fixtures.py` — synthesizes the fixtures: dup-name / Janus / CD-method-forged
  (shapes from `apkllm/tests/test_checks.py`, the findings path) plus the review-found
  drift cases — `ctor` (extension = a JS `Object.prototype` key), `shortbad` (entry names
  libziparchive accepts but strict UTF-8 rejects, ≤16 bytes, and BOM-prefixed names) and
  `tail` (heads cut inside a UTF-8 sequence), and `readers` — every one of the four
  device readers STORED / DEFLATED plus a CD method forged to 99 per reader (strict readers
  reject, AssetManager reads raw) plus hostile names (`../`, a directory entry, case-only
  twins, a DOS device stem, a 300-byte segment, tab / newline / CR / leading-quote / formula)
  for the md5-named downloads and the copy TSV; `lossy` / `lossydup` (#40: names that are not
  strict UTF-8), and `many` (#49: > 20 items in every check `detail` list — the cap, `<key>_count` /
  `_cut` and the kept items, in raw-name byte order on both sides), `bury` (a Master-Key duplicate after 21 per-entry findings) and `lfhlong` (a kept finding's `detail` quoting 700-byte names, cut head + `…` + tail at 512 code points, an astral char at the head's last code point). `smoke.mjs` asserts the expected findings / `would_open` per fixture name.
  Signing-side fixtures: `sigpairs` (duplicate v2 / unknown IDs, observed IDs, nested and
  wrong-case v1 files, a MANIFEST.MF read by apksig's rules — blank lead lines, continuation,
  CRLF / CR, a dotless-i `Built-By` —, hostile app-metadata keys), `sigbad` (a malformed pair after
  a valid one + a forged-method MANIFEST.MF), `sigcut` (300 pairs, the only v2 at #290), `sigsplit`
  (junk between CD and EOCD), `mfcut` (a main section past the 4 KiB head), `v1many` (70 v1 files).
- `xcheck.py` / `xcheck.mjs` — native-vs-wasm field-by-field comparison (above).
- `browser_check.mjs` — serves the repo root, drives `index.html` over CDP, feeds an
  APK through the file input and asserts every panel rendered; on the Extract tab it runs
  "extract all", captures the zip blob and checks it in node with `node:crypto` (every file
  is `{md5}.bin` of its own content — `{md5}.{sha256}.bin` for readers.apk's real MD5 collision
  pair —, the report is `{input md5}.json`, every entry is a file, a directory or a failure with
  a cause, the four-reader rule), single-entry downloads named exactly as the bundle names them
  (identical-content twins → the same file and JSON), the row double-click download (content
  and naming checked on a synthetic dblclick; real CDP mouse input checks one download per
  double-click and no clipboard write), copy buttons and tab badges. `shot.png` → Tamper scan tab,
  `shot-extract.png` → Extract tab.
- `../domain.js` (repo root) — what apkllm still decides in Python: `container.signing_block`'s
  pair naming over `signingBlockPairs`, and `signing.FROSTING_KEYS_DEFAULT`; plus the engine ABI
  the page expects (the worker refuses another `apkllm.wasm`).

## Lessons carried from dexllm-web / axmlllm-web

- `-pthread` stays OFF: the multithreaded build fails to load files, and GitHub Pages
  cannot serve COOP/COEP anyway.
- `-fexceptions` on every TU (static libs included) or a caught throw becomes a trap.
- zlib comes from the emscripten port, not AOSP's `external/zlib` (fidelity caveat
  shared with axmlllm-web); `${EXT}/zlib` is kept off the include path so the port's
  headers win.
- 64-bit offsets/sizes cross embind as doubles (no `WASM_BIGINT`); fine below 2^53.
- **Entry order is a 32-bit device's.** libziparchive iterates its CD hash table, keyed
  by `std::hash<std::string_view>` — libc++ uses murmur2 on a 32-bit `size_t` (wasm32)
  and CityHash64 on x86-64, so `installGate` / `entryHeads` enumerate in a different
  order than the native x86-64 build (and than a 64-bit device). Values are identical;
  compare by name (`xcheck.mjs` does). `tamperReport` is the raw CD walk and keeps file order.
- **liblog's host logger traps under wasm.** `GetThreadId()` in
  `liblog/logger_write.cpp` has no branch for a platform that is none of
  `__BIONIC__/__APPLE__/__linux__/_WIN32`, so clang emits `unreachable` and the first
  `ALOGW` libziparchive prints ("Found duplicate entry", "missed a central dir sig")
  kills the module — on clean APKs nothing is logged, so it only shows on exactly the
  tampered inputs the demo is for. `wasm_module.cpp` installs its own stderr logger via
  liblog's public `__android_log_set_logger()` from a static initializer (no AOSP patch).
