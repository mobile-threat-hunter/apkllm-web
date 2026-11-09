# wasm-build — the emscripten/embind project behind `apkllm.js` / `apkllm.wasm`

apkllm's **container layer** compiled to WebAssembly for the apkllm-web demo: real AOSP
`system/libziparchive` (+ libbase / libutils / liblog / libcutils / incfs host deps,
same source lists as `apkllm/CMakeLists.txt`) and apkllm's `native/container` +
`native/apksig` (structural EOCD / signing-block pair walk + tamper scan + the signer
certificates as present, `certs.cpp`, hashed with AOSP libavb's portable SHA-256). Nothing is
forked — every engine source is pulled from the apkllm / AOSP checkouts at configure
time; this directory owns only the build recipe, a one-header musl shim, and the
embind glue.

Out of scope on purpose: BoringSSL (apkllm links it only into its zip probe; no container
symbol needs it) and signature verification (Java apksig).

## Build

```sh
source ~/emsdk/emsdk_env.sh                     # emcc 4.0.9 used for the current build
cd wasm-build
emcmake cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
    -DAPKLLM_ROOT=/home/nyahumi/Project/apkllm   # -DAOSP_ROOT defaults to ~/Project/aosp
cmake --build build --parallel
node smoke.mjs                                  # real APKs from dexllm/test_apk + a non-zip
python3 tamper_fixtures.py /tmp/fx && node smoke.mjs /tmp/fx/*.apk   # tamper findings path
cp build/apkllm.js build/apkllm.wasm ..         # then bump window.__APKLLM_BUILD in index.html
```

Outputs: `build/apkllm.js` (MODULARIZE, `createApkllm`) + `build/apkllm.wasm`.

### Cross-checks (the review gate's "ground truth" step)

```sh
# 1. every number vs the native Python layer on the same APKs
(cd ~/Project/apkllm && PYTHONPATH=src .venv/bin/python -P \
   ~/Project/apkllm-web/wasm-build/xcheck.py /tmp/native.json APK... /tmp/fx/*.apk)
node xcheck.mjs /tmp/native.json                # → ALL MATCH
# 2. the page itself in headless Chrome (needs node ≥ 22 for global WebSocket —
#    ~/emsdk/node/22.16.0_64bit/bin/node — and google-chrome on PATH)
~/emsdk/node/22.16.0_64bit/bin/node browser_check.mjs APK [shot.png]   # → BROWSER OK
```

`xcheck` compares content_map / tamper_report / install_gate + extract_report (six input
combinations) field by field, including the `checks[]` reasons `domain.js` reproduces from
Python (a check's `detail` list compared in order: both sides keep the first 20 in raw-name byte
order, #49 — libziparchive's own iteration order is `std::hash` order, which differs between
wasm32 and x86_64, so `exceptions` / entry rows are compared by name), and runs `extract_entry` on every entry on both sides — keyed `x:<name_hex>` (raw bytes) for a lossy name, else `s:<name>` (sha256 of the
device-faithful bytes, or the identical rejection error). It also compares `signing_block` exactly
and `build_traces` with its attacker-keyed dicts sorted (a JS object puts integer-like keys
first); past build_traces' 64-name cap WHICH v1 signer files are kept follows the same hash order,
so there only the total and the count are compared.

## Layout

- `CMakeLists.txt` — mirrors apkllm's `ziparchive_static` / `apk_native_static` source
  lists minus `crypto`; single-threaded, global `-fexceptions`, `USE_ZLIB=1`,
  `FORCE_FILESYSTEM=1` (MEMFS backs libziparchive's `open()`/`mmap()`).
- `shim/include/sys/cdefs.h` — the only header musl lacks that AOSP includes
  (`__BEGIN_DECLS`); same shim axmlllm-web uses.
- `wasm_module.cpp` — embind functions mirroring `apkllm/native/binding/module.cpp`
  one-to-one (`installGate`, `extractEntry`, `entryHeads` (+ the `names` filter), `entryNames`,
  `signingBlockPairs`, `tamperScan`; same field names incl. `name_hex` / `entry_hex` for a name that is not strict
  UTF-8, Python `None` ⇄ JS `null`; `extractEntry` takes the name as a string or, for a lossy
  name, a `Uint8Array` of its raw bytes — Python's `bytes`; embind checks the argument count, so
  every argument is passed, `null` where Python takes its `None` default).
- `smoke.mjs` — node smoke test; self-consistency across the six functions. Ground
  truth is the native binding on the same files:
  `cd ~/Project/apkllm && PYTHONPATH=src .venv/bin/python -c 'import sys; sys.path.insert(0,"build/dev"); import _apk_core as c; print(c.install_gate(PATH, arsc_scope=None)["entry_count"])'`
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
- `../domain.js` (repo root) — apkllm's Python policy layer (`magic.py`,
  `container._container_checks` / `content_map` / `_tamper_checks` / `_disposition` +
  `extract_report`) ported to JS; the
  worker runs it over the engine's raw results.

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
  compare by name (`xcheck.mjs` does). `tamperScan` is the raw CD walk and keeps file order.
- **liblog's host logger traps under wasm.** `GetThreadId()` in
  `liblog/logger_write.cpp` has no branch for a platform that is none of
  `__BIONIC__/__APPLE__/__linux__/_WIN32`, so clang emits `unreachable` and the first
  `ALOGW` libziparchive prints ("Found duplicate entry", "missed a central dir sig")
  kills the module — on clean APKs nothing is logged, so it only shows on exactly the
  tampered inputs the demo is for. `wasm_module.cpp` installs its own stderr logger via
  liblog's public `__android_log_set_logger()` from a static initializer (no AOSP patch).
