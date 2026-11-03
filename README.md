# apkllm-web

[apkllm](https://github.com/mobile-threat-hunter/apk-analyzer-for-llm)'s **container layer** running in
the browser: real AOSP `system/libziparchive` (the device's own ZIP reader) compiled to
WebAssembly, plus apkllm's install-gate, content-typing and present-vs-consumed tamper
scan over it. Drop an APK and see what the device would consume — nothing is uploaded.

**Live:** <https://mobile-threat-hunter.github.io/apkllm-web/>

Static page: `index.html` + `worker.js` + `domain.js` + `apkllm.js` / `apkllm.wasm` + `apkllm_logo.png`.
Same structure as [dexllm-web](https://github.com/mobile-threat-hunter/dexllm-web).

## What it shows

| Tab | Engine call (mirrors `apkllm._apk_core`) | Python layer ported to `domain.js` |
|---|---|---|
| **Install gate** | `installGate` — every entry libziparchive enumerates, with its install/load verdict (native-lib STORED+page-aligned, dex method ∈ {0,8}, resources.arsc STORED+4-aligned) and the honest tri-state container verdict | `container._container_checks` |
| **Extract** | `extractEntry` per entry — the bytes come only from the entry's **own mapped device reader** (four-reader model: `NativeLibraryHelper` / `ART.DexFileLoader` strict, `AssetManager` lenient, generic `libziparchive` strict). Method 8 → inflate, 0 → stored copy, a forged method → raw stored only for AssetManager classes; a strict reader's forged entry is reported as rejected, never re-read with another reader's algorithm. One entry (`bytes`, or **double-click its row**) or a selection / all as a `.zip` | `container._disposition` + `extract_map` + `extract_report` (the decompression plan: reader, disposition, device_loads, deliverable) |
| **Content** | `entryHeads` — each entry's first 512 bytes as its *own device reader* produces them (inflate / stored / lenient raw) | `magic.classify` + `container.content_map` (type by magic, role / extension mismatch) |
| **Tamper scan** | `tamperScan` — an own raw ZIP walk (not libziparchive) reporting where what is *present* diverges from what the device *consumes*: CD↔LFH mismatch, duplicate names, method forgery, Janus, second EOCD | `container._tamper_checks` |
| **Signing block** | `locateSigningBlock` — EOCD / central directory / APK Signing Block location and scheme block ids (structural only) | — |

**Copy.** As in dexllm-web, every card has a **⧉ copy** button that copies its whole
dataset as tab-separated text (every entry, not just the filtered view); clicking an entry
name or a finding's entry copies that name byte-exact from the report data. Names are
attacker-controlled, so TSV cells escape `\\ \t \n \r \"` and U+0085/2028/2029 (one entry is
one row for any line splitter, and a leading quote cannot open a spreadsheet quoted field),
and a cell starting with `= + - @` gets a leading `'` so a pasted sheet never evaluates it.

Manifest-owned inputs (`extractNativeLibs`, `targetSdk`, base-AssetManager membership)
are parameters MMH gets from axmlllm; here you set them in the form. Unknown ⇒ the
verdict stays conditional (`needs_manifest`), never guessed.

**Analyzer, not gatekeeper.** Every verdict is informational display. A failing entry is
highlighted, never hidden; a container libziparchive refuses is still walked by the
tamper scan; every entry's device-faithful bytes can be saved, one at a time or as a bundle.

**Extract bundle.** `<apk>.extracted.zip` holds `files/<entry name>` for every entry its
reader delivered, plus `apkllm-extract.json`: per entry the original name, output path,
class, reader, planned disposition, what the reader actually did (`stored` / `inflate` /
`lenient_stored`), size and sha256 — or `ok: false` with a failure cause and the engine's
error: `reader_rejected` (its strict reader rejects a forged method; the device would not
load it either), `name_unaddressable` (an entry name that is not valid UTF-8, or that
decodes like another entry's — names cross apkllm's binding as U+FFFD-replaced text, so
the by-name lookup cannot reach it; native Python behaves the same) or `extract_failed` (apkllm's own guards — 512 MiB per entry,
implausible deflate expansion — or a corrupt stream). Entry names are attacker-controlled,
so output paths are made safe for Linux, macOS and Windows: `..`, control/reserved
characters, `~` (NTFS 8.3 aliases), trailing dots/spaces and DOS device stems are
%-escaped, a segment over 200 bytes is cut with a `~hash` suffix, a path over 1024 bytes is
flattened to `%LONGPATH~hash/<leaf>`, and a path that clashes with an earlier one
(case-folded incl. σ/ς, NFC/NFD, ignorable code points, file-vs-directory) goes to
`collisions/<n>/`. Directory entries (`res/`) become directory records. The zip is STORED
packaging built in the worker, capped at 65 533 entries and 1 GiB of extracted bytes;
dropping another file (or **cancel**) stops a running bundle. Windows Explorer's built-in
unzip stops at 260-character paths — use 7-Zip for deep trees.

Out of scope: signature verification (Java apksig in apkllm) and unwrap (Python).

## Build & verify

See [`wasm-build/README.md`](wasm-build/README.md): `emcmake cmake` + `ninja`, then
`smoke.mjs` (node), `xcheck.{py,mjs}` (every number vs the native Python binding on the
same APKs) and `browser_check.mjs` (the page itself in headless Chrome). After a rebuild
copy `build/apkllm.{js,wasm}` here and bump `window.__APKLLM_BUILD` in `index.html`.
