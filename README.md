# apkllm-web

[apkllm](https://github.com/mobile-threat-hunter/apk-analyzer-for-llm)'s **container layer** running in
the browser: real AOSP `system/libziparchive` (the device's own ZIP reader) compiled to
WebAssembly, plus apkllm's install-gate, content-typing, present-vs-consumed tamper
scan and the structural signing-side reads (APK Signing Block pairs, signer certificates as present, build traces) over it. Drop an APK and see what the device would consume — nothing is uploaded.

**Live:** <https://mobile-threat-hunter.github.io/apkllm-web/>

Static page: `index.html` + `worker.js` + `domain.js` + `apkllm.js` / `apkllm.wasm` + `apkllm_logo.png`.
Same structure as [dexllm-web](https://github.com/mobile-threat-hunter/dexllm-web).

## What it shows

| Tab | Engine call (mirrors `apkllm._apk_core`) | Python layer ported to `domain.js` |
|---|---|---|
| **Install gate** | `installGate` — every entry libziparchive enumerates, with its install/load verdict (native-lib STORED+page-aligned, dex method ∈ {0,8}, resources.arsc STORED+4-aligned) and the honest tri-state container verdict | `container._container_checks` |
| **Extract** | `extractEntry` per entry — the bytes come only from the entry's **own mapped device reader** (four-reader model: `NativeLibraryHelper` / `ART.DexFileLoader` strict, `AssetManager` lenient, generic `libziparchive` strict). Method 8 → inflate, 0 → stored copy, a forged method → raw stored only for AssetManager classes; a strict reader's forged entry is reported as rejected, never re-read with another reader's algorithm. One entry (`bytes`, or **double-click its row**) or a selection / all as a `.zip` | `container._disposition` + `extract_map` + `extract_report` (the decompression plan: reader, disposition, device_loads, deliverable) |
| **Content** | `entryHeads` — each entry's first 512 bytes as its *own device reader* produces them (inflate / stored / lenient raw) | `magic.classify` + `container.content_map` (type by magic, role / extension mismatch) |
| **Images** | `extractEntry` — every entry that is an image by magic (whatever its name), rendered lazily from its own reader's bytes; width × height is read from the header first (PNG, GIF, BMP, ICO, WebP, JPEG) and a bitmap over 24 Mpx is decoded only on request in the viewer | Content's `classify` + `extension_mismatch` (MIME from magic, never from the name) |
| **Tamper scan** | `tamperScan` — an own raw ZIP walk (not libziparchive) reporting where what is *present* diverges from what the device *consumes*: CD↔LFH mismatch, duplicate names, method forgery, Janus, second EOCD | `container._tamper_checks` |
| **Signing** | `signingBlockPairs` — the APK Signing Block's ID→value pairs in block order (duplicates kept; first 256 + exact total, whole-walk count + first pair per named ID; no value read) and the two gates both AOSP readers apply first (CD contiguous with the EOCD, no ZIP64). `signingCerts` — every signer certificate as present (v1 / v2 / v3 / v3.1 / stamp; subject / issuer in the JDK 17 form apksig reports, hidden characters escaped; serial, SHA-256; nothing verified), and each v3 / v3.1 / stamp proof-of-rotation lineage node by node (the capabilities each node claims, which attribute it came from and whether that attribute is structurally sound, and whether each lineage ends in the signer's own certificate — apksig keeps only attributes that parse and verify; per-attribute facts stop at 16, their counts stay exact). `entryNames` + `entryHeads(names)` — the v1 signature files under `META-INF/`, `MANIFEST.MF` and AGP's `app-metadata.properties` through their own device readers (4 KiB heads) | `container.signing_block` (pair names: apksig constants or observed IDs, duplicate / unknown IDs, which copy of an ID apksig reads, a malformed pair stopping the walk) + `container.signing_certs` (#58: which certificate apksig would read where, which bag certificate each v1 SignerInfo names — exact / equivalent / canonical_unknown / none / unknown / never) + `container.build_traces` (v1 signer files, `Created-By` / `Built-By` by apksig's manifest rules, app-metadata keys — attacker-writable hints, never evidence) |

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

**Extract naming — apkllm's convention** (as `apkllm.unwrap`: `{md5}.apk` + `{input md5}.json`).
Entry names are attacker-controlled, so no output file is ever named after one: an extracted
entry is `{md5}.bin` of its **content**; identical content is one file, an md5 collision
(same md5, different sha256) becomes `{md5}.{sha256}.bin`, never an overwrite. The JSON report
maps every entry name → file.

- **Bundle** (extract selected / all) → `<input md5>.extracted.zip` = flat `{md5}.bin` files +
  `<input md5>.json`: the input (name, size, md5, sha256), the manifest inputs, and per entry
  the original name, `file`, md5, sha256, size, class, reader, planned disposition and what
  the reader actually did (`stored` / `inflate` / `lenient_stored`) — or `ok: false` with a
  failure cause and the engine's error: `reader_rejected` (its strict reader rejects a forged
  method; the device would not load it either), `name_unaddressable` (the lookup missed — an
  entry name that is not valid UTF-8 is shown U+FFFD-replaced and looked up by its raw bytes,
  `name_hex`, as native apkllm does since #24 / #40, so this no longer follows from the name)
  or `extract_failed` (apkllm's own guards — 512 MiB per entry, implausible deflate expansion —
  or a corrupt stream). Directory entries (`res/`) are listed, with no file.
- **One entry** (`bytes`, or double-click its row) → `{md5}.zip` = `{md5}.bin` + `{md5}.json`,
  named exactly as the bundle would name that content: every other entry that could share the
  md5 (same size) is checked, and of different contents sharing an md5 the first in archive order
  keeps `{md5}`, the others get `{md5}.{sha256}` (zip, file and JSON alike). The JSON lists every
  entry with that content, so two downloads of identical content yield the same file and the
  same JSON — unzipping both into one folder never loses a mapping or overwrites other bytes.

The zips are STORED packaging built in the worker (capped at 65 533 entries and 1 GiB of
extracted bytes); dropping another file (or **cancel**) stops a running bundle. md5 is the
content *name* (apkllm's choice), sha256 beside it tells an md5 collision from identical
content (a pure-JS SHA-256 stands in where WebCrypto is unavailable, e.g. a plain-http origin).

Out of scope: signature verification (Java apksig in apkllm: whether a scheme verifies, whose
signature it is, platform_view's device-reject rules) and unwrap (Python). The Signing tab shows
only what the container holds — its certificates included, unverified: a certificate's bytes are
public, so a listed one proves nothing about who signed the APK.

## Build & verify

See [`wasm-build/README.md`](wasm-build/README.md): `emcmake cmake` + `ninja`, then
`smoke.mjs` (node), `xcheck.{py,mjs}` (every number vs the native Python binding on the
same APKs) and `browser_check.mjs` (the page itself in headless Chrome). After a rebuild
copy `build/apkllm.{js,wasm}` here and bump `window.__APKLLM_BUILD` in `index.html` (also after
any `worker.js` / `domain.js` change: the pin cache-busts all four as a set).
