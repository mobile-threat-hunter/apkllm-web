# apkllm-web

[apkllm](https://github.com/MobileThreatHunter/apkllm)'s **container layer** running in
the browser: real AOSP `system/libziparchive` (the device's own ZIP reader) compiled to
WebAssembly, plus apkllm's install-gate, content-typing and present-vs-consumed tamper
scan over it. Drop an APK and see what the device would consume — nothing is uploaded.

Static page: `index.html` + `worker.js` + `domain.js` + `apkllm.js` / `apkllm.wasm`.
Same structure as [dexllm-web](https://github.com/MobileThreatHunter/dexllm-web).

## What it shows

| Tab | Engine call (mirrors `apkllm._apk_core`) | Python layer ported to `domain.js` |
|---|---|---|
| **Install gate** | `installGate` — every entry libziparchive enumerates, with its install/load verdict (native-lib STORED+page-aligned, dex method ∈ {0,8}, resources.arsc STORED+4-aligned) and the honest tri-state container verdict | `container._container_checks` |
| **Content** | `entryHeads` — each entry's first 512 bytes as its *own device reader* produces them (inflate / stored / lenient raw) | `magic.classify` + `container.content_map` (type by magic, role / extension mismatch) |
| **Tamper scan** | `tamperScan` — an own raw ZIP walk (not libziparchive) reporting where what is *present* diverges from what the device *consumes*: CD↔LFH mismatch, duplicate names, method forgery, Janus, second EOCD | `container._tamper_checks` |
| **Signing block** | `locateSigningBlock` — EOCD / central directory / APK Signing Block location and scheme block ids (structural only) | — |

Manifest-owned inputs (`extractNativeLibs`, `targetSdk`, base-AssetManager membership)
are parameters MMH gets from axmlllm; here you set them in the form. Unknown ⇒ the
verdict stays conditional (`needs_manifest`), never guessed.

**Analyzer, not gatekeeper.** Every verdict is informational display. A failing entry is
highlighted, never hidden; a container libziparchive refuses is still walked by the
tamper scan; every entry's device-faithful bytes can be saved.

Out of scope: signature verification (Java apksig in apkllm) and unwrap (Python).

## Build & verify

See [`wasm-build/README.md`](wasm-build/README.md): `emcmake cmake` + `ninja`, then
`smoke.mjs` (node), `xcheck.{py,mjs}` (every number vs the native Python binding on the
same APKs) and `browser_check.mjs` (the page itself in headless Chrome). After a rebuild
copy `build/apkllm.{js,wasm}` here and bump `window.__APKLLM_BUILD` in `index.html`.
