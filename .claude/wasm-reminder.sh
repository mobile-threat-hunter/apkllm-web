#!/usr/bin/env bash
# Pre-edit hook for apkllm-web's wasm engine sources (apkllm-web's analog of
# apkllm's aosp-reminder.sh). Enforces the inherited core policy — the web
# repo compiles real AOSP/apkllm code as-is and owns only thin glue — plus the
# WASM build lessons learned in dexllm-web.
#
# Never blocks: any failure (missing jq, malformed JSON) exits 0 silently.
set -u

path="$(jq -r '.tool_input.file_path // empty' 2>/dev/null || true)"
[ -z "$path" ] && exit 0
case "$path" in
  */wasm-build/*.cpp|*/wasm-build/*.cc|*/wasm-build/*.h|*/wasm-build/*.hpp) ;;
  */wasm-build/CMakeLists.txt) ;;
  */worker.js) ;;
  *) exit 0 ;;
esac

cat <<'MSG'
🔬 WASM engine source. apkllm-web's inherited policy before editing:

  1. ENGINE LOGIC LIVES IN apkllm (~/Project/apkllm), NOT HERE. The wasm build
     compiles the SAME sources the Python build does — real AOSP libziparchive
     + apkllm native/container + native/apksig/tamper — pulled from the apkllm
     checkout via -DAPKLLM_ROOT. Never vendor-fork, hand-port, or re-derive
     container/tamper logic in this repo; change it upstream and re-sync.
     The embind binding (wasm_module.cpp) is thin marshalling glue mirroring
     apkllm's native/binding/module.cpp — same functions, same field names.

  2. ANALYZER, NOT GATEKEEPER — carried into the UI. Verdicts (install_gate,
     tamper findings) are informational display, never a filter: no entry is
     hidden or dropped on a failed verdict. Manifest-owned inputs
     (extractNativeLibs, targetSdk) are parameters the USER supplies in the UI;
     unknown → render the honest tri-state (needs_manifest), never guess.

  3. WASM BUILD RULES (dexllm-web lessons — violating these cost real debugging):
       - SINGLE-THREADED: -pthread stays OFF. A multithreaded build fails to
         load files (and GitHub Pages can't serve COOP/COEP for
         SharedArrayBuffer anyway).
       - -fexceptions on EVERY translation unit that throws or catches —
         including vendored static libs. A missed TU turns a caught throw into
         an unrecoverable wasm trap.
       - Link flags of record: MODULARIZE=1, FORCE_FILESYSTEM=1,
         ALLOW_MEMORY_GROWTH=1, USE_ZLIB=1, generous STACK_SIZE.

  4. AFTER ENGINE CHANGES, SYNC THE ARTIFACTS: rebuild (ninja -C
     wasm-build/build), node smoke-test on real APKs, copy the fresh .js/.wasm
     to the repo root, and bump the build SHA everywhere index.html pins it —
     the served engine is otherwise stale.

  5. AOSP anchor: android16-qpr2-release / BP4A.251205.006 (~/Project/aosp),
     via the apkllm checkout. Ground truth for verdicts: the native apkllm
     Python API on the same APK, python -m zipfile for entry methods.
MSG
