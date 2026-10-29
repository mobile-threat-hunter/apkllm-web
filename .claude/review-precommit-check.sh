#!/usr/bin/env bash
# PreToolUse(Bash) gate — runs before every Bash tool call.
# Inherited from apkllm's review-precommit-check.sh, adapted for apkllm-web
# (the WASM/browser demo of apkllm's container layer).
#
# Purpose: after any FIX (a change to production source), force an ADVERSARIAL
# CODE REVIEW before the commit/push lands. A container-gate rendering or an
# embind-binding change can be subtly wrong in a way a quick browser look
# doesn't catch; the practice is to spawn independent reviewer agents on the
# diff, triage their findings, fix the real ones, and re-verify BEFORE
# committing. This gate makes that a mandatory, conscious step at publish time.
#
# What "adversarial review" means here (do ALL of it, then commit):
#   0. FIDELITY SELF-CHECK (use AOSP/apkllm as-is; don't fork / don't guess).
#      - The wasm engine compiles the SAME AOSP libziparchive + apkllm
#        native/container + native/apksig/tamper sources the Python build does,
#        pulled from the apkllm checkout (-DAPKLLM_ROOT) — engine-logic changes
#        belong in ~/Project/apkllm, never re-derived in this repo. The embind
#        binding is thin marshalling glue mirroring native/binding/module.cpp.
#      - Analyzer-not-gatekeeper carries into the UI: no verdict is ever used
#        to hide/drop an entry from display. Manifest-owned inputs
#        (extractNativeLibs, targetSdk) are user-supplied UI parameters or
#        shown honestly as needs_manifest — never guessed.
#      - WASM build rules (dexllm-web lessons): SINGLE-THREADED (-pthread OFF;
#        a multithreaded build fails to load files), -fexceptions on every TU
#        that throws or catches (a missed one turns a caught throw into an
#        unrecoverable wasm trap).
#      If the change violates any of these, RECONSIDER — do not commit.
#   1. Spawn >=2 INDEPENDENT reviewer agents on the diff — e.g. the Agent tool
#      with compound-engineering:ce-adversarial-reviewer + ce-correctness-reviewer,
#      or invoke the `code-review` skill. Each must try to CONSTRUCT a breaking
#      input (a malformed/tampered/forged-method/duplicate-name APK, or a UI
#      state that misrenders a tri-state verdict).
#   2. Triage every finding (CONFIRMED / PLAUSIBLE / REFUTED). Fix the real ones.
#   3. Re-verify: rebuild the wasm (ninja -C wasm-build/build), run the node
#      smoke test on real APKs, cross-check verdicts against ground truth
#      (the native apkllm Python API on the same file / python -m zipfile),
#      and if engine artifacts changed, re-sync them to the repo root + bump
#      the build SHA before a browser drop-test.
#   4. THEN re-run the SAME commit/push command prefixed with REVIEWED=1, e.g.:
#          REVIEWED=1 git commit -m "..."
#      (Combine with the docs gate when both apply: DOCS_CHECKED=1 REVIEWED=1 ...)
#
# Only gates commits/pushes whose change touches PRODUCTION source
# (wasm-build/** C++/CMake, index.html, worker.js, cmd/** Go). Docs-only /
# config-only commits, non-git Bash, and git reads pass through untouched.
set -u

cmd="$(jq -r '.tool_input.command // empty' 2>/dev/null || true)"
[[ -z "$cmd" ]] && exit 0

# Only gate git commit / git push.
grep -qE 'git[^&|;]*\b(commit|push)\b' <<<"$cmd" || exit 0

# Already reviewed this turn → allow.
grep -qE 'REVIEWED=1|#[[:space:]]*reviewed' <<<"$cmd" && exit 0

root="${CLAUDE_PROJECT_DIR:-.}"
cd "$root" 2>/dev/null || exit 0

# Collect the files this operation would carry. A COMMIT carries only its own
# change (staged + unstaged-tracked); a PUSH carries every commit ahead of upstream.
if grep -qE 'git[^&|;]*\bpush\b' <<<"$cmd"; then
    up="$(git rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' 2>/dev/null || true)"
    changed="$([[ -n "$up" ]] && git diff --name-only "$up"...HEAD 2>/dev/null)"
else
    changed="$( { git diff --cached --name-only 2>/dev/null
                  git diff --name-only 2>/dev/null; } | sort -u )"
fi

# Does the change touch PRODUCTION source (a "fix")? If not, pass through.
grep -qE '^(wasm-build/.*\.(cpp|cc|h|hpp)|wasm-build/CMakeLists\.txt|index\.html|worker\.js|cmd/.*\.go)$' \
    <<<"$changed" || exit 0

{
    echo "🔬 Adversarial-review gate — this commit/push changes production source"
    echo "   (a fix). Before it lands, run an ADVERSARIAL CODE REVIEW and address"
    echo "   the findings:"
    echo "     0. FIDELITY SELF-CHECK: engine logic lives in ~/Project/apkllm (AOSP"
    echo "        as-is via -DAPKLLM_ROOT) — the binding is thin glue; the UI never"
    echo "        filters on a verdict; manifest inputs are supplied or needs_manifest,"
    echo "        never guessed; wasm stays single-threaded with -fexceptions."
    echo "     1. Spawn >=2 INDEPENDENT reviewers on the diff (Agent tool:"
    echo "        compound-engineering:ce-adversarial-reviewer + ce-correctness-reviewer,"
    echo "        or the code-review skill). Each must CONSTRUCT a breaking input"
    echo "        (malformed / tampered / forged-method / duplicate-name APK, or a"
    echo "        tri-state the UI misrenders)."
    echo "     2. Triage findings; fix the real ones."
    echo "     3. Re-verify: rebuild wasm, node smoke on real APKs, cross-check vs the"
    echo "        native apkllm Python API / python zipfile; re-sync artifacts + bump"
    echo "        the build SHA if the engine changed."
    echo "   Then re-run the SAME command prefixed with REVIEWED=1, e.g.:"
    echo "       REVIEWED=1 git commit -m \"...\""
    echo "   (with the docs gate: DOCS_CHECKED=1 REVIEWED=1 git commit -m \"...\")"
} >&2
exit 2
