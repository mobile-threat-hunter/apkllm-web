# apkllm-web

apkllm(APK 컨테이너/압축 해제 분석 라이브러리)의 기능을 브라우저에서 육안으로 확인하는 웹 데모.

- 소스 라이브러리: `/home/nyahumi/Project/apkllm`
- 참조 구현: `/home/nyahumi/Project/dexllm-web` — dexllm을 WASM으로 빌드해 정적 페이지(index.html + dexllm.js/dexllm.wasm)로 띄운 구조를 그대로 따를 것
- dexllm-web 교훈: WASM은 **단일 스레드로 빌드**해야 함 (멀티스레드 빌드 시 파일 로드 실패)
- 데모 범위(확정): **컨테이너 레이어만** — C++ libziparchive 기반 install_gate / extract_map / tamper_scan / content(entry_heads) + 구조적 서명 읽기(signing_block = signing_block_pairs, build_traces = entry_names + entry_heads(names), signing_certs = signingCerts — 서명 인증서 as present, 검증 없음, apkllm #58)를 WASM으로. 서명 검증(Java apksig)·언랩(Python)은 범위 밖.

## 검증 게이트 (`.claude/` — apkllm/dexllm에서 선별 상속)

- **`wasm-reminder.sh`** (PreToolUse, wasm-build C++/CMake/worker.js 편집 시): 엔진 로직은 apkllm 본체에서 고치고 `-DAPKLLM_ROOT`로 당겨올 것(포크 금지) · embind 바인딩은 `native/binding/module.cpp`를 미러링하는 얇은 글루 · analyzer-not-gatekeeper(UI가 verdict로 엔트리를 숨기지 않음) · 단일 스레드 + 전역 `-fexceptions` + 산출물 동기화/SHA 범프.
- **`docs-precommit-check.sh`** (PreToolUse Bash): commit/push 전 docs 드리프트 리뷰 강제 — 완료 후 `DOCS_CHECKED=1` 접두로 재실행.
- **`review-precommit-check.sh`** (PreToolUse Bash): 프로덕션 소스(wasm-build/**, index.html, worker.js, cmd/**) 변경을 싣는 commit/push 전 적대적 리뷰(독립 리뷰어 ≥2) + 재검증(리빌드·node 스모크·네이티브 apkllm/python zipfile 교차검증) 강제 — 완료 후 `REVIEWED=1`.
- **stale 산출물 리마인더** (PostToolUse): wasm-build 소스 수정 시 리빌드→루트 복사→SHA 범프 경고.
- 스킬: `karpathy-guidelines` (그대로 상속).
- 상속 거부: py-quality(파이썬 없음), Java 어댑터 리마인더(서명 범위 밖), uncapped-analyser·dad-reminder·dexkit-* 스킬(dexllm 전용).
