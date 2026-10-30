/* wasm shim: emscripten's musl has no sys/cdefs.h (glibc/BSD header).
 * AOSP headers include it for the __BEGIN_DECLS family only — provide the
 * macros they use, nothing more. (Same shim axmlllm-web uses.) */
#pragma once

#ifdef __cplusplus
#define __BEGIN_DECLS extern "C" {
#define __END_DECLS }
#else
#define __BEGIN_DECLS
#define __END_DECLS
#endif

#ifndef __CONCAT
#define __CONCAT(x, y) x##y
#endif
#ifndef __STRING
#define __STRING(x) #x
#endif
