cmake_minimum_required(VERSION 3.20)
project(apkllm_wasm LANGUAGES C CXX)

# Single-threaded WASM build of apkllm's CONTAINER layer for the apkllm-web
# GitHub Pages demo: real AOSP libziparchive (+ its host deps) and apkllm's
# native/container + native/apksig (structural ZIP/signing-block reader +
# tamper scan), all compiled AS-IS from the apkllm / AOSP checkouts. Nothing
# is forked here — the engine lives upstream; this file is the build recipe
# and wasm_module.cpp the embind glue.
#
# Out of scope (by design): BoringSSL `crypto`. apkllm's CMakeLists links it
# only into apkllm-zip-probe; no symbol the container layer uses comes from it,
# so the wasm build drops the whole target (the signer certificates' SHA-256 is
# libavb's). Signature verification is Java apksig and stays out of the web demo.
#
# Configure with:
#   source ~/emsdk/emsdk_env.sh
#   emcmake cmake -B build -G Ninja -DAPKLLM_ROOT=/path/to/apkllm [-DAOSP_ROOT=/path/to/aosp]
#   cmake --build build --parallel
#
# Outputs: build/apkllm.js + build/apkllm.wasm — copy into apkllm-web/.

set(CMAKE_CXX_STANDARD 23)   # apkllm's own standard
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT EMSCRIPTEN)
    message(FATAL_ERROR "This is the wasm build — configure through `emcmake cmake`")
endif()

if(NOT DEFINED APKLLM_ROOT)
    message(FATAL_ERROR "Pass -DAPKLLM_ROOT=/abs/path/to/apkllm")
endif()
get_filename_component(APKLLM_ROOT "${APKLLM_ROOT}" ABSOLUTE)
if(NOT EXISTS "${APKLLM_ROOT}/native/container/container.cpp")
    message(FATAL_ERROR "apkllm not found at ${APKLLM_ROOT} (no native/container/container.cpp)")
endif()

# ── AOSP source root — same anchor as apkllm (android16-qpr2-release / BP4A.251205.006)
if(NOT DEFINED AOSP_ROOT)
    set(AOSP_ROOT "/home/nyahumi/Project/aosp" CACHE PATH "AOSP checkout root")
endif()
if(NOT EXISTS "${AOSP_ROOT}/system/libziparchive/zip_archive.cc")
    message(FATAL_ERROR "AOSP_ROOT='${AOSP_ROOT}' does not contain system/libziparchive. Set -DAOSP_ROOT=/path/to/aosp")
endif()

set(SYS "${AOSP_ROOT}/system")
set(EXT "${AOSP_ROOT}/external")

# ── Include roots — same list as APKLLM_ROOT/CMakeLists.txt, plus the musl shim.
set(AOSP_INCLUDES
    # Headers musl lacks (sys/cdefs.h) — searched before the emscripten sysroot.
    ${CMAKE_CURRENT_SOURCE_DIR}/shim/include
    ${SYS}/libziparchive/include
    ${SYS}/libziparchive
    ${SYS}/core/libutils/include
    ${SYS}/core/libutils/binder/include
    ${SYS}/libbase/include
    ${SYS}/core/libcutils/include
    ${SYS}/logging/liblog/include
    ${SYS}/core/include
    ${EXT}/fmtlib/include
    ${SYS}/incremental_delivery/incfs/util/include
    ${SYS}/libziparchive/incfs_support/include
)
# NOTE: ${EXT}/zlib is deliberately NOT on the include path — zlib comes from the
# emscripten port (USE_ZLIB=1) and its headers must win. Fidelity caveat: that is
# not AOSP's external/zlib copy (same trade-off axmlllm-web makes).

# ── Source sets — same lists as APKLLM_ROOT/CMakeLists.txt (ziparchive_static).
set(LZ ${SYS}/libziparchive)
set(LIBZIPARCHIVE_SRCS
    ${LZ}/zip_archive.cc ${LZ}/zip_cd_entry_map.cc ${LZ}/zip_error.cpp
)

set(UB ${SYS}/core/libutils/binder)
set(LIBUTILS_BINDER_SRCS
    ${UB}/Errors.cpp ${UB}/RefBase.cpp ${UB}/SharedBuffer.cpp ${UB}/String16.cpp
    ${UB}/String8.cpp ${UB}/StrongPointer.cpp ${UB}/Unicode.cpp ${UB}/VectorImpl.cpp
)

set(LU ${SYS}/core/libutils)
set(LIBUTILS_SRCS
    ${LU}/FileMap.cpp ${LU}/JenkinsHash.cpp ${LU}/LightRefBase.cpp
    ${LU}/NativeHandle.cpp ${LU}/Printer.cpp ${LU}/StopWatch.cpp
    ${LU}/SystemClock.cpp ${LU}/Threads.cpp ${LU}/Timers.cpp
    ${LU}/Tokenizer.cpp ${LU}/misc.cpp
)

set(LB ${SYS}/libbase)
set(LIBBASE_SRCS
    ${LB}/chrono_utils.cpp ${LB}/file.cpp ${LB}/hex.cpp ${LB}/logging.cpp
    ${LB}/mapped_file.cpp ${LB}/parsebool.cpp ${LB}/parsenetaddress.cpp
    ${LB}/posix_strerror_r.cpp ${LB}/process.cpp ${LB}/properties.cpp
    ${LB}/result.cpp ${LB}/stringprintf.cpp ${LB}/strings.cpp ${LB}/threads.cpp
    ${LB}/test_utils.cpp ${LB}/errors_unix.cpp ${LB}/cmsg.cpp
)
# NOTE: utf8.cpp is the Windows-only wrapper; on POSIX it maps inline — do not compile it.

set(LL ${SYS}/logging/liblog)
set(LIBLOG_SRCS
    ${LL}/log_event_list.cpp ${LL}/log_event_write.cpp ${LL}/logger_name.cpp
    ${LL}/logger_read.cpp ${LL}/logger_write.cpp ${LL}/logprint.cpp
    ${LL}/properties.cpp ${LL}/event_tag_map.cpp
)
set(FMT_SRCS ${EXT}/fmtlib/src/format.cc)

set(LC ${SYS}/core/libcutils)
set(LIBCUTILS_SRCS ${LC}/trace-host.cpp)

set(LIBINCFS_SRCS ${SYS}/incremental_delivery/incfs/util/map_ptr.cpp)

# C++ exceptions must be enabled on EVERY translation unit that throws or
# catches (dexllm-web lesson): without -fexceptions emscripten compiles the TU
# in "no exceptions" mode, try/catch becomes a no-op and a thrown
# std::exception escapes as an unrecoverable wasm trap. The AOSP libs allocate
# (bad_alloc) and apkllm's container layer catches around libziparchive's
# extraction loop, so the flag goes on the static libs too — one global switch.
# It MUST precede the first add_library(): CMake snapshots the directory's
# COMPILE_OPTIONS into a target when the target is created (review finding
# ADV-4 — declared after ziparchive_static, every AOSP TU built without it).
add_compile_options(-fexceptions)
add_link_options(-fexceptions)

add_library(ziparchive_static STATIC
    ${LIBZIPARCHIVE_SRCS} ${LIBUTILS_BINDER_SRCS} ${LIBUTILS_SRCS}
    ${LIBBASE_SRCS} ${LIBLOG_SRCS} ${LIBCUTILS_SRCS}
    ${LIBINCFS_SRCS} ${FMT_SRCS}
)
target_include_directories(ziparchive_static PUBLIC ${AOSP_INCLUDES})
target_compile_definitions(ziparchive_static PUBLIC ZLIB_CONST)
target_compile_definitions(ziparchive_static PRIVATE
    LIBLOG_LOG_TAG=1006 SNET_EVENT_LOG_TAG=1397638484 ANDROID_DEBUGGABLE=0)
# Emscripten's clang is already libc++ (no -stdlib / -static-libstdc++ here).
# Silence the AOSP warning set — we are not upstream.
target_compile_options(ziparchive_static PUBLIC -w "SHELL:-s USE_ZLIB=1")
target_link_options(ziparchive_static PUBLIC "SHELL:-s USE_ZLIB=1")

# ── libavb SHA-256 — AOSP's portable C implementation, as-is (apkllm #58: the signer
#    certificates' digest without BoringSSL). Same two files and defines as APKLLM_ROOT.
set(AVB "${EXT}/avb/libavb")
if(NOT EXISTS "${AVB}/crypto/sha256_impl.c")
    message(FATAL_ERROR "libavb not found at ${AVB}. Check AOSP_ROOT.")
endif()
add_library(avb_sha256_static STATIC ${AVB}/crypto/sha256_impl.c ${AVB}/avb_sysdeps_posix.c)
# avb_sha.h picks its implementation header by include path: crypto/ = the portable C one.
target_include_directories(avb_sha256_static PUBLIC ${AVB} ${AVB}/crypto)
target_compile_definitions(avb_sha256_static PRIVATE AVB_COMPILATION)
target_compile_options(avb_sha256_static PRIVATE -w)

# ── apkllm native core — container install-gate + structural signing-block
#    reader + tamper scan + signer certificates as present (certs.cpp, #58). Same
#    sources as APKLLM_ROOT/CMakeLists.txt's apk_native_static MINUS the crypto
#    dependency (apksig.cpp is the structural EOCD/Signing-Block locator and needs no
#    BoringSSL; certs.cpp hashes with libavb).
add_library(apk_native_static STATIC
    ${APKLLM_ROOT}/native/container/container.cpp
    ${APKLLM_ROOT}/native/apksig/apksig.cpp
    ${APKLLM_ROOT}/native/apksig/tamper.cpp
    ${APKLLM_ROOT}/native/apksig/certs.cpp
)
target_include_directories(apk_native_static PUBLIC
    ${APKLLM_ROOT}/native/container ${APKLLM_ROOT}/native/apksig)
target_link_libraries(apk_native_static PUBLIC ziparchive_static avb_sha256_static)

# ── Embind binding (this file).
add_executable(apkllm wasm_module.cpp)
target_link_libraries(apkllm PRIVATE apk_native_static)
target_compile_options(apkllm PRIVATE -O3)
# Single-threaded (-pthread stays OFF), modularised, growable memory, MEMFS
# so libziparchive's open()/mmap() of the uploaded APK work in the browser.
target_link_options(apkllm PRIVATE
    -lembind
    -O3
    "SHELL:-s MODULARIZE=1"
    "SHELL:-s EXPORT_NAME=createApkllm"
    "SHELL:-s EXPORTED_RUNTIME_METHODS=['FS','getExceptionMessage']"
    "SHELL:-s FORCE_FILESYSTEM=1"
    "SHELL:-s ALLOW_MEMORY_GROWTH=1"
    "SHELL:-s STACK_SIZE=16MB"
)

# Output .js next to .wasm (Emscripten default). No -sENVIRONMENT restriction
# so the build also runs under node for the offline smoke test.
set_target_properties(apkllm PROPERTIES SUFFIX ".js")
