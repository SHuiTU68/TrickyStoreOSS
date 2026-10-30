# Copyright 2026 Dakkshesh <beakthoven@gmail.com>
# SPDX-License-Identifier: GPL-3.0-or-later
cmake_minimum_required(VERSION 3.28)
project(TrickyStoreOSS)

find_package(cxx REQUIRED CONFIG)
link_libraries(cxx::cxx)

# --- Hardening ---
# Full RELRO + non-executable stack on every artifact built here. The injector and the
# interceptor are exactly the binaries an attacker would want to hijack, so their GOT must
# be resolved and mprotected read-only at load time (-z now needs API 23+; minSdk is 29)
# and no segment may ever be mapped writable+executable. `-fstack-protector-strong` is the
# NDK default already; spelling it out keeps the guarantee independent of future defaults.
add_compile_options(-fstack-protector-strong)
add_link_options(
    "-Wl,-z,relro"
    "-Wl,-z,now"
    "-Wl,-z,noexecstack"
)

add_library(my_logging STATIC logging/logging.cpp)
target_include_directories(my_logging PUBLIC logging/include)
target_link_libraries(my_logging log)

# Maps parser (used by injector)
add_library(ts_maps STATIC maps/maps.cpp)
target_include_directories(ts_maps PUBLIC maps/include)
target_include_directories(ts_maps PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# PLTI (PLT hooking library)
add_subdirectory(external/PLTI)

# libutils stub
add_library(utils SHARED stub/stub_utils.cpp)
target_include_directories(utils PUBLIC external/AOSP/include)

# libbinder stub
add_library(binder SHARED stub/stub_binder.cpp)
target_include_directories(binder PUBLIC external/AOSP/include)
target_link_libraries(binder PRIVATE utils)

# Rust payload helpers (native-inject)
# The pure-logic half of the injector -- maps parsing, wait-status and PTRACE_EVENT rendering,
# magic-string generation and the SELinux knobs -- lives in Rust and is compiled by Gradle's
# `buildRustInject` task into a static archive. Only the thin C++ wrappers stay here; see
# native_rust.h for the ABI.
set(RUSTINJECT_LIB
    "${CMAKE_CURRENT_SOURCE_DIR}/../../../build/rust/inject/${ANDROID_ABI}/librustinject.a"
    CACHE FILEPATH "native-inject static archive linked into libinject.so")
if(NOT EXISTS "${RUSTINJECT_LIB}")
    message(
        FATAL_ERROR
            "Missing ${RUSTINJECT_LIB}. Build it with `cargo build --release --target aarch64-linux-android` from native-inject/ (Gradle's buildRustInject task does this and copies the archive here), or point -DRUSTINJECT_LIB at an existing archive."
    )
endif()
add_library(rustinject STATIC IMPORTED)
set_target_properties(rustinject PROPERTIES IMPORTED_LOCATION "${RUSTINJECT_LIB}")
# std's runtime borrows from libdl/libm; `log` comes along for the bindings that log errors.
# No extra C++ runtime is linked on purpose. The `cxx` prefab archive is a libc++ built with
# exceptions turned off and already carries the exception classes, so adding NDK `libc++abi` only
# re-defines them and ld.lld stops with "duplicate symbol: std::exception::~exception()". The one
# symbol the archive's C++ objects do need -- `__gxx_personality_v0`, referenced from the
# call-site table that `lsplt-sys`'s wrapper.cc emits -- is defined locally, with the reasoning,
# in `inject/eh_personality.cpp`.
target_link_libraries(rustinject INTERFACE dl log m)
add_executable(libinject.so inject/main.cpp inject/utils.cpp inject/eh_personality.cpp)
target_include_directories(libinject.so PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(libinject.so PRIVATE ts_maps my_logging rustinject)
# W^X for the one standalone executable: code and rodata get their own pages. The shared
# libraries keep lld's tighter single-code-segment layout — there elf_compact.py reclaims
# more bytes than separate-code would spend.
target_link_options(libinject.so PRIVATE "-Wl,-z,separate-code")

add_library(${CMAKE_PROJECT_NAME} SHARED binder_interceptor.cpp)
target_include_directories(${CMAKE_PROJECT_NAME} PUBLIC external/linux-kernel/include)
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE log dl binder utils plti my_logging)
# Export exactly one symbol: `entry`, the name the injector resolves with a remote
# `dlsym()` ("exec ./inject <pid> libTrickyStoreOSS.so entry"). Everything else defined in
# this object becomes local, so the dynamic symbol table stops carrying a map of the
# interceptor's internals to anyone who dumps the library.
target_link_options(${CMAKE_PROJECT_NAME} PRIVATE
    "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/ts_entry.map")
