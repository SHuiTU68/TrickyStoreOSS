# Copyright 2026 Dakkshesh <beakthoven@gmail.com>
# SPDX-License-Identifier: GPL-3.0-or-later
cmake_minimum_required(VERSION 3.28)
project(TrickyStoreOSS)

find_package(cxx REQUIRED CONFIG)
link_libraries(cxx::cxx)

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
# `c++abi` is not optional: some of the objects the archive carries are compiled by a `cc` build
# script with unwind tables, and they reference `DW.ref.__gxx_personality_v0`. The prefab `cxx`
# module only ships libc++ itself (stl: none, exceptions off), so nothing in the default link line
# defines that symbol and ld.lld fails with "undefined symbol: __gxx_personality_v0".
target_link_libraries(rustinject INTERFACE dl log m c++abi)

add_executable(libinject.so inject/main.cpp inject/utils.cpp)
target_include_directories(libinject.so PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(libinject.so PRIVATE ts_maps my_logging rustinject)

add_library(${CMAKE_PROJECT_NAME} SHARED binder_interceptor.cpp)
target_include_directories(${CMAKE_PROJECT_NAME} PUBLIC external/linux-kernel/include)
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE log dl binder utils plti my_logging)
