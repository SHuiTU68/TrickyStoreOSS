// Copyright 2026 Dakkshesh <beakthoven@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The single C++ exception symbol this image has to define, and why it is a stub.
//
// `native-inject` depends on `lsplt-sys`, whose `wrapper.cc` wraps every `MapInfo` call in
// `try { ... } catch (...) { ... }` to turn a `std::bad_alloc` out of `std::string`/`new` into an
// empty result. That file is compiled by the crate's `cc` build script with exceptions enabled, so
// its code carries a call-site table, and a call-site table needs a personality routine: the
// object holds a relocation against `__gxx_personality_v0` via `DW.ref.__gxx_personality_v0`.
// The symbol therefore has to exist at link time, even though nothing here can throw:
//
//   * everything under `inject/` is compiled with `-fno-exceptions` (see CMakeLists.txt);
//   * the `cxx` prefab module is a libc++ built with exceptions turned off -- its `abi.json` says
//     `"stl": "none"`, it ships `cxa_noexception.o` rather than the real throw/personality pair,
//     and neither `__cxa_throw` nor `__gxx_personality_v0` appears anywhere in `libcxx.a`;
//   * the Rust halves are built with `panic = "abort"`.
//
// So this routine is unreachable. It answers "no handler in this frame, keep unwinding", which is
// the truthful answer for a frame that cannot own a live landing pad, and it keeps the link honest
// without dragging a C++ runtime in.
//
// The obvious alternative -- adding NDK `libc++abi.a` to the link -- does not work: it re-defines
// the exception classes that prefab's `libcxx.a` already provides (`std::exception::~exception()`,
// `std::bad_alloc::bad_alloc()`, `vtable for std::bad_array_new_length`, ...) and ld.lld stops with
// `error: duplicate symbol`.
#include <stdint.h>
#include <unwind.h>

extern "C" _Unwind_Reason_Code
__gxx_personality_v0(int /*version*/, _Unwind_Action /*actions*/, uint64_t /*exception_class*/,
                     struct _Unwind_Exception * /*exception_object*/,
                     struct _Unwind_Context * /*context*/) {
    return _URC_CONTINUE_UNWIND;
}
