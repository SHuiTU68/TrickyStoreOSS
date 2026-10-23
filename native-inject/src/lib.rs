//! Native helpers for the Tricky Store injection payload.
//!
//! This crate replaces the pure-logic half of `app/src/main/cpp`: the `/proc/pid/maps`
//! parser, the `waitpid` status renderer, the magic-marker generator and the SELinux
//! label helpers. Everything that is coupled to a platform ABI on purpose stays in C++:
//!
//! * `binder_interceptor.cpp` and `stub/*.cpp` link against the AOSP `Parcel`/`IBinder`
//!   vtable layout and export symbols that must match binder's names byte for byte.
//! * `inject/main.cpp` and the ptrace half of `inject/utils.cpp` poke at
//!   `user_regs_struct`, `PTRACE_GETREGSET` and raw `process_vm_readv` layouts.
//!
//! The C++ side keeps its existing classes and signatures; `ffi` exposes a small C
//! surface that the thin C++ wrappers in `maps/maps.cpp` and `inject/utils.cpp` call
//! into, so no call site outside those two files had to change.

#![deny(clippy::undocumented_unsafe_blocks)]
#![allow(clippy::missing_safety_doc)]

pub mod ffi;
pub mod magic;
pub mod maps;
pub mod selinux;
pub mod status;
pub mod sys;

/// Length of the marker string written into the remote process.
///
/// Mirrors `ts::constants::kMagicLength` / `kMainMagicLength` on the C++ side.
pub const MAIN_MAGIC_LENGTH: usize = 16;
