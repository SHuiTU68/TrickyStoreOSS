//! The few libc entry points the crate needs, declared by hand.
//!
//! The crate deliberately has no dependencies: it is cross-compiled for Android inside the Gradle
//! build, and every dependency would be one more thing that has to be vendored offline. Declaring
//! the handful of symbols below is cheaper than carrying `libc` for them.

use core::ffi::{c_char, c_int, c_long, c_void};

pub const EINTR: i32 = 4;

extern "C" {
    pub fn setxattr(
        path: *const c_char,
        name: *const c_char,
        value: *const c_void,
        size: usize,
        flags: c_int,
    ) -> isize;
    pub fn syscall(number: c_long, ...) -> c_long;
}

// Bionic and glibc disagree on the name of the `errno` accessor: bionic exports the
// `__errno` function, glibc exports a `__errno_location` one. Both return a pointer into
// the calling thread's TLS.
#[cfg(target_os = "android")]
extern "C" {
    #[link_name = "__errno"]
    pub fn errno_location() -> *mut c_int;
}

#[cfg(not(target_os = "android"))]
extern "C" {
    #[link_name = "__errno_location"]
    pub fn errno_location() -> *mut c_int;
}

/// `SYS_gettid`, which differs per architecture on Linux.
#[cfg(target_arch = "aarch64")]
pub const SYS_GETTID: c_long = 178;
#[cfg(target_arch = "arm")]
pub const SYS_GETTID: c_long = 224;
#[cfg(target_arch = "x86_64")]
pub const SYS_GETTID: c_long = 186;
#[cfg(target_arch = "x86")]
pub const SYS_GETTID: c_long = 224;

/// The value of `errno` in the calling thread.
pub fn errno() -> i32 {
    // SAFETY: `__errno` returns a valid pointer into the thread's TLS on every Android/bionic
    // release this library supports, and the pointer is only read.
    unsafe { *errno_location() }
}

/// The id of the calling thread, which the `/proc/<tid>` fallback path needs.
pub fn gettid() -> i64 {
    // SAFETY: `SYS_gettid` takes no arguments and is available on every kernel this targets.
    unsafe { syscall(SYS_GETTID) as i64 }
}
