//! SELinux label helpers.
//!
//! This replaces `setfilecon()` and `set_sockcreate_con()`. Both used to format a `/proc` path into
//! a fixed 256-byte stack buffer with `snprintf` and to compare a `write()` result against
//! `strlen() + 1`; the versions below build the path as a `String` and report the `errno` of the
//! failing call so the caller can log it with `PLOGE`.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;

use crate::sys;

/// `O_CLOEXEC`, so the descriptor never leaks into an `exec` of the target process.
const O_CLOEXEC: i32 = 0o2000000;

/// The extended attribute SELinux stores a file label in.
const SELINUX_XATTR: &[u8] = b"security.selinux\0";

/// The `sockcreate` knob, which only accepts a write from the thread that owns it.
const THREAD_SOCKCREATE: &str = "/proc/thread-self/attr/sockcreate";

/// Labels `path` with `context`, returning the `errno` of the failing syscall on error.
pub fn set_file_context(path: &std::ffi::CStr, context: &std::ffi::CStr) -> Result<(), i32> {
    // SAFETY: both pointers come from `CStr`, so they are NUL-terminated and outlive the call; the
    // binary slice is exactly `SELINUX_XATTR`'s bytes, and the attribute value is passed with the
    // length `setxattr` expects (the NUL included, which is what `setfilecon` wrote too).
    let result = unsafe {
        sys::setxattr(
            path.as_ptr(),
            SELINUX_XATTR.as_ptr().cast(),
            context.as_ptr().cast(),
            context.to_bytes_with_nul().len(),
            0,
        )
    };
    if result == 0 {
        return Ok(());
    }
    Err(sys::errno())
}

/// Sets the `sockcreate` context of the calling thread, returning the `errno` of the failure.
///
/// `/proc/thread-self` is tried first; older kernels do not have it, so the thread id path is the
/// fallback, exactly as in the C++ version.
pub fn set_sockcreate_context(context: &std::ffi::CStr) -> Result<(), i32> {
    let bytes = context.to_bytes_with_nul();
    let first_error = match write_knob(THREAD_SOCKCREATE, bytes) {
        Ok(()) => return Ok(()),
        Err(error) => error,
    };
    match write_knob(&sockcreate_path(sys::gettid()), bytes) {
        Ok(()) => Ok(()),
        // The thread-self failure is the more informative one: it is the path the kernel is
        // expected to provide.
        Err(_) => Err(first_error),
    }
}

/// The `/proc/<tid>/attr/sockcreate` path used when `/proc/thread-self` is unavailable.
pub fn sockcreate_path(tid: i64) -> String {
    format!("/proc/{tid}/attr/sockcreate")
}

/// Writes `data` to the knob at `path`, treating a short write as a failure.
fn write_knob(path: &str, data: &[u8]) -> Result<(), i32> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(O_CLOEXEC)
        .open(path)
        .map_err(|error| error.raw_os_error().unwrap_or(-1))?;
    let written = file
        .write(data)
        .map_err(|error| error.raw_os_error().unwrap_or(-1))?;
    if written != data.len() {
        return Err(-1);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn builds_the_fallback_path() {
        assert_eq!(sockcreate_path(4242), "/proc/4242/attr/sockcreate");
    }

    #[test]
    fn labelling_a_missing_file_reports_an_errno() {
        let path = CString::new("/definitely/not/here").unwrap();
        let context = CString::new("u:object_r:system_file:s0").unwrap();
        let error = set_file_context(&path, &context).unwrap_err();
        assert!(error > 0, "expected a positive errno, got {error}");
    }

    #[test]
    fn writing_an_unreachable_knob_reports_an_errno() {
        let error = write_knob("/definitely/not/here", b"x\0").unwrap_err();
        assert!(error > 0, "expected a positive errno, got {error}");
    }
}
