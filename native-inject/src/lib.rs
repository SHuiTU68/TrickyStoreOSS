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
pub mod bootstrap;
pub mod ffi;
pub mod intercept;
pub mod keymint;
pub mod magic;
pub mod maps;
pub mod plthook;
pub mod remote;
pub mod selinux;
pub mod status;
pub mod surgeon;
pub mod sys;

/// Length of the marker string written into the remote process.
///
/// Mirrors `ts::constants::kMagicLength` / `kMainMagicLength` on the C++ side.
pub const MAIN_MAGIC_LENGTH: usize = 16;

/// Minimal diagnostics for the injected payload.
///
/// The payload runs inside `keystore2`, which has no logger of ours and no stderr anyone reads.
/// On Android the messages go straight to logd via `liblog`; on a host they go to stderr, so a
/// test or a manual `dlopen` still shows what happened.
mod diag {
    /// Name every line carries in logcat.
    ///
    /// Only the Android sink uses it; a host prints straight to stderr, so without the gate the
    /// constant would be dead code in every `cargo test` run.
    #[cfg(target_os = "android")]
    const TAG: &str = "tricky-inject";

    /// `ANDROID_LOG_WARN`. 4 is `INFO`, 6 is `ERROR`.
    #[cfg(target_os = "android")]
    const PRIO_WARN: i32 = 5;
    /// `ANDROID_LOG_ERROR`.
    #[cfg(target_os = "android")]
    const PRIO_ERROR: i32 = 6;

    #[cfg(target_os = "android")]
    mod sys {
        use std::ffi::c_char;

        // liblog is part of the NDK sysroot; the payload never ships it, it links against the
        // platform copy the way every other Android library does.
        #[link(name = "log")]
        extern "C" {
            pub fn __android_log_write(
                priority: i32,
                tag: *const c_char,
                text: *const c_char,
            ) -> i32;
        }
    }

    /// Writes one line at the given priority.
    #[cfg(target_os = "android")]
    fn write(priority: i32, message: &str) {
        use std::ffi::CString;
        let Ok(text) = CString::new(message) else {
            // An interior NUL means the message was built from data we do not control; dropping
            // the log line is fine, panicking inside keystore2 is not.
            return;
        };
        let Ok(tag) = CString::new(TAG) else {
            return;
        };
        // SAFETY: both pointers are valid NUL-terminated strings that outlive the call, which is
        // the entire contract of `__android_log_write`.
        unsafe {
            sys::__android_log_write(priority, tag.as_ptr(), text.as_ptr());
        }
    }

    /// Something was missing or refused; the hook is still a pass-through.
    pub fn warn(message: &str) {
        #[cfg(target_os = "android")]
        write(PRIO_WARN, message);
        #[cfg(not(target_os = "android"))]
        eprintln!("[warn] {message}");
    }

    /// Interception is not installed. The caller of `entry` treats this as a failure.
    ///
    /// On a host `entry` never reaches a failure branch (there is nothing to hook), so this is
    /// unreachable here by construction rather than by omission.
    #[cfg_attr(not(target_os = "android"), allow(dead_code))]
    pub fn error(message: &str) {
        #[cfg(target_os = "android")]
        write(PRIO_ERROR, message);
        #[cfg(not(target_os = "android"))]
        eprintln!("[error] {message}");
    }

    /// The hook is live.
    pub fn info(message: &str) {
        #[cfg(target_os = "android")]
        write(PRIO_WARN - 1, message);
        #[cfg(not(target_os = "android"))]
        eprintln!("[info] {message}");
    }
}

/// File-based probe used while the interception path is being brought up.
///
/// logd is not trustworthy for this: a line written from inside `commit` either arrives very
/// late or not at all when the hook machinery touches the caller's own mappings, so the only
/// way to see how far execution got is to append to a file the target uid can write.
mod probe {
    /// Appends one line to the probe file.
    #[cfg(target_os = "android")]
    pub fn mark(message: &str) {
        use std::io::Write;
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open("/data/misc/keystore/.inject-probe.log")
        {
            let _ = writeln!(file, "{} {}", std::process::id(), message);
        }
    }
    /// Saves the first marshalled reply verbatim so the layout can be inspected offline.
    ///
    /// Written once: a second `generateKey` reply would only overwrite the sample being looked at.
    #[cfg(target_os = "android")]
    pub fn dump_reply(bytes: &[u8]) {
        let path = "/data/misc/keystore/.inject-reply.bin";
        if std::path::Path::new(path).exists() {
            return;
        }
        let _ = std::fs::write(path, bytes);
    }
    /// Saves the first spliced reply next to the original sample.
    #[cfg(target_os = "android")]
    pub fn dump_patched(bytes: &[u8]) {
        let path = "/data/misc/keystore/.inject-patched.bin";
        if std::path::Path::new(path).exists() {
            return;
        }
        let _ = std::fs::write(path, bytes);
    }
    #[cfg(not(target_os = "android"))]
    pub fn dump_patched(_bytes: &[u8]) {}
    /// The host has no probe sink: tests assert on the returned values instead.
    #[cfg(not(target_os = "android"))]
    pub fn mark(_message: &str) {}
    /// The host keeps no reply samples either.
    #[cfg(not(target_os = "android"))]
    pub fn dump_reply(_bytes: &[u8]) {}
}

/// The payload entry point, called by the injector after `dlopen`.
///
/// Signature matches the C++ implementation it replaces: a `dlopen` handle (unused -- the crate
/// links against nothing it would have to resolve at runtime) and a `bool` that means "the hook
/// is installed". Returning `false` leaves the process exactly as it was, because a registration
/// that is not committed has no effect.
///
/// Order matters: the configuration is loaded before the hook becomes live. A hook that rewrites
/// with no keybox would marshal and rebuild every `generateKey` reply for nothing, and if it did
/// so it could only ever fail closed on the reply.
#[no_mangle]
pub extern "C" fn entry(_library_handle: *mut std::ffi::c_void) -> bool {
    if bootstrap::install_default() {
        diag::info("keybox loaded; certificate surgery armed");
    } else {
        // Not an error: a device with no keybox installed simply keeps the real attestation. The
        // hook is still worth installing because the configuration cannot be added later without
        // re-injecting, and the pass-through path costs a descriptor comparison.
        diag::warn("no usable keybox.xml; replies will be forwarded untouched");
    }
    #[cfg(target_os = "android")]
    {
        diag::info("probe: entry begin");
        probe::mark("entry: begin");
        if let Err(error) = intercept::platform::install() {
            diag::error(&format!(
                "cannot install the AIBinder_transact hook: {error}"
            ));
            return false;
        }
        diag::info("probe: install returned ok");
        probe::mark("entry: install ok");
        // The commit resolves the trampoline, so it is also the first point where the hook can be
        // shown to be live: `lsplt` accepts registrations for objects that have no such PLT slot.
        diag::info("probe: committing");
        probe::mark("entry: committing");
        let commit_result = intercept::platform::commit();
        diag::info(&format!("probe: commit returned {commit_result:?}"));
        if let Err(error) = commit_result {
            diag::error(&format!(
                "cannot activate the AIBinder_transact hook: {error}"
            ));
            return false;
        }
        diag::info("AIBinder_transact is hooked; KeyMint replies on code 3 are rewritten");
        true
    }
    #[cfg(not(target_os = "android"))]
    {
        // Nothing to hook on a host. Reporting success keeps the caller's control flow identical
        // to the device, and `intercept::platform` does not exist here at all.
        diag::warn("not running on Android; no hook was installed");
        true
    }
}
