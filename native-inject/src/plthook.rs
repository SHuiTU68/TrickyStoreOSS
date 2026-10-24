//! PLT hook installation on top of `lsplt-rs`.
//!
//! The C++ payload used `external/PLTI` for the same job. This module keeps the *policy*
//! (which mapped object to hook, which symbol, what to do when the library is missing) and
//! delegates the mechanism to `lsplt-rs`. Two behaviours of lsplt are worth spelling out
//! because they differ from PLTI and they shape the caller:
//!
//! * A hook is only live after [`commit`]. Registering alone changes nothing, which is why
//!   `entry` registers every symbol first and commits once: a half-installed interception
//!   layer sees some transactions and not others.
//! * `register_hook` takes the `(dev, inode)` pair of the *mapped object*, not a dlopen handle.
//!   The inode is what makes this work inside keystore, where the same `libbinder_ndk.so` may
//!   be mapped from the APEX or from `/system/lib64` depending on the release. We therefore
//!   identify the object by scanning our own maps and matching the trailing path component.
//!
//! The `#[cfg(not(target_os = "android"))]` half exists so the path matching and the call
//! ordering stay unit-testable on a host, where lsplt has nothing to hook.

/// One `(object, symbol)` pair to hook.
///
/// `libraries` is a list of sonames tried in order. Android canary merges `libbinder` and
/// `libutils` into `libcore_bundle.so`, and the ndk backend means the function we want may be
/// in `libbinder_ndk.so` while the parcellable helpers live in `libbinder.so`; both spellings
/// have to be tried rather than guessed.
#[derive(Debug, Clone, Copy)]
pub struct HookSpec {
    /// Candidate sonames, e.g. `&["libbinder_ndk.so", "libbinder.so"]`.
    pub libraries: &'static [&'static str],
    /// The PLT symbol to redirect, e.g. `"AIBinder_transact"`.
    pub symbol: &'static str,
}

/// True when the mapped path names the library we are looking for.
///
/// Matching is on the trailing component with a separator check, so
/// `/apex/com.android.binder/lib64/libbinder_ndk.so` matches `libbinder_ndk.so`, while
/// `libbinder_ndk.so.bak` or `libbinder_ndk.so.debug` do not. A plain `ends_with` would
/// accept both of those, and `libbinder_ndk.so.debug` is a real symbol file that ships on
/// userdebug builds.
pub fn path_matches_soname(pathname: &str, soname: &str) -> bool {
    match pathname.rfind('/') {
        // `pathname[..]` is an unsized `str`, so the right-hand side has to be dereferenced
        // before it can be compared to another `&str`.
        Some(index) => pathname[index + 1..] == *soname,
        None => pathname == soname,
    }
}

/// True when `pathname` names any of `libraries`.
pub fn path_matches_any(pathname: &str, libraries: &[&str]) -> bool {
    libraries
        .iter()
        .any(|soname| path_matches_soname(pathname, soname))
}

#[cfg(target_os = "android")]
mod platform {
    use super::HookSpec;
    use std::ffi::c_void;
    use std::io;

    /// Installs `symbol` in the first mapped object named by `spec.libraries`.
    ///
    /// Returns the trampoline the caller must use to reach the original function. `lsplt`
    /// fills the backup pointer during `commit`, so a `null` return means the registration
    /// succeeded but the symbol was not found in that object's PLT -- the caller has to treat
    /// that as a failure, because forwarding through a null pointer is an instant SIGSEGV in
    /// the process that owns the keystore.
    pub fn install(spec: &HookSpec, callback: *mut c_void) -> io::Result<*mut c_void> {
        let maps = lsplt_rs::MapInfo::scan_self();
        let mapped = maps
            .iter()
            .find(|entry| {
                entry
                    .pathname
                    .as_deref()
                    .is_some_and(|pathname| super::path_matches_any(pathname, spec.libraries))
            })
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("none of {:?} is mapped into this process", spec.libraries),
                )
            })?;
        let mut backup: *mut c_void = std::ptr::null_mut();
        lsplt_rs::register_hook(
            mapped.dev,
            mapped.inode,
            spec.symbol,
            callback,
            Some(&mut backup),
        )?;
        Ok(backup)
    }

    /// Makes every [`install`]ed hook live.
    pub fn commit() -> io::Result<()> {
        lsplt_rs::commit_hook()
    }
}

#[cfg(not(target_os = "android"))]
mod platform {
    use super::HookSpec;
    use std::ffi::c_void;
    use std::io;
    use std::sync::Mutex;

    /// Records what a host build would have hooked, so the call sequence is testable.
    ///
    /// The pointer is deliberately a non-null, non-dereferenceable sentinel built without a
    /// provenance-carrying cast: code that verifies "a trampoline came back" keeps its shape on
    /// the host, and a test can assert that the caller refused to proceed with a null one by
    /// asking [`registrations`] what happened.
    static REGISTRATIONS: Mutex<Vec<(Vec<&'static str>, &'static str)>> = Mutex::new(Vec::new());

    pub fn install(spec: &HookSpec, _callback: *mut c_void) -> io::Result<*mut c_void> {
        let mut guard = REGISTRATIONS
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        guard.push((spec.libraries.to_vec(), spec.symbol));
        Ok(std::ptr::without_provenance_mut(1))
    }

    pub fn commit() -> io::Result<()> {
        Ok(())
    }

    /// The `(libraries, symbol)` pairs registered so far, in order.
    ///
    /// Test-only in practice: on a device the equivalent observation is "did the transaction
    /// arrive", which the reply rewrite answers. Keeping the accessor unconditionally would be
    /// dead code in the shipped build, so it is compiled out there.
    #[cfg(test)]
    pub fn registrations() -> Vec<(Vec<&'static str>, &'static str)> {
        REGISTRATIONS
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }

    /// Clears the recorded registrations. Tests share the process, so each one starts here.
    #[cfg(test)]
    pub fn clear() {
        REGISTRATIONS
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clear();
    }
}

pub use platform::{commit, install};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_last_component_decides_matching() {
        assert!(path_matches_soname(
            "/apex/com.android.binder/lib64/libbinder_ndk.so",
            "libbinder_ndk.so"
        ));
        assert!(path_matches_soname("libbinder_ndk.so", "libbinder_ndk.so"));
        // A symbol file is not the library, and a backup copy is not the live object.
        assert!(!path_matches_soname(
            "/system/lib64/libbinder_ndk.so.debug",
            "libbinder_ndk.so"
        ));
        assert!(!path_matches_soname(
            "/data/local/tmp/libbinder_ndk.so.bak",
            "libbinder_ndk.so"
        ));
        // A prefix of the trailing component must not match either.
        assert!(!path_matches_soname(
            "/system/lib64/xlibbinder_ndk.so",
            "libbinder_ndk.so"
        ));
    }

    #[test]
    fn any_of_the_candidates_matches() {
        let candidates: &[&str] = &["libbinder_ndk.so", "libbinder.so"];
        assert!(path_matches_any("/system/lib64/libbinder.so", candidates));
        assert!(!path_matches_any("/system/lib64/libutils.so", candidates));
        // The canary bundle needs an explicit entry; silence here is what makes the caller add it.
        assert!(!path_matches_any(
            "/system/lib64/libcore_bundle.so",
            candidates
        ));
    }

    /// The host half has one job: answer "installed" in the same shape a device does, so a caller
    /// that checks for a null trampoline behaves identically under `cargo test`.
    #[test]
    fn a_host_install_records_the_request_and_yields_a_trampoline() {
        platform::clear();
        let spec = HookSpec {
            libraries: &["libbinder_ndk.so", "libbinder.so"],
            symbol: "AIBinder_transact",
        };
        let trampoline = install(&spec, std::ptr::null_mut()).expect("a host install cannot fail");
        assert!(
            !trampoline.is_null(),
            "null is what the caller rejects as a failure"
        );
        assert_eq!(
            platform::registrations(),
            vec![(
                vec!["libbinder_ndk.so", "libbinder.so"],
                "AIBinder_transact"
            )]
        );
        commit().expect("committing on a host has nothing to do and must not fail");
    }
}
