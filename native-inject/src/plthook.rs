//! PLT hook installation on top of `lsplt-rs`.
//!
//! The C++ payload used `external/PLTI` for the same job. This module keeps the *policy*
//! (which mapped objects are candidates, which symbol, what to do when nothing matches) and
//! delegates the mechanism to `lsplt-rs`. Three behaviours of lsplt shape the caller, and two of
//! them each cost a debugging session:
//!
//! * `register_hook` takes the `(dev, inode)` pair of the object whose **PLT is patched**, which
//!   is the object that *calls* the symbol, not the one that defines it. Passing the definer
//!   (`libbinder_ndk.so` for `AIBinder_transact`) registers a hook that can never fire: a library
//!   resolves its own exports internally and has no relocation for them, so the PLT scan finds
//!   nothing while lsplt still reports success.
//! * That silent miss is the second trap: a symbol with no matching relocation is skipped without
//!   an error, so success can only be judged after [`commit`], by looking at which backup slots
//!   were filled.
//! * A hook is only live after [`commit`], and lsplt writes the backup pointer *during* that
//!   commit. The trampoline therefore does not exist before it, and checking earlier can only
//!   ever answer "not found". `entry` registers every candidate first and commits once: a
//!   half-installed interception layer sees some transactions and not others.
//!
//! The `#[cfg(not(target_os = "android"))]` half exists so the path matching and the call
//! ordering stay unit-testable on a host, where lsplt has nothing to hook.

/// One symbol to hook everywhere it is imported.
///
/// `exclude` lists objects whose PLT must not be patched: the libraries that *define* the symbol
/// (they have no PLT slot for it, and a PLT hook redirects call sites, not definitions), plus our
/// own payload, which must never intercept itself. Everything else that is mapped from a real
/// file is a candidate. A fixed list of "the library we want" is what made the first version
/// fail: on keystore2 the callers are `android.hardware.security.keymint-V5-ndk.so` and friends,
/// while `libbinder_ndk.so` only exports the symbol.
#[derive(Debug, Clone, Copy)]
pub struct HookSpec {
    /// Objects never hooked, matched on the trailing path component.
    pub exclude: &'static [&'static str],
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
    use std::sync::Mutex;

    use lsplt_rs::{DeviceId, Inode};

    /// One `*mut c_void` slot that lsplt writes the trampoline into during [`commit`].
    ///
    /// The slot is heap-allocated and never freed so its address stays valid for the life of the
    /// process: lsplt stores the address at registration time and writes through it later, and a
    /// reallocated `Vec` element would leave it writing into freed memory. Only the address of the
    /// box is kept, so nothing ever frees it.
    struct Slot(*mut *mut c_void);

    // SAFETY: the pointer refers to a leaked allocation that lsplt writes and `trampoline()` reads
    // under the same mutex. Rust cannot observe an alias to it.
    unsafe impl Send for Slot {}
    // SAFETY: see above; all access is serialised by `SLOTS`.
    unsafe impl Sync for Slot {}

    static SLOTS: Mutex<Vec<Slot>> = Mutex::new(Vec::new());

    /// Registers `spec.symbol` in every mapped object that is not excluded.
    ///
    /// Objects are deduplicated by `(dev, inode)`: `/proc/self/maps` lists one line per segment,
    /// and registering the same object once per segment would patch the same PLT slot repeatedly.
    ///
    /// Registration itself cannot detect a miss -- lsplt queues the request and only touches
    /// memory in [`commit`] -- so the real test is [`trampoline`] after that commit.
    pub fn install(spec: &HookSpec, callback: *mut c_void) -> io::Result<()> {
        let maps = lsplt_rs::MapInfo::scan_self();
        let mut seen: Vec<(DeviceId, Inode)> = Vec::new();
        let mut slots = SLOTS.lock().unwrap_or_else(|error| error.into_inner());
        slots.clear();
        for entry in &maps {
            let Some(pathname) = entry.pathname.as_deref() else {
                // Anonymous mappings and `[anon:...]` regions are not files.
                continue;
            };
            if !pathname.starts_with('/') {
                // `[vdso]`, `[stack]`, `[anon:dalvik-...]`: no ELF on disk to scan.
                continue;
            }
            if entry.dev == 0 || entry.inode == 0 {
                // Deleted or special files carry no identity lsplt can match against.
                continue;
            }
            if super::path_matches_any(pathname, spec.exclude) {
                continue;
            }
            if seen.contains(&(entry.dev, entry.inode)) {
                continue;
            }
            seen.push((entry.dev, entry.inode));
            let slot = Box::into_raw(Box::new(std::ptr::null_mut::<c_void>()));
            // SAFETY: `slot` came from `Box::into_raw`, so it is a valid, aligned, uniquely owned
            // `*mut c_void` for the rest of the process; lsplt writes the trampoline through it at
            // commit. The allocation is intentionally leaked, so the reference stays valid.
            let backup = unsafe { &mut *slot };
            lsplt_rs::register_hook(entry.dev, entry.inode, spec.symbol, callback, Some(backup))?;
            slots.push(Slot(slot));
        }
        if slots.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no loaded object is eligible for a PLT hook",
            ));
        }
        // Worth a line on the device: the registration count is the only evidence that the scan
        // found the callers of the symbol at all, and it costs nothing at injection time.
        crate::diag::info(&format!(
            "queued a PLT hook for {} in {} mapped object(s)",
            spec.symbol,
            slots.len()
        ));
        Ok(())
    }

    /// Makes every [`install`]ed hook live and fills the backup slots.
    pub fn commit() -> io::Result<()> {
        lsplt_rs::commit_hook()
    }

    /// The trampoline lsplt published for the first object that actually had the symbol.
    ///
    /// `None` means no loaded object had a PLT slot for the symbol, which is the only honest
    /// signal available because lsplt reports that miss as success. Every trampoline resolves to
    /// the same real function, so the first one found serves every patched call site.
    pub fn trampoline() -> Option<*mut c_void> {
        let slots = SLOTS.lock().unwrap_or_else(|error| error.into_inner());
        for slot in slots.iter() {
            // SAFETY: the slot is a leaked allocation, valid for the whole process lifetime, and
            // `commit` -- the only writer -- has already returned on this thread.
            let value = unsafe { *slot.0 };
            if !value.is_null() {
                return Some(value);
            }
        }
        None
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

    pub fn install(spec: &HookSpec, _callback: *mut c_void) -> io::Result<()> {
        let mut guard = REGISTRATIONS
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        guard.push((spec.exclude.to_vec(), spec.symbol));
        Ok(())
    }

    pub fn commit() -> io::Result<()> {
        Ok(())
    }

    pub fn trampoline() -> Option<*mut c_void> {
        Some(std::ptr::without_provenance_mut(1))
    }

    /// The `(exclude, symbol)` pairs registered so far, in order.
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

pub use platform::{commit, install, trampoline};

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
            exclude: &["libbinder_ndk.so", "libbinder.so"],
            symbol: "AIBinder_transact",
        };
        install(&spec, std::ptr::null_mut()).expect("a host install cannot fail");
        commit().expect("committing on a host has nothing to do and must not fail");
        let trampoline = trampoline().expect("the host build always has a trampoline");
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
    }
}
