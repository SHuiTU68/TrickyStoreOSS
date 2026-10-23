//! The C surface consumed by the thin C++ wrappers.
//!
//! Every function here is `extern "C"`, takes only scalar/pointer arguments and never
//! unwinds: the crate is built with `panic = "abort"` because it runs inside
//! `system_server`'s process, where an unwind across the FFI boundary is undefined
//! behaviour and a silent crash is more acceptable than corrupting the caller's stack.
//!
//! The C++ declarations for this file live in `app/src/main/cpp/native_rust.h`.

use core::ffi::{c_char, c_int};

use crate::maps;
use crate::remote;
use crate::selinux;
use crate::status;
use crate::sys;

/// One `maps` line, laid out to be `memcpy`-friendly from C.
///
/// `path` points into the owning [`TsMapList`] and is NUL-terminated so C++ can build a
/// `std::string` from it directly; `path_len` is provided for callers that want a
/// length-checked slice instead.
#[repr(C)]
pub struct TsMapEntry {
    pub start: usize,
    pub end: usize,
    /// `PROT_READ | PROT_WRITE | PROT_EXEC`, matching the `sys/mman.h` bits.
    pub perms: u8,
    /// 1 when the mapping is private (`p` in the fourth permission column).
    pub is_private: u8,
    pub offset: usize,
    pub dev: u64,
    pub inode: u64,
    pub path: *const c_char,
    pub path_len: usize,
}

/// An owned array of [`TsMapEntry`] plus the backing storage for their paths.
///
/// The struct is opaque on the C side; it is only ever touched through
/// [`ts_maps_len`], [`ts_maps_entry`] and [`ts_maps_free`].
pub struct TsMapList {
    entries: Vec<TsMapEntry>,
    /// All paths, each NUL-terminated and packed back to back.
    ///
    /// Built once with an exact capacity and never mutated afterwards, so the pointers
    /// recorded in `entries` stay valid for the lifetime of the list. Never read directly,
    /// hence the `allow`: the field exists purely to own the storage the entry pointers
    /// point into.
    #[allow(dead_code)]
    paths: Vec<u8>,
}

impl TsMapList {
    fn build(parsed: Vec<maps::MapEntry>) -> Self {
        let total: usize = parsed.iter().map(|entry| entry.path.len() + 1).sum();
        let mut paths = Vec::with_capacity(total);
        let mut offsets = Vec::with_capacity(parsed.len());
        for entry in &parsed {
            offsets.push(paths.len());
            paths.extend_from_slice(&entry.path);
            paths.push(0);
        }

        let base = paths.as_ptr();
        let entries = parsed
            .iter()
            .zip(&offsets)
            .map(|(entry, offset)| TsMapEntry {
                start: entry.start,
                end: entry.end,
                perms: entry.perms,
                is_private: u8::from(entry.is_private),
                offset: entry.offset,
                dev: entry.dev,
                inode: entry.inode,
                // SAFETY: `offset` was recorded while building `paths` and every path was
                // followed by a NUL, so `offset + path.len()` is in bounds and the byte at
                // that index is the terminator.
                path: unsafe { base.add(*offset) }.cast(),
                path_len: entry.path.len(),
            })
            .collect();

        Self { entries, paths }
    }
}

/// Parses `/proc/<pid>/maps`, returning an owned list or null if it cannot be read.
///
/// A null `pid` means the calling process, matching `MapInfo::Scan()`'s default.
///
/// # Safety
///
/// `pid` must be null or a valid NUL-terminated C string. The returned pointer must be
/// released with [`ts_maps_free`].
#[no_mangle]
pub unsafe extern "C" fn ts_maps_scan(pid: *const c_char) -> *mut TsMapList {
    let pid = if pid.is_null() {
        "self".to_string()
    } else {
        // SAFETY: the caller guarantees `pid` is a NUL-terminated string.
        match unsafe { core::ffi::CStr::from_ptr(pid) }.to_str() {
            Ok(text) => text.to_string(),
            // Non-UTF-8 pids cannot name a real process; behave like a read failure.
            Err(_) => return core::ptr::null_mut(),
        }
    };

    let mut path = String::with_capacity(16 + pid.len());
    path.push_str("/proc/");
    path.push_str(&pid);
    path.push_str("/maps");

    let Ok(buffer) = std::fs::read(&path) else {
        return core::ptr::null_mut();
    };

    Box::into_raw(Box::new(TsMapList::build(maps::parse(&buffer))))
}

/// Number of entries in `list`, or 0 for a null list.
///
/// # Safety
///
/// `list` must be null or a pointer returned by [`ts_maps_scan`] that has not been freed.
#[no_mangle]
pub unsafe extern "C" fn ts_maps_len(list: *const TsMapList) -> usize {
    if list.is_null() {
        return 0;
    }
    // SAFETY: the caller keeps `list` alive for the duration of the call.
    unsafe { &*list }.entries.len()
}

/// Borrowed pointer to entry `index`, or null when out of range.
///
/// # Safety
///
/// Same as [`ts_maps_len`]. The pointer is invalidated by [`ts_maps_free`].
#[no_mangle]
pub unsafe extern "C" fn ts_maps_entry(list: *const TsMapList, index: usize) -> *const TsMapEntry {
    if list.is_null() {
        return core::ptr::null();
    }
    // SAFETY: the caller keeps `list` alive for the duration of the call; `get` bounds-checks.
    match unsafe { &*list }.entries.get(index) {
        Some(entry) => entry,
        None => core::ptr::null(),
    }
}

/// Releases a list returned by [`ts_maps_scan`]; null is a no-op.
///
/// # Safety
///
/// `list` must be null or a pointer from [`ts_maps_scan`], and must not be used afterwards.
#[no_mangle]
pub unsafe extern "C" fn ts_maps_free(list: *mut TsMapList) {
    if list.is_null() {
        return;
    }
    // SAFETY: ownership is transferred back exactly once, per the contract above.
    drop(unsafe { Box::from_raw(list) });
}

/// `TS_MODULE_*` selector: the mapping at file offset zero.
///
/// Only the tests spell this selector out; the exported function treats every value other than
/// [`TS_MODULE_NON_EXEC`] as the base, so the constant would otherwise be dead in a normal build.
#[cfg(test)]
const TS_MODULE_BASE: c_int = 0;
/// `TS_MODULE_*` selector: a mapping without `PROT_EXEC`.
const TS_MODULE_NON_EXEC: c_int = 1;
/// Start address of the first module mapping selected by `mode`, or 0 when nothing matches.
///
/// A mapping never starts at address zero, so 0 doubles as the "not found" answer without
/// needing an out-parameter. `mode` is a `TS_MODULE_*` constant; any other value falls back to
/// `TS_MODULE_BASE`, the selector most call sites want.
///
/// # Safety
///
/// `list` must be null or a live pointer from [`ts_maps_scan`]. `suffix` must be valid for
/// `suffix_len` bytes; unlike the path fields it does not need a terminator.
#[no_mangle]
pub unsafe extern "C" fn ts_maps_find_module(
    list: *const TsMapList,
    suffix: *const c_char,
    suffix_len: usize,
    mode: c_int,
) -> usize {
    if list.is_null() || suffix.is_null() {
        return 0;
    }
    let mode = if mode == TS_MODULE_NON_EXEC {
        maps::ModuleMatch::NonExecutable
    } else {
        maps::ModuleMatch::Base
    };
    // SAFETY: the caller guarantees `suffix_len` readable bytes at `suffix`.
    let suffix = unsafe { core::slice::from_raw_parts(suffix.cast::<u8>(), suffix_len) };
    // SAFETY: the caller keeps `list` alive for the duration of the call.
    let list = unsafe { &*list };
    for entry in &list.entries {
        // SAFETY: the list owns NUL-terminated paths and `path_len` bounds the slice inside
        // that storage.
        let path = unsafe { core::slice::from_raw_parts(entry.path.cast::<u8>(), entry.path_len) };
        if maps::matches_module(path, entry.offset, entry.perms, suffix, mode) {
            return entry.start;
        }
    }
    0
}
/// Translates a symbol address resolved in our own process into the tracee's address space.
///
/// Both processes map the same file, so the symbol keeps its distance from the module base.
/// Both steps wrap, matching the `ptrdiff_t` arithmetic this replaces when `symbol_addr` happens
/// to sit below `local_base` (an ordering the C++ code tolerated by accident).
#[no_mangle]
pub extern "C" fn ts_translate_remote_symbol(
    local_base: usize,
    remote_base: usize,
    symbol_addr: usize,
) -> usize {
    remote_base.wrapping_add(symbol_addr.wrapping_sub(local_base))
}

/// Reserves `bytes` bytes on the tracee stack and returns the 16-byte-aligned pointer.
///
/// Replaces the `sp - bytes` then `& ~0xf` pair in `align_stack`. The payload helpers keep their
/// own subtraction so their log messages still report the raw payload size.
#[no_mangle]
pub extern "C" fn ts_reserve_stack(sp: usize, bytes: usize) -> usize {
    remote::reserve_stack(sp, bytes)
}

/// Copies `text` into a caller buffer with `snprintf` semantics, returning the full length.
///
/// The return value is the number of bytes the text needs *excluding* the terminator, so a
/// result greater than or equal to `capacity` means the output was truncated.
///
/// # Safety
///
/// `out` must be null or point to at least `capacity` writable bytes.
unsafe fn copy_out(text: &[u8], out: *mut c_char, capacity: usize) -> usize {
    if !out.is_null() && capacity > 0 {
        let copied = text.len().min(capacity - 1);
        // SAFETY: the caller guarantees `capacity` writable bytes at `out`, and
        // `copied + 1 <= capacity` because of the `min` above.
        unsafe {
            core::ptr::copy_nonoverlapping(text.as_ptr(), out.cast::<u8>(), copied);
            *out.add(copied) = 0;
        }
    }
    text.len()
}

/// Renders a `waitpid` status into `out`, returning the length the text needs.
///
/// # Safety
///
/// `out` must be null or point to at least `capacity` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn ts_describe_status(
    status: c_int,
    out: *mut c_char,
    capacity: usize,
) -> usize {
    let text = status::describe(status);
    // SAFETY: forwarded from the caller, who owns `capacity` bytes at `out`.
    unsafe { copy_out(text.as_bytes(), out, capacity) }
}

/// Writes `length` random marker characters into `out`, returning the number written.
///
/// Returns 0 when the entropy source cannot be read, which the C++ caller turns into an
/// empty `std::string`.
///
/// # Safety
///
/// `out` must be null or point to at least `capacity` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn ts_generate_magic(length: usize, out: *mut c_char, capacity: usize) -> usize {
    let Some(magic) = crate::magic::generate(length) else {
        return 0;
    };
    // SAFETY: forwarded from the caller, who owns `capacity` bytes at `out`.
    unsafe { copy_out(&magic, out, capacity) }
}

/// `setfilecon(3)`: labels `path` with `context`, returning 0 or -1 with `errno` set.
///
/// # Safety
///
/// `path` and `context` must be valid NUL-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn ts_setfilecon(path: *const c_char, context: *const c_char) -> c_int {
    if path.is_null() || context.is_null() {
        // SAFETY: `errno` is thread-local and always writable.
        unsafe { *sys::errno_location() = 22 }; // EINVAL
        return -1;
    }
    // SAFETY: both pointers are non-null and NUL-terminated per the contract above.
    let (path, context) = unsafe {
        (
            core::ffi::CStr::from_ptr(path),
            core::ffi::CStr::from_ptr(context),
        )
    };
    match selinux::set_file_context(path, context) {
        Ok(()) => 0,
        Err(error) => {
            // SAFETY: `errno` is thread-local and always writable.
            unsafe { *sys::errno_location() = error };
            -1
        }
    }
}

/// Sets the `sockcreate` context of the calling thread, returning 0 or -1 with `errno` set.
///
/// # Safety
///
/// `context` must be a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn ts_set_sockcreate_con(context: *const c_char) -> c_int {
    if context.is_null() {
        // SAFETY: `errno` is thread-local and always writable.
        unsafe { *sys::errno_location() = 22 }; // EINVAL
        return -1;
    }
    // SAFETY: the pointer is non-null and NUL-terminated per the contract above.
    let context = unsafe { core::ffi::CStr::from_ptr(context) };
    match selinux::set_sockcreate_context(context) {
        Ok(()) => 0,
        Err(error) => {
            // SAFETY: `errno` is thread-local and always writable.
            unsafe { *sys::errno_location() = error };
            -1
        }
    }
}

/// The `PTRACE_EVENT_*` name carried by a stopped status, as a static C string.
///
/// Mirrors [`status::ptrace_event`]; the two are kept in sync by a unit test below.
///
/// # Safety
///
/// Always safe to call; the returned pointer is `'static` and never freed.
#[no_mangle]
pub unsafe extern "C" fn ts_ptrace_event(status: c_int) -> *const c_char {
    const NAMES: [&[u8]; 9] = [
        b"(no event)\0",
        b"PTRACE_EVENT_FORK\0",
        b"PTRACE_EVENT_VFORK\0",
        b"PTRACE_EVENT_CLONE\0",
        b"PTRACE_EVENT_EXEC\0",
        b"PTRACE_EVENT_VFORK_DONE\0",
        b"PTRACE_EVENT_EXIT\0",
        b"PTRACE_EVENT_SECCOMP\0",
        b"PTRACE_EVENT_STOP\0",
    ];
    let event = status >> 16;
    let index = match event {
        1..=7 => event as usize,
        128 => 8,
        _ => 0,
    };
    NAMES[index].as_ptr().cast()
}

/// Classifies a stop seen while a remote call is in flight.
///
/// Returns `TS_CALL_COMPLETED` (0) when the tracee faulted exactly at the planted return
/// address, `TS_CALL_CRASHED` (1) when it faulted elsewhere, `TS_CALL_SUPPRESS` (2) for a
/// benign `SIGCHLD` that should be swallowed, and `TS_CALL_UNEXPECTED` (3) otherwise. The
/// raw `ptrace`/`waitpid` calls stay in C++.
#[no_mangle]
pub extern "C" fn ts_classify_stop(stop_signal: c_int, reg_ip: u64, expected_return_addr: u64) -> c_int {
    remote::classify_stop(stop_signal, reg_ip, expected_return_addr).code()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The static table above must agree with the `&'static str` version it mirrors.
    #[test]
    fn ptrace_event_names_match_status_module() {
        for event in [0, 1, 2, 3, 4, 5, 6, 7, 128, 99] {
            let status = event << 16;
            // SAFETY: the function only reads a static table and never dereferences its
            // input beyond the shift.
            let from_ffi = unsafe { core::ffi::CStr::from_ptr(ts_ptrace_event(status)) };
            assert_eq!(from_ffi.to_str().unwrap(), status::ptrace_event(status));
        }
    }

    #[test]
    fn describe_status_writes_and_reports_needed_length() {
        let mut buffer = [0u8; 128];
        // SAFETY: `buffer` provides the capacity that is passed alongside it.
        let written = unsafe { ts_describe_status(3, buffer.as_mut_ptr().cast(), buffer.len()) };
        // SAFETY: the previous call NUL-terminated the buffer.
        let text = unsafe { core::ffi::CStr::from_ptr(buffer.as_ptr().cast()) };
        assert_eq!(text.to_str().unwrap(), status::describe(3));
        assert_eq!(written, status::describe(3).len());
    }

    #[test]
    fn describe_status_truncates_without_overrunning() {
        let mut buffer = [0x7fu8; 8];
        // SAFETY: `buffer` provides the capacity that is passed alongside it.
        let needed = unsafe { ts_describe_status(3, buffer.as_mut_ptr().cast(), buffer.len()) };
        let expected = status::describe(3);
        assert!(needed > buffer.len(), "the sample status must not fit in 8 bytes");
        assert_eq!(needed, expected.len());
        assert_eq!(&buffer[..7], &expected.as_bytes()[..7], "the prefix is copied");
        assert_eq!(buffer[7], 0, "the terminator must fit inside the buffer");
    }

    #[test]
    fn describe_status_accepts_a_zero_capacity_buffer() {
        // SAFETY: a null pointer with zero capacity must be tolerated; the return value still
        // reports the space that would have been needed.
        let needed = unsafe { ts_describe_status(0, core::ptr::null_mut(), 0) };
        assert_eq!(needed, status::describe(0).len());
    }

    #[test]
    fn maps_scan_sees_our_own_mappings() {
        // SAFETY: null asks for the current process, which always has a maps file.
        let list = unsafe { ts_maps_scan(core::ptr::null()) };
        assert!(!list.is_null());
        // SAFETY: `list` is alive until `ts_maps_free` below.
        let count = unsafe { ts_maps_len(list) };
        assert!(count > 0);

        let mut found_executable = false;
        for index in 0..count {
            // SAFETY: `index` is below the length just queried.
            let entry = unsafe { ts_maps_entry(list, index) };
            assert!(!entry.is_null());
            // SAFETY: the entry lives as long as the list, and `path`/`path_len` describe a
            // slice inside the list's path buffer.
            let entry = unsafe { &*entry };
            let path = unsafe { core::slice::from_raw_parts(entry.path.cast::<u8>(), entry.path_len) };
            if path.starts_with(b"/") && entry.perms & maps::PROT_EXEC != 0 {
                found_executable = true;
            }
            // Every path must be NUL-terminated, since C++ reads it as a C string.
            // SAFETY: the byte at `path_len` is the terminator by construction.
            assert_eq!(unsafe { *entry.path.add(entry.path_len) }, 0);
        }
        assert!(found_executable, "expected at least one executable file mapping");

        // SAFETY: ownership goes back exactly once.
        unsafe { ts_maps_free(list) };
    }

    #[test]
    fn maps_scan_of_a_missing_process_returns_null() {
        let pid = c"/definitely/not/a/pid";
        // SAFETY: `pid` is a valid C string.
        let list = unsafe { ts_maps_scan(pid.as_ptr()) };
        assert!(list.is_null());
    }

    #[test]
    fn magic_is_written_and_terminated() {
        let mut buffer = [0u8; 32];
        // SAFETY: `buffer` provides the capacity that is passed alongside it.
        let written = unsafe { ts_generate_magic(16, buffer.as_mut_ptr().cast(), buffer.len()) };
        assert_eq!(written, 16);
        assert_eq!(buffer[16], 0);
        assert!(buffer[..16].iter().all(|byte| crate::magic::ALPHABET.contains(byte)));
    }

    #[test]
    fn maps_find_module_selects_by_mode() {
        // Built straight from a document, the way `ts_maps_scan` builds it after reading the
        // file, so the lookup can be exercised without depending on this process's own maps.
        let document = b"\
7f00-7f10 r--p 00000000 fd:01 42 /apex/libc.so
7f10-7f20 r-xp 00001000 fd:01 42 /apex/libc.so
";
        let list = Box::into_raw(Box::new(TsMapList::build(maps::parse(document))));
        let suffix = b"libc.so";
        // SAFETY: `list` is a live, owned list and `suffix` is a readable slice.
        let base = unsafe { ts_maps_find_module(list, suffix.as_ptr().cast(), suffix.len(), TS_MODULE_BASE) };
        assert_eq!(base, 0x7f00, "the offset-zero mapping is the base");
        // SAFETY: same live list and suffix, different selector.
        let region = unsafe { ts_maps_find_module(list, suffix.as_ptr().cast(), suffix.len(), TS_MODULE_NON_EXEC) };
        assert_eq!(region, 0x7f00, "the r--p mapping is the only one without PROT_EXEC");
        let missing = b"libm.so";
        // SAFETY: same live list; the suffix simply matches nothing.
        let not_found = unsafe { ts_maps_find_module(list, missing.as_ptr().cast(), missing.len(), TS_MODULE_BASE) };
        assert_eq!(not_found, 0);
        // SAFETY: ownership goes back exactly once.
        unsafe { ts_maps_free(list) };
    }

    #[test]
    fn maps_find_module_tolerates_null() {
        // SAFETY: both pointers are null, which the function checks before reading anything.
        assert_eq!(unsafe { ts_maps_find_module(core::ptr::null(), core::ptr::null(), 0, TS_MODULE_BASE) }, 0);
    }

    #[test]
    fn translate_remote_symbol_keeps_the_offset() {
        assert_eq!(ts_translate_remote_symbol(0x1000, 0x8000, 0x1234), 0x8234);
        // A symbol below the base wraps exactly like the `ptrdiff_t` subtraction it replaces.
        assert_eq!(ts_translate_remote_symbol(0x2000, 0x8000, 0x1000), 0x7000);
        // Zero bases are a no-op, which is what an unresolved module would produce.
        assert_eq!(ts_translate_remote_symbol(0, 0, 0x5555), 0x5555);
    }

    #[test]
    fn reserve_stack_matches_the_cpp_alignment() {
        assert_eq!(ts_reserve_stack(0x1000, 0), 0x1000);
        assert_eq!(ts_reserve_stack(0x1000, 8), 0xff0);
    }
    #[test]
    fn setfilecon_rejects_null() {
        // SAFETY: the function only checks for null before touching the pointers.
        assert_eq!(unsafe { ts_setfilecon(core::ptr::null(), core::ptr::null()) }, -1);
        // SAFETY: `errno` is thread-local and always readable.
        assert_eq!(unsafe { *sys::errno_location() }, 22);
    }
}
