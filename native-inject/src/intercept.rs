//! The `AIBinder_transact` hook: patch mode.
//!
//! ## Why this entry point and not `ioctl`
//!
//! The C++ payload hooked `ioctl` inside `libbinder.so`, i.e. it looked at raw
//! `BINDER_WRITE_READ` buffers and re-implemented the `BinderInterceptor` proxy on top of a
//! backdoor transaction. That design needs a live helper process to hand requests to, and the
//! only thing a helper process can do with them is mint *software* keys -- which is the
//! behaviour that changes `keyBlob` ownership and eventually logs an app out.
//!
//! Patch mode does the opposite. `keystore2` asks the real KeyMint HAL for a key, the TEE
//! produces a real `keyBlob` for that real key, and the only thing that changes on the way
//! back is the certificate chain: the leaf is re-signed with the keybox key and the root of
//! trust is patched to `locked`/`Verified`. The key itself never leaves the TEE, so every
//! caller that later uses the blob sees exactly what it would have seen unpatched.
//!
//! `AIBinder_transact` is where that reply is available as a plain parcel, with a stable C ABI
//! in `libbinder_ndk.so`, so it is both the narrowest and the most portable seam we can pick.
//! Hooking it also means we inherit the binder library's own handling of one-way calls and
//! nested transactions instead of re-deriving them.
//!
//! ## Rewriting a parcel without a parser for the whole reply
//!
//! A `Parcel` cannot be edited in place -- there is no truncate and no seek. So the rewrite is
//! expressed as "copy everything up to this byte range, substitute this range, copy the rest",
//! which is [`rebuild`]. Keeping it in that shape means the byte surgery is a pure function
//! that runs (and is tested) on a host, and the platform half only has to obtain the bytes and
//! hand back a new parcel.

use std::cell::Cell;
use std::ops::Range;

/// What the hook does with one transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plan {
    /// Call the original and hand its reply back untouched.
    Forward,
    /// Call the original, then rewrite the certificate chain in its reply.
    ForwardAndRewrite,
}

/// Decides [`Plan`] for one transaction.
///
/// `reentrant` is true when we are already inside a transact on this thread. That happens for
/// real: repairing the chain means asking the device for the signing key's characteristics,
/// which is another transaction on the same binder, on the same thread. Without this flag the
/// hook would recurse until the stack is gone, inside the process that owns the keystore.
pub fn plan(descriptor: &str, code: u32, reentrant: bool) -> Plan {
    if reentrant || !crate::keymint::is_patchable_device(descriptor) {
        return Plan::Forward;
    }
    if crate::keymint::reply_has_certificate_chain(code) {
        Plan::ForwardAndRewrite
    } else {
        Plan::Forward
    }
}

/// Depth guard for the hook.
///
/// `Cell<bool>` rather than a counter on purpose: a nested transact is not "depth two", it is
/// "not ours", and a counter invites the belief that three levels are fine. It is per-thread
/// because binder transactions are.
pub struct RecursionGuard;

thread_local! {
    static IN_TRANSACT: Cell<bool> = const { Cell::new(false) };
}

impl RecursionGuard {
    /// Marks this thread as inside the hook. `None` means we already were.
    pub fn enter() -> Option<Self> {
        IN_TRANSACT.with(|flag| {
            if flag.replace(true) {
                None
            } else {
                Some(RecursionGuard)
            }
        })
    }
}

impl Drop for RecursionGuard {
    fn drop(&mut self) {
        IN_TRANSACT.with(|flag| flag.set(false));
    }
}

/// True when this thread is currently inside the hook.
pub fn is_reentrant() -> bool {
    IN_TRANSACT.with(Cell::get)
}

/// A byte range of the reply parcel replaced by `replacement`.
///
/// `replacement` is a fully encoded parcel fragment (its own length prefixes, its own
/// padding), not a payload the callee has to frame. The surgeon that produces it knows the
/// `byte[]` encoding rule; putting that framing here would mean two places that can disagree
/// about padding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyRewrite {
    /// Offset range in the original parcel bytes.
    pub range: Range<usize>,
    /// Encoded bytes that take its place.
    pub replacement: Vec<u8>,
}

/// Copies `original` around `rewrite`.
///
/// Returns `None` -- never a truncated parcel -- when the range does not fit. A malformed
/// reply must reach the caller unchanged: a half-copied parcel makes `keystore2` read garbage
/// as a `KeyCreationResult`, which surfaces as a crash in a system service rather than an
/// error the caller can retry.
pub fn rebuild(original: &[u8], rewrite: &ReplyRewrite) -> Option<Vec<u8>> {
    let start = rewrite.range.start;
    let end = rewrite.range.end;
    if start > end || end > original.len() {
        return None;
    }
    let mut out = Vec::with_capacity(original.len() - (end - start) + rewrite.replacement.len());
    out.extend_from_slice(&original[..start]);
    out.extend_from_slice(&rewrite.replacement);
    out.extend_from_slice(&original[end..]);
    Some(out)
}

#[cfg(target_os = "android")]
pub mod platform {
    //! The thin ABI layer. Everything here is `unsafe` because it hands pointers to the binder
    //! library, and it is deliberately the only place in the crate that does so for replies.
    use super::{plan, rebuild, Plan, RecursionGuard, ReplyRewrite};
    use std::ffi::{c_char, c_void, CStr};
    use std::sync::atomic::{AtomicPtr, Ordering};

    /// `binder_status_t` value returned when the transaction was not understood at all.
    ///
    /// Used as the failure value for a rewrite that produced nothing: it makes `keystore2`
    /// report `UNKNOWN_TRANSACTION` and retry through the path it already has, rather than
    /// silently returning an empty `KeyCreationResult`.
    pub const UNKNOWN_TRANSACTION: i32 = -1;

    pub type TransactFn =
        unsafe extern "C" fn(*mut c_void, u32, *mut c_void, *mut *mut c_void, u32) -> i32;

    static ORIGINAL_TRANSACT: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

    extern "C" {
        fn AIBinder_transact(
            binder: *mut c_void,
            code: u32,
            input: *mut c_void,
            reply: *mut *mut c_void,
            flags: u32,
        ) -> i32;
        fn AIBinder_getClass(binder: *mut c_void) -> *const c_void;
        fn AIBinder_descriptorForType(clazz: *const c_void) -> *const c_char;
        fn AParcel_marshal(parcel: *const c_void, length: *mut usize, buffer: *mut *mut u8) -> i32;
        fn AParcel_delete(parcel: *mut c_void) -> i32;
        fn AParcel_unmarshal(buffer: *const u8, length: usize, parcel: *mut *mut c_void) -> i32;
    }

    /// Installs the hook. Called from `entry`; the trampoline is only live after the caller
    /// commits, so a failed install leaves the process completely untouched.
    pub fn install() -> std::io::Result<()> {
        use crate::plthook::{HookSpec, HookSpec as _};
        let spec = HookSpec {
            libraries: &["libbinder_ndk.so", "libbinder.so", "libcore_bundle.so"],
            symbol: "AIBinder_transact",
        };
        let original = crate::plthook::install(&spec, hooked_transact as *mut c_void)?;
        if original.is_null() {
            // The registration went through but the object has no such PLT slot. Continuing
            // would mean forwarding through null.
            return Err(std::io::Error::other(
                "AIBinder_transact is not plumbed through the PLT of the binder library",
            ));
        }
        ORIGINAL_TRANSACT.store(original, Ordering::Release);
        Ok(())
    }

    /// Commits the installed hook.
    pub fn commit() -> std::io::Result<()> {
        crate::plthook::commit()
    }

    fn original() -> TransactFn {
        let pointer = ORIGINAL_TRANSACT.load(Ordering::Acquire);
        debug_assert!(!pointer.is_null(), "trampoline used before install");
        // SAFETY: `pointer` is the trampoline lsplt handed back for `AIBinder_transact`, which
        // has exactly this signature by definition of the hook.
        unsafe { std::mem::transmute::<*mut c_void, TransactFn>(pointer) }
    }

    fn descriptor_of(binder: *mut c_void) -> Option<&'static str> {
        if binder.is_null() {
            return None;
        }
        // SAFETY: `binder` is the object the transact was addressed to. The NDK guarantees a
        // live object here for the duration of the call.
        unsafe {
            let class = AIBinder_getClass(binder);
            if class.is_null() {
                return None;
            }
            let descriptor = AIBinder_descriptorForType(class);
            if descriptor.is_null() {
                return None;
            }
            CStr::from_ptr(descriptor).to_str().ok()
        }
    }

    /// The hook itself.
    ///
    /// SAFETY: called by the binder library with exactly the arguments of `AIBinder_transact`;
    /// `reply`, when non-null, points to a slot the caller owns and we may fill.
    unsafe extern "C" fn hooked_transact(
        binder: *mut c_void,
        code: u32,
        input: *mut c_void,
        reply: *mut *mut c_void,
        flags: u32,
    ) -> i32 {
        let Some(_guard) = RecursionGuard::enter() else {
            return original()(binder, code, input, reply, flags);
        };
        let descriptor = descriptor_of(binder).unwrap_or_default();
        if plan(descriptor, code, false) == Plan::Forward {
            return original()(binder, code, input, reply, flags);
        }
        // Ask the real HAL with a reply parcel we own, so the rewrite can look at the bytes.
        let mut scratch: *mut c_void = std::ptr::null_mut();
        let status = original()(binder, code, input, &mut scratch, flags);
        if status != 0 || scratch.is_null() {
            // The HAL failed. Forwarding the failure verbatim is the only correct answer: a
            // caller that gets OK with a synthetic reply would persist a key the TEE never
            // created.
            if reply.is_null() {
                return status;
            }
            *reply = scratch;
            return status;
        }
        match rewrite_or_passthrough(scratch, reply) {
            Some(patched) => {
                AParcel_delete(scratch);
                if !reply.is_null() {
                    *reply = patched;
                }
                status
            }
            None => {
                if !reply.is_null() {
                    *reply = scratch;
                }
                status
            }
        }
    }

    /// Marshals the reply, asks [`crate::surgeon`] for a rewrite, and unmarshals the result.
    ///
    /// `None` means "keep the original", which is the answer for every case that is not a
    /// clean, understood `KeyCreationResult`.
    unsafe fn rewrite_or_passthrough(
        scratch: *mut c_void,
        reply: *mut *mut c_void,
    ) -> Option<*mut c_void> {
        if reply.is_null() {
            return None;
        }
        let mut length: usize = 0;
        let mut buffer: *mut u8 = std::ptr::null_mut();
        if AParcel_marshal(scratch, &mut length, &mut buffer) != 0 || buffer.is_null() {
            return None;
        }
        let bytes = std::slice::from_raw_parts(buffer, length);
        let rewrite: ReplyRewrite = crate::surgeon::plan_reply_rewrite(bytes)?;
        let patched = rebuild(bytes, &rewrite)?;
        let mut parcel: *mut c_void = std::ptr::null_mut();
        if AParcel_unmarshal(patched.as_ptr(), patched.len(), &mut parcel) != 0 || parcel.is_null()
        {
            return None;
        }
        Some(parcel)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keymint::{KEYMINT_DESCRIPTOR, TX_DEVICE_LOCKED, TX_GENERATE_KEY};

    #[test]
    fn only_generate_key_on_the_device_interface_is_rewritten() {
        assert_eq!(
            plan(KEYMINT_DESCRIPTOR, TX_GENERATE_KEY, false),
            Plan::ForwardAndRewrite
        );
        assert_eq!(
            plan(KEYMINT_DESCRIPTOR, TX_DEVICE_LOCKED, false),
            Plan::Forward
        );
        assert_eq!(
            plan(
                "android.hardware.security.keymint.IKeyMintOperation",
                TX_GENERATE_KEY,
                false
            ),
            Plan::Forward
        );
    }

    #[test]
    fn a_reentrant_transaction_is_never_rewritten() {
        // Even the one code we care about: asking for it from inside our own rewrite would
        // recurse until the stack dies inside keystore2.
        assert_eq!(
            plan(KEYMINT_DESCRIPTOR, TX_GENERATE_KEY, true),
            Plan::Forward
        );
    }

    #[test]
    fn the_guard_is_held_for_exactly_one_scope() {
        assert!(!is_reentrant());
        {
            let guard = RecursionGuard::enter().expect("first entry");
            assert!(is_reentrant());
            assert!(
                RecursionGuard::enter().is_none(),
                "second entry must be refused"
            );
            drop(guard);
        }
        assert!(!is_reentrant());
        // Dropping the refused attempt must not have cleared the live guard's flag early.
        let guard = RecursionGuard::enter().expect("entry after the scope ended");
        drop(guard);
    }

    #[test]
    fn rebuild_splices_the_three_pieces() {
        let original = b"AAAABBBBCCCC";
        let rewrite = ReplyRewrite {
            range: 4..8,
            replacement: b"xy".to_vec(),
        };
        assert_eq!(
            rebuild(original, &rewrite).expect("in range"),
            b"AAAAxyCCCC".to_vec()
        );
    }

    #[test]
    fn rebuild_refuses_rather_than_truncating() {
        let original = b"AAAABBBB";
        let past_the_end = ReplyRewrite {
            range: 4..9,
            replacement: b"xy".to_vec(),
        };
        assert_eq!(rebuild(original, &past_the_end), None);
        let inverted = ReplyRewrite {
            // Spelled as a struct literal so a range that cannot exist reads as deliberate;
            // clippy refuses a literal `6..4` outright, and this case has to stay in the test.
            range: core::ops::Range { start: 6, end: 4 },
            replacement: b"xy".to_vec(),
        };
        assert_eq!(rebuild(original, &inverted), None);
    }

    #[test]
    fn an_empty_replacement_deletes_the_range() {
        let original = b"AAAABBBBCCCC";
        let rewrite = ReplyRewrite {
            range: 4..8,
            replacement: Vec::new(),
        };
        assert_eq!(
            rebuild(original, &rewrite).expect("in range"),
            b"AAAA CCCC"
                .to_vec()
                .into_iter()
                .filter(|byte| *byte != b' ')
                .collect::<Vec<u8>>()
        );
    }
}
