//! The KeyMint transaction surface we are allowed to look at.
//!
//! Patch mode needs exactly one thing from the HAL: the reply of `generateKey`, because that
//! reply carries the certificate chain the TEE signed. Everything else is forwarded untouched,
//! and keeping that list explicit is what stops this crate from drifting into the
//! "reimplement the keystore" design that changes `keyBlob` ownership and logs users out.
//!
//! ## Where the numbers come from
//!
//! `IKeyMintDevice` is an AIDL interface, and AIDL assigns transaction codes by declaration
//! order starting at `FIRST_CALL_TRANSACTION` (1). `generateKey` is the third method in
//! `hardware/interfaces/security/keymint/aidl/.../IKeyMintDevice.aidl`, so it is code 3.
//!
//! The ordering below is corroborated by TEESimulator, which hooks the same entry point and
//! lists codes 3, 4, 5, 6, 7, 10, 13, 14 as handled; that is exactly
//! `generateKey`/`importKey`/`importWrappedKey`/`upgradeKey`/`deleteKey`/`deviceLocked`/
//! `getKeyCharacteristics`/`deleteAllKeys` under this numbering. Two independent
//! implementations agreeing is the best evidence available short of reading the AIDL.
//!
//! `IKeyMintDevice` was added in Android 12. Before that the interface is Keymaster 4.1
//! (`android.hardware.keymaster@4.1::IKeymasterDevice`, HIDL) with a *different* code layout,
//! which is why [`is_patchable_device`] checks the descriptor and not only the code.

/// AIDL interface descriptor of the modern keymint device.
pub const KEYMINT_DESCRIPTOR: &str = "android.hardware.security.keymint.IKeyMintDevice";

/// Descriptor of the Keymaster 4.x HIDL interface (Android 11 and older).
///
/// Patch mode does not patch through this one: HIDL parcels are HidlSupport-wrapped and the
/// cert chain sits in a `Vec<uint8_t>`, but more importantly the daemon already reports the
/// process name (`keystore` vs `keystore2`) for the SDK it runs on, so the older layout is
/// recognised only to be *rejected explicitly* instead of being silently mis-parsed.
pub const KEYMASTER_DESCRIPTOR: &str = "android.hardware.keymaster@4.1::IKeymasterDevice";

pub const TX_GET_HARDWARE_INFO: u32 = 1;
pub const TX_ADD_RNG_ENTROPY: u32 = 2;
pub const TX_GENERATE_KEY: u32 = 3;
pub const TX_IMPORT_KEY: u32 = 4;
pub const TX_IMPORT_WRAPPED_KEY: u32 = 5;
pub const TX_UPGRADE_KEY: u32 = 6;
pub const TX_DELETE_KEY: u32 = 7;
pub const TX_DESTROY_ATTESTATION_IDS: u32 = 8;
pub const TX_BEGIN: u32 = 9;
pub const TX_DEVICE_LOCKED: u32 = 10;
pub const TX_EARLY_BOOT_ENDED: u32 = 11;
pub const TX_CONVERT_STORAGE_KEY_TO_EPHEMERAL: u32 = 12;
pub const TX_GET_KEY_CHARACTERISTICS: u32 = 13;
pub const TX_DELETE_ALL_KEYS: u32 = 14;

/// True when `descriptor` is the interface whose codes this module documents.
///
/// AIDL descriptors are NUL-terminated C strings; the caller trims before asking, but the
/// comparison is exact on purpose. `IKeyMintDevice` and `IKeyMintOperation` (the handle type
/// returned by `begin`) share a prefix, and patching an operation transaction would mean
/// reading a request that has no certificate in it.
pub fn is_patchable_device(descriptor: &str) -> bool {
    descriptor == KEYMINT_DESCRIPTOR
}

/// True when the reply to `code` contains a certificate chain the TEE signed.
///
/// Only `generateKey` does. `importKey` also produces attestation, but the chain is generated
/// on the next `generateKey`/`getKeyCharacteristics` path and the `importKey` reply is a plain
/// `KeyCharacteristics`; the request already carries the caller's attestation params, so
/// nothing in the reply is worth rewriting.
pub fn reply_has_certificate_chain(code: u32) -> bool {
    code == TX_GENERATE_KEY
}

/// The transactions a Patch-mode build cares about at all.
///
/// Kept as a function rather than a boolean expression at the call site so the hook can log a
/// single line ("code 13 not inspected") instead of leaving future readers to re-derive the
/// list. Codes absent from this set are forwarded without a single parcel access.
pub fn is_inspected(code: u32) -> bool {
    matches!(
        code,
        TX_GENERATE_KEY
            | TX_IMPORT_KEY
            | TX_IMPORT_WRAPPED_KEY
            | TX_UPGRADE_KEY
            | TX_DELETE_KEY
            | TX_DEVICE_LOCKED
            | TX_EARLY_BOOT_ENDED
            | TX_GET_KEY_CHARACTERISTICS
            | TX_DELETE_ALL_KEYS
    )
}

/// Human-readable name, for logs that have to be readable without the source.
pub fn transaction_name(code: u32) -> &'static str {
    match code {
        TX_GET_HARDWARE_INFO => "getHardwareInfo",
        TX_ADD_RNG_ENTROPY => "addRngEntropy",
        TX_GENERATE_KEY => "generateKey",
        TX_IMPORT_KEY => "importKey",
        TX_IMPORT_WRAPPED_KEY => "importWrappedKey",
        TX_UPGRADE_KEY => "upgradeKey",
        TX_DELETE_KEY => "deleteKey",
        TX_DESTROY_ATTESTATION_IDS => "destroyAttestationIds",
        TX_BEGIN => "begin",
        TX_DEVICE_LOCKED => "deviceLocked",
        TX_EARLY_BOOT_ENDED => "earlyBootEnded",
        TX_CONVERT_STORAGE_KEY_TO_EPHEMERAL => "convertStorageKeyToEphemeral",
        TX_GET_KEY_CHARACTERISTICS => "getKeyCharacteristics",
        TX_DELETE_ALL_KEYS => "deleteAllKeys",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_key_is_third_and_is_the_only_chain_reply() {
        assert_eq!(TX_GENERATE_KEY, 3);
        assert_eq!(transaction_name(TX_GENERATE_KEY), "generateKey");
        assert!(reply_has_certificate_chain(TX_GENERATE_KEY));
        // importKey returns KeyCharacteristics, not a chain.
        assert!(!reply_has_certificate_chain(TX_IMPORT_KEY));
        assert!(!reply_has_certificate_chain(TX_GET_KEY_CHARACTERISTICS));
    }

    #[test]
    fn the_inspected_set_is_the_documented_one() {
        // The set TEESimulator handles, mapped onto these names.
        for code in [3u32, 4, 5, 6, 7, 10, 13, 14] {
            assert!(is_inspected(code), "code {code} should be inspected");
        }
        // `begin` returns an operation handle; there is nothing to patch and touching it would
        // put a parcel read on the hot path of every crypto operation.
        assert!(!is_inspected(TX_BEGIN));
        assert!(!is_inspected(TX_GET_HARDWARE_INFO));
    }

    #[test]
    fn the_operation_interface_is_not_the_device_interface() {
        assert!(is_patchable_device(KEYMINT_DESCRIPTOR));
        assert!(!is_patchable_device(
            "android.hardware.security.keymint.IKeyMintOperation"
        ));
        assert!(!is_patchable_device(KEYMASTER_DESCRIPTOR));
    }
}
