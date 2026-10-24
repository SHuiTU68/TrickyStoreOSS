//! Verified-boot inputs the certificate builders need on every attestation.
//!
//! Kotlin resolved them in `AndroidUtils`: the boot key came from `ro.boot.vbmeta.public_key_digest`,
//! then from a cached TEE attestation, then from a random value persisted under
//! `/data/adb/tricky_store/boot_key`; the boot hash came from `ro.boot.vbmeta.digest`, then from the
//! cached attestation, then from a random value written back through `resetprop`.
//!
//! The order and the failure modes are carried over unchanged, because the values end up inside the
//! attestation extension and their provenance decides whether a verifier sees a consistent device.
//! What changes is the third source: instead of asking keystore2 for a throwaway key at startup
//! (which needs a full binder client and leaves a key behind if the daemon is killed mid-probe), the
//! snapshot the interceptor caches from the first real attestation it observes is used. Under the
//! patch model that is the honest source anyway: the values come from the same TEE the forwarded
//! `generateKey` will use.

use std::path::{Path, PathBuf};

use certgen::hide_props;
use certgen::hide_props::PropertySource;
use certgen::system::{ShShell, SystemProperties};

use crate::probe::Snapshot;

/// Property the platform publishes the AVB public key digest in.
const BOOT_KEY_PROP: &str = "ro.boot.vbmeta.public_key_digest";
/// Property the platform publishes the AVB hash in.
const BOOT_HASH_PROP: &str = "ro.boot.vbmeta.digest";
/// Persisted fallback for the boot key, kept outside the module directory so a module update does not
/// change the value the device has been reporting.
const BOOT_KEY_FILE: &str = "boot_key";

/// Where a resolved value came from. Logged verbatim, and part of the `--dump` output, because the
/// three cases are not equivalent: only the property and attestation paths describe the real device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    SystemProperty,
    Attestation,
    Persisted,
    Random,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::SystemProperty => "system_property",
            Source::Attestation => "attestation",
            Source::Persisted => "persisted",
            Source::Random => "random",
        }
    }
}

/// Both verified-boot inputs, already resolved and logged.
#[derive(Debug, Clone)]
pub struct VerifiedBoot {
    pub key: Vec<u8>,
    pub key_source: Source,
    pub hash: Vec<u8>,
    pub hash_source: Source,
}

/// Resolves the boot key and the boot hash. The hash is written back to the property when it did not
/// come from one, which is what makes the keystore's own attestations agree with the ones we produce.
pub fn resolve(data_dir: &Path, snapshot: Option<&Snapshot>) -> VerifiedBoot {
    let (key, key_source) = resolve_boot_key(data_dir, snapshot);
    let (hash, hash_source) = resolve_boot_hash(snapshot);
    if hash_source != Source::SystemProperty {
        set_property(BOOT_HASH_PROP, &to_hex(&hash));
    }
    VerifiedBoot {
        key,
        key_source,
        hash,
        hash_source,
    }
}

fn resolve_boot_key(data_dir: &Path, snapshot: Option<&Snapshot>) -> (Vec<u8>, Source) {
    if let Some(key) = property_hex(BOOT_KEY_PROP) {
        return (key, Source::SystemProperty);
    }
    if let Some(key) = snapshot.and_then(|snapshot| snapshot.non_zero_boot_key()) {
        return (key, Source::Attestation);
    }
    (persisted_boot_key(data_dir), Source::Persisted)
}

fn resolve_boot_hash(snapshot: Option<&Snapshot>) -> (Vec<u8>, Source) {
    if let Some(hash) = property_hex(BOOT_HASH_PROP) {
        return (hash, Source::SystemProperty);
    }
    if let Some(hash) = snapshot.and_then(|snapshot| snapshot.non_zero_boot_hash()) {
        return (hash, Source::Attestation);
    }
    (random_bytes(), Source::Random)
}

/// Reads a 32-byte hex property. A property that is set but malformed is treated as absent, matching
/// the Kotlin `runCatching { digest.hexToByteArray() }.getOrNull()`; the length check comes first so a
/// short value is never padded into something that looks like a digest.
fn property_hex(name: &str) -> Option<Vec<u8>> {
    let value = SystemProperties.get(name)?;
    let trimmed = value.trim();
    if trimmed.len() != 64 {
        return None;
    }
    from_hex(trimmed)
}

/// Reads the persisted fallback, generating and storing one on first boot. The file is written
/// atomically enough for this purpose (temp file, rename) so a crash cannot leave half a key behind.
fn persisted_boot_key(data_dir: &Path) -> Vec<u8> {
    let path: PathBuf = data_dir.join(BOOT_KEY_FILE);
    if let Ok(text) = std::fs::read_to_string(&path) {
        if let Some(key) = from_hex(text.trim()) {
            crate::log::debug(format!("Using persisted boot key from {}", path.display()));
            return key;
        }
        crate::log::warn(format!("Ignoring malformed boot key in {}", path.display()));
    }
    let key = random_bytes();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let temp = path.with_extension("tmp");
    let written = std::fs::write(&temp, to_hex(&key)).and_then(|()| std::fs::rename(&temp, &path));
    if written.is_err() {
        crate::log::error(format!(
            "Failed to persist boot key to {}; keeping it ephemeral",
            path.display()
        ));
    }
    crate::log::debug("Generated a random boot key (no AVB key available)");
    key
}

/// 32 bytes from `/dev/urandom`. Reading the device directly avoids pulling a RNG crate into the
/// daemon: `getrandom` would be the same syscall with a longer dependency chain.
pub fn random_bytes() -> Vec<u8> {
    use std::io::Read;

    let mut buffer = vec![0u8; 32];
    match std::fs::File::open("/dev/urandom").and_then(|mut file| file.read_exact(&mut buffer)) {
        Ok(()) => buffer,
        Err(error) => {
            // A device without /dev/urandom cannot happen on Android; the fallback keeps the daemon
            // running with a value that is at least not all zeroes, and says so.
            crate::log::error(format!("Failed to read /dev/urandom: {error}"));
            for (index, byte) in buffer.iter_mut().enumerate() {
                *byte = (index as u8).wrapping_mul(37).wrapping_add(11);
            }
            buffer
        }
    }
}

/// Writes one property through `resetprop`, which is the only way to change an `ro.*` property after
/// boot and, unlike a raw property write, does not leave a modification trace behind.
pub fn set_property(name: &str, value: &str) -> bool {
    let applied = hide_props::set_property(name, value, &SystemProperties, &ShShell);
    if !applied {
        crate::log::error(format!("Failed to set {name}"));
    }
    applied
}

pub fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(nibble(byte >> 4));
        out.push(nibble(byte & 0x0f));
    }
    out
}

fn nibble(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        _ => (b'a' + value - 10) as char,
    }
}

/// Strict hex decode: exact length, no prefixes, no whitespace inside. Anything else is rejected
/// rather than repaired, so a truncated property cannot silently become a different key.
pub fn from_hex(text: &str) -> Option<Vec<u8>> {
    if text.is_empty() || text.len() % 2 != 0 {
        return None;
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let high = digit(pair[0])?;
        let low = digit(pair[1])?;
        out.push((high << 4) | low);
    }
    Some(out)
}

fn digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips_and_rejects_junk() {
        let bytes = vec![0x00, 0x01, 0xab, 0xff];
        assert_eq!(to_hex(&bytes), "0001abff");
        assert_eq!(from_hex("0001abff"), Some(bytes));
        assert_eq!(from_hex("0001ABFF"), Some(vec![0x00, 0x01, 0xab, 0xff]));
        assert_eq!(from_hex("000"), None);
        assert_eq!(from_hex("00zz"), None);
        assert_eq!(from_hex(""), None);
    }

    #[test]
    fn a_fresh_boot_key_is_persisted_and_reused() {
        let dir = std::env::temp_dir().join(format!("tricky-boot-key-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let first = persisted_boot_key(&dir);
        let second = persisted_boot_key(&dir);
        assert_eq!(first.len(), 32);
        assert_eq!(first, second);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
