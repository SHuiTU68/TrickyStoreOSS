//! The attestation snapshot the control plane reasons about.
//!
//! The Kotlin daemon asked keystore2 for a throwaway key at startup (`AttestUtils.probe`) and kept the
//! verified-boot fields of the certificate it got back. That probe came at a price the native daemon
//! cannot pay: it needs a full binder client, it leaves a key behind if the daemon dies between
//! `generateKey` and `deleteKey`, and — under the patch model — it creates a key the platform has to
//! garbage-collect on a path no application asked for.
//!
//! What the probe was really good for is the values: `verified_boot_key`, `verified_boot_hash`,
//! `os_version`, the attestation/keymaster version pair and the module hash, all of them as the TEE
//! actually reports them. Those are exactly the fields the interceptor already parses out of every
//! attestation it rewrites, so the interceptor is the honest source: same TEE, same request shape,
//! no extra key. It drops what it saw into [`SNAPSHOT_FILE`], and the daemon reads it at boot.
//!
//! A missing snapshot is not an error. On the very first boot after install the interceptors have not
//! seen an attestation yet, so every field is absent and `boot` falls back to the properties and the
//! persisted key exactly as the Kotlin version did when the probe failed.
use std::path::{Path, PathBuf};

use certgen::report::Note;

use crate::boot::from_hex;

/// File the interceptor writes and the daemon reads, inside the data directory.
pub const SNAPSHOT_FILE: &str = "attestation.snapshot";

/// Written first so a human opening the file knows which contract produced it.
const HEADER: &str = "# tricky-store attestation snapshot v1";

/// Length of every digest in an attestation record: AVB keys and hashes are SHA-256.
const DIGEST_LEN: usize = 32;

/// One observed attestation, reduced to the fields the daemon needs.
///
/// Every field is optional because a partial snapshot is valid: an attestation for a non-strongbox key
/// carries no module hash, and a legacy Keymaster backend reports no version pair. Absence means "the
/// interceptor has not seen this yet", which is different from a zeroed value and must not be
/// conflated with one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Snapshot {
    /// `verified_boot_key` from the attestation record.
    pub boot_key: Option<Vec<u8>>,
    /// `verified_boot_hash` from the attestation record.
    pub boot_hash: Option<Vec<u8>>,
    /// `os_version` the TEE reported, in the platform's `major * 10000 + minor * 100 + patch` form.
    pub os_version: Option<i32>,
    /// Attestation version the record was tagged with.
    pub attestation_version: Option<i32>,
    /// Keymaster/KeyMint version the backend reported.
    pub keymaster_version: Option<i32>,
    /// Module hash, when the backend supplies one.
    pub module_hash: Option<Vec<u8>>,
    /// Unix seconds at which the interceptor captured this, used only to say how stale it is.
    pub captured_at: Option<u64>,
}

impl Snapshot {
    /// True when the interceptor has not observed anything yet.
    pub fn is_empty(&self) -> bool {
        self.boot_key.is_none()
            && self.boot_hash.is_none()
            && self.os_version.is_none()
            && self.attestation_version.is_none()
            && self.keymaster_version.is_none()
            && self.module_hash.is_none()
    }

    /// The boot key, but only when it can be used as one.
    ///
    /// The Kotlin code tested `!verifiedBootKey.all { it == 0.toByte() }` before trusting the cached
    /// value; the length check is added here because a 32-byte digest is the only shape an attestation
    /// record ever holds and a shorter array would end up in a certificate as a silently different key.
    pub fn non_zero_boot_key(&self) -> Option<Vec<u8>> {
        usable_digest(self.boot_key.as_deref(), "verified_boot_key")
    }

    /// The boot hash under the same rules as [`Self::non_zero_boot_key`].
    pub fn non_zero_boot_hash(&self) -> Option<Vec<u8>> {
        usable_digest(self.boot_hash.as_deref(), "verified_boot_hash")
    }

    /// Parses the on-disk form. Unknown keys are ignored (a newer interceptor may write more fields),
    /// malformed ones are dropped with a note instead of failing the load: a corrupt snapshot must not
    /// stop the daemon, it must only make it fall back.
    pub fn parse(text: &str, notes: &mut Vec<Note>) -> Self {
        let mut snapshot = Snapshot::default();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                notes.push(Note::warn(format!(
                    "attestation.snapshot: ignoring line without '=': {line}"
                )));
                continue;
            };
            let key = key.trim();
            let value = value.trim();
            match key {
                "boot_key" => snapshot.boot_key = digest_field(value, key, notes),
                "boot_hash" => snapshot.boot_hash = digest_field(value, key, notes),
                "module_hash" => snapshot.module_hash = digest_field(value, key, notes),
                "os_version" => snapshot.os_version = int_field(value, key, notes),
                "attest_version" => snapshot.attestation_version = int_field(value, key, notes),
                "keymaster_version" => snapshot.keymaster_version = int_field(value, key, notes),
                "captured_at" => {
                    snapshot.captured_at = int_field(value, key, notes)
                        .map(i64::from)
                        .and_then(|value| u64::try_from(value).ok())
                }
                other => notes.push(Note::debug(format!(
                    "attestation.snapshot: ignoring unknown key '{other}'"
                ))),
            }
        }
        snapshot
    }

    /// Serialises back to the on-disk form. Only present fields are written, so an empty snapshot
    /// round-trips to a header-only file rather than to a file full of zeroes.
    pub fn encode(&self) -> String {
        let mut out = String::new();
        out.push_str(HEADER);
        out.push('\n');
        if let Some(key) = &self.boot_key {
            out.push_str(&format!("boot_key={}\n", crate::boot::to_hex(key)));
        }
        if let Some(hash) = &self.boot_hash {
            out.push_str(&format!("boot_hash={}\n", crate::boot::to_hex(hash)));
        }
        if let Some(os_version) = self.os_version {
            out.push_str(&format!("os_version={os_version}\n"));
        }
        if let Some(version) = self.attestation_version {
            out.push_str(&format!("attest_version={version}\n"));
        }
        if let Some(version) = self.keymaster_version {
            out.push_str(&format!("keymaster_version={version}\n"));
        }
        if let Some(hash) = &self.module_hash {
            out.push_str(&format!("module_hash={}\n", crate::boot::to_hex(hash)));
        }
        if let Some(captured_at) = self.captured_at {
            out.push_str(&format!("captured_at={captured_at}\n"));
        }
        out
    }

    /// One line for the log and for `--dump`.
    pub fn describe(&self) -> String {
        if self.is_empty() {
            return "empty".to_owned();
        }
        let mut parts: Vec<String> = Vec::new();
        if let Some(key) = &self.boot_key {
            parts.push(format!("boot_key={} bytes", key.len()));
        }
        if let Some(hash) = &self.boot_hash {
            parts.push(format!("boot_hash={} bytes", hash.len()));
        }
        if let Some(os_version) = self.os_version {
            parts.push(format!("os_version={os_version}"));
        }
        if let Some(version) = self.attestation_version {
            parts.push(format!("attest_version={version}"));
        }
        if let Some(version) = self.keymaster_version {
            parts.push(format!("keymaster_version={version}"));
        }
        if let Some(hash) = &self.module_hash {
            parts.push(format!("module_hash={} bytes", hash.len()));
        }
        parts.join(" ")
    }
}

/// Where the snapshot lives for one data directory.
pub fn snapshot_path(data_dir: &Path) -> PathBuf {
    data_dir.join(SNAPSHOT_FILE)
}

/// Reads the snapshot, if the interceptor has written one.
pub fn read(data_dir: &Path) -> Option<Snapshot> {
    let path = snapshot_path(data_dir);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(error) => {
            crate::log::error(format!("Failed to read {}: {error}", path.display()));
            return None;
        }
    };
    let mut notes = Vec::new();
    let snapshot = Snapshot::parse(&text, &mut notes);
    crate::log::replay(&notes);
    Some(snapshot)
}

/// Writes the snapshot atomically. The interceptor calls this on first sight and then only when a
/// value changes; a crash mid-write must not leave a half-parsed file, hence temp-plus-rename.
///
/// `allow(dead_code)` because the writer is the injected library, not the daemon: the daemon only
/// reads, so the round trip lives in the tests until the D2 interceptor calls this.
#[allow(dead_code)]
pub fn write(data_dir: &Path, snapshot: &Snapshot) -> std::io::Result<()> {
    let path = snapshot_path(data_dir);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temp = path.with_extension("tmp");
    std::fs::write(&temp, snapshot.encode())?;
    std::fs::rename(&temp, &path)?;
    Ok(())
}

/// The control-plane "probe": read what the interceptors observed and say so.
///
/// Returns `None` when there is no snapshot at all, which the caller treats as "no cached values" —
/// the same outcome as the Kotlin probe failing, minus the retry loop (retrying cannot help here: the
/// file appears when the first attestation happens, not on a timer).
pub fn probe(data_dir: &Path) -> Option<Snapshot> {
    let path = snapshot_path(data_dir);
    match read(data_dir) {
        None => {
            crate::log::info(format!(
                "No attestation snapshot at {}; boot values will come from properties and the persisted key",
                path.display()
            ));
            None
        }
        Some(snapshot) => {
            crate::log::info(format!(
                "Attestation snapshot at {}: {}",
                path.display(),
                snapshot.describe()
            ));
            Some(snapshot)
        }
    }
}

/// A digest field, accepted only at the length the attestation record uses.
fn digest_field(value: &str, key: &str, notes: &mut Vec<Note>) -> Option<Vec<u8>> {
    let Some(bytes) = from_hex(value) else {
        notes.push(Note::warn(format!(
            "{key}: '{}' is not valid hex, ignored",
            ellipsis(value)
        )));
        return None;
    };
    if bytes.len() != DIGEST_LEN {
        notes.push(Note::warn(format!(
            "{key}: expected {DIGEST_LEN} bytes, got {}, ignored",
            bytes.len()
        )));
        return None;
    }
    Some(bytes)
}

fn int_field(value: &str, key: &str, notes: &mut Vec<Note>) -> Option<i32> {
    match value.parse::<i32>() {
        Ok(number) => Some(number),
        Err(_) => {
            notes.push(Note::warn(format!(
                "{key}: '{}' is not an integer, ignored",
                ellipsis(value)
            )));
            None
        }
    }
}

fn ellipsis(value: &str) -> String {
    if value.len() <= 32 {
        return value.to_owned();
    }
    format!("{}...", &value[..32])
}

/// Shared by the two digest accessors: right length, and not the all-zero placeholder a failed
/// attestation leaves behind.
fn usable_digest(value: Option<&[u8]>, name: &str) -> Option<Vec<u8>> {
    let bytes = value?;
    if bytes.len() != DIGEST_LEN {
        crate::log::warn(format!(
            "Snapshot {name} is {} bytes, not {DIGEST_LEN}; not using it",
            bytes.len()
        ));
        return None;
    }
    if bytes.iter().all(|byte| *byte == 0) {
        crate::log::debug(format!("Snapshot {name} is all zeroes; not using it"));
        return None;
    }
    Some(bytes.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(fill: u8) -> String {
        crate::boot::to_hex(&[fill; DIGEST_LEN])
    }

    #[test]
    fn a_snapshot_round_trips_through_the_file_format() {
        let snapshot = Snapshot {
            boot_key: Some(vec![0x11; DIGEST_LEN]),
            boot_hash: Some(vec![0x22; DIGEST_LEN]),
            os_version: Some(140000),
            attestation_version: Some(300),
            keymaster_version: Some(300),
            module_hash: Some(vec![0x33; DIGEST_LEN]),
            captured_at: Some(1_700_000_000),
        };
        let mut notes = Vec::new();
        let parsed = Snapshot::parse(&snapshot.encode(), &mut notes);
        assert!(notes.is_empty(), "unexpected notes: {notes:?}");
        assert_eq!(parsed, snapshot);
    }

    #[test]
    fn an_empty_snapshot_is_recognised() {
        let mut notes = Vec::new();
        let parsed = Snapshot::parse(HEADER, &mut notes);
        assert!(parsed.is_empty());
        assert!(notes.is_empty());
        assert_eq!(parsed.encode(), format!("{HEADER}\n"));
    }

    #[test]
    fn malformed_fields_are_dropped_with_a_note() {
        let text = format!(
            "boot_key={}\nboot_hash=not-hex\nos_version=abc\nkeymaster_version=300\nunknown=1\n",
            hex32(0x44)
        );
        let mut notes = Vec::new();
        let parsed = Snapshot::parse(&text, &mut notes);
        assert_eq!(parsed.boot_key, Some(vec![0x44; DIGEST_LEN]));
        assert_eq!(parsed.boot_hash, None);
        assert_eq!(parsed.os_version, None);
        assert_eq!(parsed.keymaster_version, Some(300));
        assert_eq!(
            notes.len(),
            3,
            "expected three warnings plus one debug: {notes:?}"
        );
    }

    #[test]
    fn a_short_digest_is_rejected_rather_than_padded() {
        let mut notes = Vec::new();
        let parsed = Snapshot::parse("boot_key=00112233\n", &mut notes);
        assert_eq!(parsed.boot_key, None);
        assert_eq!(notes.len(), 1);
    }

    #[test]
    fn a_zeroed_digest_is_not_used() {
        let snapshot = Snapshot {
            boot_key: Some(vec![0; DIGEST_LEN]),
            boot_hash: Some(vec![0x55; DIGEST_LEN]),
            ..Snapshot::default()
        };
        assert_eq!(snapshot.non_zero_boot_key(), None);
        assert_eq!(snapshot.non_zero_boot_hash(), Some(vec![0x55; DIGEST_LEN]));
    }

    #[test]
    fn a_missing_digest_is_not_used() {
        let snapshot = Snapshot::default();
        assert_eq!(snapshot.non_zero_boot_key(), None);
        assert_eq!(snapshot.non_zero_boot_hash(), None);
    }

    #[test]
    fn writing_then_reading_returns_the_same_snapshot() {
        let dir = std::env::temp_dir().join(format!("tricky-snapshot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let snapshot = Snapshot {
            boot_key: Some(vec![0x66; DIGEST_LEN]),
            ..Snapshot::default()
        };
        write(&dir, &snapshot).expect("write");
        assert_eq!(read(&dir), Some(snapshot));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_snapshot_reads_as_none() {
        let dir = std::env::temp_dir().join(format!("tricky-snapshot-none-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(read(&dir), None);
    }
}
