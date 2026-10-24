//! On-disk persistence for issued keys: format, bounds checks, and durable writes.
//!
//! The daemon keeps one record per (uid, alias) under `/data/adb/tricky_store/keys/<uid>/<sha256>.bin`
//! so an issued key survives a restart. Losing or corrupting that record is what breaks an app's
//! keystore identity, so the disk side is deliberately strict:
//!
//!   - **The record is parsed before it is written.** `persist` decodes the blob, applies every
//!     bounds check, and re-encodes it, so a bug in the Kotlin encoder can never put a record on
//!     disk that this module's own reader would reject on the next boot.
//!   - **Every length is checked against the bytes that are actually there.** A truncated or
//!     hand-crafted record fails with a message naming the field, instead of allocating a huge
//!     buffer or silently reading zeros.
//!   - **The record is only visible once it is complete and durable**, and only its owner can read
//!     it: write to `.tmp` (mode 0600), `fsync`, rename into place, then `fsync` the directory.
//!     A crash mid-write leaves the previous record untouched.
//!
//! ## Why the blob layout is unchanged from the Kotlin implementation
//!
//! Records written by the previous Kotlin-only build are already on disk, so the on-disk format is
//! frozen: `FORMAT_VERSION` 4 (current) and `LEGACY_FORMAT_VERSION` 3 (accepted, never produced).
//! The `#[repr]`-free layout below mirrors `DataOutputStream` exactly — big-endian, `writeUTF`
//! uses *modified* UTF-8 for strings (two-byte length, NUL as `C0 80`, supplementary characters as
//! a UTF-16 surrogate pair), everything else is length-prefixed byte arrays.
//!
//! ## What stayed in Kotlin
//!
//! This module owns bytes and files; it does not own Java objects. Turning a record into a
//! `KeyPair`, `SecretKey`, `Certificate` chain and `KeyGenParameters` — and back — needs the
//! platform providers, and the owner-identity check needs the live keystore fingerprint. Those
//! stay in `PersistenceManager`, which is now a thin codec over these entry points.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use ring::digest::{digest, SHA256};

use crate::error::{CertGenError, Result};
use crate::wire::{malformed, Cursor, Encoder};

/// Current record layout. Written for every new record.
pub const FORMAT_VERSION: u8 = 4;
/// Pre-owner-identity layout. Accepted on load, never written.
pub const LEGACY_FORMAT_VERSION: u8 = 3;
/// Hard ceiling for one record file; also the largest blob the loader will read into memory.
pub const MAX_RECORD_BYTES: usize = 16 * 1024 * 1024;
/// Keystore aliases are short; anything longer is a corrupt record or an attack.
pub const MAX_ALIAS_LENGTH: usize = 4096;
/// Ceiling for a single key/chain/metadata blob inside a record.
pub const MAX_BLOB_BYTES: usize = 8 * 1024 * 1024;
/// A persisted chain is the leaf plus intermediates; 64 is far above any real chain.
pub const MAX_CHAIN_COUNT: usize = 64;
/// Ceiling for the integer parameter lists (purpose, digest, padding, ...).
pub const MAX_INT_LIST_COUNT: usize = 256;
/// `bootIdentity` is a boot id or start time rendered as text.
pub const MAX_BOOT_IDENTITY_LENGTH: usize = 256;
/// `SecretKey.getAlgorithm()` names are short identifiers.
pub const MAX_SECRET_ALGORITHM_LENGTH: usize = 128;
/// A DER-encoded RSA public exponent (3 bytes in practice).
pub const MAX_RSA_EXPONENT_BYTES: usize = 1024;
/// Owner identity fingerprints are SHA-256 digests.
pub const OWNER_FINGERPRINT_BYTES: usize = 32;

/// Directory the daemon persists into.
pub const DEFAULT_DIR: &str = "/data/adb/tricky_store/keys";

const TMP_SUFFIX: &str = ".tmp";

/// Remaining-use bookkeeping for a key with a usage limit.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UseState {
    pub lifetime_remaining: Option<i32>,
    pub per_boot_remaining: Option<i32>,
    pub boot_identity: Option<String>,
}

/// The `KeyGenParameters` fields a record has to round-trip.
///
/// Field-for-field with the Kotlin data holder, in the same order the disk format writes them; the
/// `Option` fields are the ones KeyMint may leave unset, and are stored with a presence byte.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyParams {
    pub algorithm: i32,
    pub key_size: i32,
    pub ec_curve: i32,
    pub purpose: Vec<i32>,
    pub digest: Vec<i32>,
    pub padding: Vec<i32>,
    pub block_mode: Vec<i32>,
    pub mgf_digest: Vec<i32>,
    pub usage_count_limit: i32,
    pub caller_nonce: Option<bool>,
    pub unlocked_device_required: Option<bool>,
    pub active_date_time: Option<i64>,
    pub origination_expire_date_time: Option<i64>,
    pub usage_expire_date_time: Option<i64>,
    pub no_auth_required: Option<bool>,
    pub origin: Option<i32>,
    pub rsa_public_exponent: Option<Vec<u8>>,
    pub max_uses_per_boot: i32,
    pub user_secure_ids: Vec<i64>,
    pub user_auth_type: Option<i32>,
    pub auth_timeout: Option<i32>,
    pub allow_while_on_body: Option<bool>,
    pub trusted_user_presence_required: Option<bool>,
    pub trusted_confirmation_required: Option<bool>,
    pub auth_policy_provenance: i32,
    pub created_at_ms: Option<i64>,
}

/// One persisted key, already parsed and validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub uid: i32,
    pub alias: String,
    pub security_level: i32,
    pub skip_leaf_hack: bool,
    pub nspace: i64,
    pub domain: i32,
    /// `(PKCS#8 private, X.509 public)` encoded key material.
    pub key_pair: Option<(Vec<u8>, Vec<u8>)>,
    /// `(algorithm, encoded secret)` for symmetric keys.
    pub secret_key: Option<(String, Vec<u8>)>,
    /// DER-encoded chain, leaf first.
    pub chain: Vec<Vec<u8>>,
    pub metadata: Option<Vec<u8>>,
    pub params: KeyParams,
    pub use_state: Option<UseState>,
    pub owner_identity_fingerprint: Option<Vec<u8>>,
}

/// Per-file failure while scanning the persistence directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadFailure {
    pub file_name: String,
    pub message: String,
}

/// Result of one directory scan.
///
/// A bad record never fails the whole load: it is reported here and skipped, which is what lets the
/// daemon start with the remaining keys instead of refusing to boot.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LoadOutcome {
    /// Canonical record blobs, each still prefixed with its source format version.
    pub records: Vec<Vec<u8>>,
    pub failures: Vec<LoadFailure>,
}

impl Record {
    /// Rejects anything that must not reach the disk.
    ///
    /// These are the invariants the reader depends on: a negative uid or an oversized alias has no
    /// valid path, negative counters would make the usage accounting meaningless, and a
    /// fingerprint of the wrong length would silently never match a real one.
    pub fn validate(&self) -> Result<()> {
        if self.uid < 0 {
            return Err(invalid("uid must not be negative"));
        }
        if self.alias.is_empty() {
            return Err(invalid("alias must not be empty"));
        }
        // Kotlin's `String.length` counts UTF-16 units, so the limit has to be applied the same way
        // or a record accepted by one side would be rejected by the other.
        if self.alias.encode_utf16().count() > MAX_ALIAS_LENGTH {
            return Err(invalid("alias exceeds the maximum length"));
        }
        if let Some(fingerprint) = &self.owner_identity_fingerprint {
            if fingerprint.len() != OWNER_FINGERPRINT_BYTES {
                return Err(invalid("owner identity fingerprint must be 32 bytes"));
            }
        }
        if let Some(UseState {
            lifetime_remaining,
            per_boot_remaining,
            boot_identity,
        }) = &self.use_state
        {
            if lifetime_remaining.is_some_and(|value| value < 0) {
                return Err(invalid("lifetime remaining must not be negative"));
            }
            if per_boot_remaining.is_some_and(|value| value < 0) {
                return Err(invalid("per-boot remaining must not be negative"));
            }
            if boot_identity
                .as_ref()
                .is_some_and(|id| id.encode_utf16().count() > MAX_BOOT_IDENTITY_LENGTH)
            {
                return Err(invalid("boot identity exceeds the maximum length"));
            }
        }
        if self.params.usage_count_limit < 0 || self.params.max_uses_per_boot < 0 {
            return Err(invalid("usage counters must not be negative"));
        }
        for list in [
            &self.params.purpose,
            &self.params.digest,
            &self.params.padding,
            &self.params.block_mode,
            &self.params.mgf_digest,
        ] {
            if list.len() > MAX_INT_LIST_COUNT {
                return Err(invalid("parameter list exceeds the maximum length"));
            }
        }
        if self.params.user_secure_ids.len() > MAX_INT_LIST_COUNT {
            return Err(invalid("secure id list exceeds the maximum length"));
        }
        if self.chain.len() > MAX_CHAIN_COUNT {
            return Err(invalid("certificate chain exceeds the maximum length"));
        }
        for der in &self.chain {
            check_blob_len(der.len(), 1, MAX_BLOB_BYTES, "certificate")?;
        }
        if let Some((private, public)) = &self.key_pair {
            check_blob_len(private.len(), 1, MAX_BLOB_BYTES, "private key")?;
            check_blob_len(public.len(), 1, MAX_BLOB_BYTES, "public key")?;
        }
        if let Some((algorithm, secret)) = &self.secret_key {
            if algorithm.encode_utf16().count() > MAX_SECRET_ALGORITHM_LENGTH {
                return Err(invalid("secret key algorithm exceeds the maximum length"));
            }
            check_blob_len(secret.len(), 1, MAX_BLOB_BYTES, "secret key")?;
        }
        if let Some(metadata) = &self.metadata {
            check_blob_len(metadata.len(), 0, MAX_BLOB_BYTES, "metadata")?;
        }
        if let Some(exponent) = &self.params.rsa_public_exponent {
            check_blob_len(
                exponent.len(),
                1,
                MAX_RSA_EXPONENT_BYTES,
                "rsa public exponent",
            )?;
        }
        Ok(())
    }

    /// Serializes with the given format version; `FORMAT_VERSION` for anything new.
    ///
    /// A version-3 record is only produced when a version-3 record was read, so that the caller can
    /// still see on disk (and report) that the key predates owner identity binding. Version 3 has
    /// no `maxUsesPerBoot`/secure-id/auth-policy block: those were derived from `usageCountLimit`
    /// by the reader, so writing them back would corrupt the record.
    pub fn encode(&self, version: u8) -> Result<Vec<u8>> {
        self.validate()?;
        if version != FORMAT_VERSION && version != LEGACY_FORMAT_VERSION {
            return Err(invalid("refusing to write an unknown record version"));
        }
        let mut out = Vec::with_capacity(512);
        out.push(version);
        put_i32(&mut out, self.uid);
        put_mutf8(&mut out, &self.alias)?;
        put_i32(&mut out, self.security_level);
        put_bool(&mut out, self.skip_leaf_hack);
        put_i64(&mut out, self.nspace);
        put_i32(&mut out, self.domain);
        match &self.key_pair {
            Some((private, public)) => {
                put_bool(&mut out, true);
                put_blob(&mut out, private)?;
                put_blob(&mut out, public)?;
            }
            None => put_bool(&mut out, false),
        }
        match &self.secret_key {
            Some((algorithm, secret)) => {
                put_bool(&mut out, true);
                put_mutf8(&mut out, algorithm)?;
                put_blob(&mut out, secret)?;
            }
            None => put_bool(&mut out, false),
        }
        put_i32(&mut out, self.chain.len() as i32);
        for der in &self.chain {
            put_blob(&mut out, der)?;
        }
        match &self.metadata {
            Some(metadata) => {
                put_bool(&mut out, true);
                put_blob(&mut out, metadata)?;
            }
            None => put_bool(&mut out, false),
        }
        let params = &self.params;
        put_i32(&mut out, params.algorithm);
        put_i32(&mut out, params.key_size);
        put_i32(&mut out, params.ec_curve);
        put_int_list(&mut out, &params.purpose)?;
        put_int_list(&mut out, &params.digest)?;
        put_int_list(&mut out, &params.padding)?;
        put_int_list(&mut out, &params.block_mode)?;
        put_int_list(&mut out, &params.mgf_digest)?;
        put_i32(&mut out, params.usage_count_limit);
        put_opt_bool(&mut out, params.caller_nonce);
        put_opt_bool(&mut out, params.unlocked_device_required);
        put_opt_i64(&mut out, params.active_date_time);
        put_opt_i64(&mut out, params.origination_expire_date_time);
        put_opt_i64(&mut out, params.usage_expire_date_time);
        put_opt_bool(&mut out, params.no_auth_required);
        put_opt_i32(&mut out, params.origin);
        match &params.rsa_public_exponent {
            Some(exponent) => {
                put_bool(&mut out, true);
                put_blob(&mut out, exponent)?;
            }
            None => put_bool(&mut out, false),
        }
        if version >= FORMAT_VERSION {
            put_i32(&mut out, params.max_uses_per_boot);
            put_i32(&mut out, params.user_secure_ids.len() as i32);
            for id in &params.user_secure_ids {
                put_i64(&mut out, *id);
            }
            put_opt_i32(&mut out, params.user_auth_type);
            put_opt_i32(&mut out, params.auth_timeout);
            put_opt_bool(&mut out, params.allow_while_on_body);
            put_opt_bool(&mut out, params.trusted_user_presence_required);
            put_opt_bool(&mut out, params.trusted_confirmation_required);
            put_i32(&mut out, params.auth_policy_provenance);
            put_opt_i64(&mut out, params.created_at_ms);
            put_opt_i32(
                &mut out,
                self.use_state
                    .as_ref()
                    .and_then(|state| state.lifetime_remaining),
            );
            put_opt_i32(
                &mut out,
                self.use_state
                    .as_ref()
                    .and_then(|state| state.per_boot_remaining),
            );
            match self
                .use_state
                .as_ref()
                .and_then(|state| state.boot_identity.as_ref())
            {
                Some(identity) => {
                    put_bool(&mut out, true);
                    put_mutf8(&mut out, identity)?;
                }
                None => put_bool(&mut out, false),
            }
            match &self.owner_identity_fingerprint {
                Some(fingerprint) => {
                    put_bool(&mut out, true);
                    out.extend_from_slice(fingerprint);
                }
                None => put_bool(&mut out, false),
            }
        }
        if out.len() > MAX_RECORD_BYTES {
            return Err(invalid("record exceeds the maximum size"));
        }
        Ok(out)
    }

    /// Parses a record file. Returns the record and the format version it was written with.
    pub fn decode(bytes: &[u8]) -> Result<(Self, u8)> {
        if bytes.is_empty() {
            return Err(malformed("record is empty"));
        }
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(malformed("record exceeds the maximum size"));
        }
        let mut cur = Cursor::new(bytes);
        let version = cur.u8()?;
        if version != FORMAT_VERSION && version != LEGACY_FORMAT_VERSION {
            return Err(invalid(&format!("unsupported record format {version}")));
        }
        let uid = cur.i32()?;
        if uid < 0 {
            return Err(malformed("negative uid"));
        }
        let alias = read_mutf8(&mut cur)?;
        if alias.is_empty() || alias.encode_utf16().count() > MAX_ALIAS_LENGTH {
            return Err(malformed("alias outside the accepted length"));
        }
        let security_level = cur.i32()?;
        let skip_leaf_hack = cur.bool()?;
        let nspace = cur.i64()?;
        let domain = cur.i32()?;
        let key_pair = if cur.bool()? {
            let private = take_blob(&mut cur, 1, MAX_BLOB_BYTES, "private key")?;
            let public = take_blob(&mut cur, 1, MAX_BLOB_BYTES, "public key")?;
            Some((private, public))
        } else {
            None
        };
        let secret_key = if cur.bool()? {
            let algorithm = read_mutf8(&mut cur)?;
            if algorithm.encode_utf16().count() > MAX_SECRET_ALGORITHM_LENGTH {
                return Err(malformed("secret key algorithm exceeds the maximum length"));
            }
            let secret = take_blob(&mut cur, 1, MAX_BLOB_BYTES, "secret key")?;
            Some((algorithm, secret))
        } else {
            None
        };
        let chain_count = cur.i32()?;
        if !(0..=MAX_CHAIN_COUNT as i32).contains(&chain_count) {
            return Err(malformed(
                "certificate chain count outside the accepted range",
            ));
        }
        let mut chain = Vec::with_capacity(chain_count as usize);
        for _ in 0..chain_count {
            chain.push(take_blob(&mut cur, 1, MAX_BLOB_BYTES, "certificate")?);
        }
        let metadata = if cur.bool()? {
            Some(take_blob(&mut cur, 0, MAX_BLOB_BYTES, "metadata")?)
        } else {
            None
        };
        let mut params = KeyParams {
            algorithm: cur.i32()?,
            key_size: cur.i32()?,
            ec_curve: cur.i32()?,
            purpose: cur.i32_vec()?,
            digest: cur.i32_vec()?,
            padding: cur.i32_vec()?,
            block_mode: cur.i32_vec()?,
            mgf_digest: cur.i32_vec()?,
            usage_count_limit: cur.i32()?,
            caller_nonce: cur.optional_bool()?,
            unlocked_device_required: cur.optional_bool()?,
            active_date_time: cur.optional_i64()?,
            origination_expire_date_time: cur.optional_i64()?,
            usage_expire_date_time: cur.optional_i64()?,
            no_auth_required: cur.optional_bool()?,
            origin: cur.optional_i32()?,
            ..KeyParams::default()
        };
        params.rsa_public_exponent = if cur.bool()? {
            Some(take_blob(
                &mut cur,
                1,
                MAX_RSA_EXPONENT_BYTES,
                "rsa public exponent",
            )?)
        } else {
            None
        };
        // Both branches below assign this exactly once, so no placeholder initial value is needed.
        let use_state;
        let mut owner_identity_fingerprint = None;
        if version >= FORMAT_VERSION {
            params.max_uses_per_boot = cur.i32()?;
            if params.max_uses_per_boot < 0 {
                return Err(malformed("negative per-boot usage limit"));
            }
            let secure_id_count = cur.i32()?;
            if !(0..=MAX_INT_LIST_COUNT as i32).contains(&secure_id_count) {
                return Err(malformed("secure id count outside the accepted range"));
            }
            params.user_secure_ids = Vec::with_capacity(secure_id_count as usize);
            for _ in 0..secure_id_count {
                params.user_secure_ids.push(cur.i64()?);
            }
            params.user_auth_type = cur.optional_i32()?;
            params.auth_timeout = cur.optional_i32()?;
            params.allow_while_on_body = cur.optional_bool()?;
            params.trusted_user_presence_required = cur.optional_bool()?;
            params.trusted_confirmation_required = cur.optional_bool()?;
            params.auth_policy_provenance = cur.i32()?;
            params.created_at_ms = cur.optional_i64()?;
            let lifetime_remaining = cur.optional_i32()?;
            let per_boot_remaining = cur.optional_i32()?;
            let boot_identity = if cur.bool()? {
                let identity = read_mutf8(&mut cur)?;
                if identity.encode_utf16().count() > MAX_BOOT_IDENTITY_LENGTH {
                    return Err(malformed("boot identity exceeds the maximum length"));
                }
                Some(identity)
            } else {
                None
            };
            use_state = Some(UseState {
                lifetime_remaining,
                per_boot_remaining,
                boot_identity,
            });
            if cur.bool()? {
                let fingerprint = cur.take_bytes(OWNER_FINGERPRINT_BYTES)?.to_vec();
                owner_identity_fingerprint = Some(fingerprint);
            }
        } else {
            // Format 3 predates per-boot limits and owner binding; the reader used to synthesize a
            // zeroed use state from `usageCountLimit`, and it still has to, or every legacy key
            // would come back with an exhausted budget.
            use_state = Some(UseState {
                lifetime_remaining: if params.usage_count_limit > 0 {
                    Some(0)
                } else {
                    None
                },
                per_boot_remaining: if params.usage_count_limit > 0 {
                    Some(0)
                } else {
                    None
                },
                boot_identity: None,
            });
        }
        if !cur.is_at_end() {
            return Err(malformed("trailing bytes after the record"));
        }
        let record = Record {
            uid,
            alias,
            security_level,
            skip_leaf_hack,
            nspace,
            domain,
            key_pair,
            secret_key,
            chain,
            metadata,
            params,
            use_state,
            owner_identity_fingerprint,
        };
        record.validate()?;
        Ok((record, version))
    }
}

/// Where the record for `alias` owned by `uid` lives.
///
/// The alias is hashed rather than used as a file name: aliases come from untrusted apps and can
/// contain `/`, `..`, or be long enough to exceed `NAME_MAX`. SHA-256 hex is a fixed 64 characters.
pub fn record_path(dir: &Path, uid: i32, alias: &str) -> Result<PathBuf> {
    if uid < 0 {
        return Err(invalid("uid must not be negative"));
    }
    if alias.is_empty() {
        return Err(invalid("alias must not be empty"));
    }
    Ok(PathBuf::from(dir)
        .join(uid.to_string())
        .join(format!("{}.bin", alias_fingerprint(alias))))
}

/// Lower-case hex SHA-256 of the alias, the record's file stem.
pub fn alias_fingerprint(alias: &str) -> String {
    let digest = digest(&SHA256, alias.as_bytes());
    let mut out = String::with_capacity(64);
    for byte in digest.as_ref() {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Validates `blob` and writes it durably as the record it describes.
///
/// The blob is parsed first: it must be a complete, well-formed record of a known version whose
/// `uid`/`alias` are usable as a path. It is then re-encoded so exactly one canonical byte sequence
/// can exist for a given record — two encoders can never disagree about what is on disk.
///
/// The write itself is crash-safe: `chmod 0600` on the temporary file before any secret is written,
/// `fsync` it, `rename` it over the target, then `fsync` the directory. Until the rename the old
/// record is intact; after it, the new record is durable.
pub fn persist(dir: &Path, blob: &[u8]) -> Result<()> {
    let (record, version) = Record::decode(blob)?;
    let canonical = record.encode(version)?;
    persist_record(dir, &record, &canonical)
}

fn persist_record(dir: &Path, record: &Record, bytes: &[u8]) -> Result<()> {
    let file = record_path(dir, record.uid, &record.alias)?;
    let parent = file
        .parent()
        .ok_or_else(|| invalid("persistence path has no parent directory"))?
        .to_path_buf();
    fs::create_dir_all(&parent).map_err(io_error)?;
    set_mode(&parent, 0o700)?;
    let tmp = PathBuf::from(format!("{}{TMP_SUFFIX}", file.display()));
    let written = write_tmp(&tmp, bytes).and_then(|()| {
        set_mode(&parent, 0o700)?;
        fs::rename(&tmp, &file).map_err(io_error)?;
        sync_dir(&parent)
    });
    if written.is_err() {
        // Leaving a partial `.tmp` behind would be harmless but it would also never be cleaned up,
        // and the next successful write reuses the same name anyway.
        let _ = fs::remove_file(&tmp);
    }
    written
}

fn write_tmp(tmp: &Path, bytes: &[u8]) -> Result<()> {
    let mut handle = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(tmp)
        .map_err(io_error)?;
    // Set the mode before the payload is written so the secret is never readable by another uid,
    // not even for the window between `write` and a later `chmod`.
    set_mode(tmp, 0o600)?;
    handle.write_all(bytes).map_err(io_error)?;
    handle.flush().map_err(io_error)?;
    handle.sync_all().map_err(io_error)
}

/// Removes the record for `(uid, alias)`, if any, and makes the removal durable.
pub fn delete(dir: &Path, uid: i32, alias: &str) -> Result<()> {
    let file = record_path(dir, uid, alias)?;
    if file.exists() {
        fs::remove_file(&file).map_err(io_error)?;
        if let Some(parent) = file.parent() {
            sync_dir(parent)?;
        }
    }
    Ok(())
}

/// Reads every `.bin` record under `dir`.
///
/// A record that fails to parse is reported in `failures` and skipped: one corrupt file must not
/// stop the daemon from serving the other keys. Directories and other files are ignored.
pub fn load(dir: &Path) -> LoadOutcome {
    let mut outcome = LoadOutcome::default();
    let mut files = Vec::new();
    collect_records(dir, &mut files);
    // Deterministic order: the caller logs and applies these in sequence, and a stable order makes
    // the boot log comparable between runs.
    files.sort();
    for path in files {
        match load_one(&path) {
            Ok(blob) => outcome.records.push(blob),
            Err(err) => outcome.failures.push(LoadFailure {
                file_name: path
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                message: err.to_string(),
            }),
        }
    }
    outcome
}

fn load_one(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::metadata(path).map_err(io_error)?;
    if !metadata.is_file() {
        return Err(invalid("not a regular file"));
    }
    let length = metadata.len();
    if length == 0 || length > MAX_RECORD_BYTES as u64 {
        return Err(invalid(&format!(
            "record is {length} bytes, outside 1..={MAX_RECORD_BYTES}"
        )));
    }
    let expected =
        usize::try_from(length).map_err(|_| invalid("record size does not fit in memory"))?;
    let mut bytes = Vec::with_capacity(expected);
    File::open(path)
        .map_err(io_error)?
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() != expected {
        // Short reads on a regular file mean it changed under us; the record can't be trusted.
        return Err(invalid("record changed while it was being read"));
    }
    let (record, version) = Record::decode(&bytes)?;
    // Re-encode for the same reason `persist` does: hand back the canonical form, not whatever
    // bytes happened to be on disk.
    record.encode(version)
}

fn collect_records(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        match entry.file_type() {
            Ok(kind) if kind.is_dir() => collect_records(&path, out),
            Ok(kind) if kind.is_file() => {
                if path.extension().and_then(|ext| ext.to_str()) == Some("bin") {
                    out.push(path);
                }
            }
            _ => {}
        }
    }
}

/// Builds the loader response: `[u32 ok]{ [bytes blob] }[u32 failed]{ [text name][text message] }`.
pub fn encode_load_outcome(outcome: &LoadOutcome, encoder: &mut Encoder) {
    encoder.u32(outcome.records.len() as u32);
    for blob in &outcome.records {
        encoder.bytes(blob);
    }
    encoder.u32(outcome.failures.len() as u32);
    for failure in &outcome.failures {
        encoder.text(&failure.file_name);
        encoder.text(&failure.message);
    }
}

fn check_blob_len(len: usize, min: usize, max: usize, what: &str) -> Result<()> {
    if len < min || len > max {
        return Err(invalid(&format!(
            "{what} is {len} bytes, outside {min}..={max}"
        )));
    }
    Ok(())
}

fn invalid(message: &str) -> CertGenError {
    CertGenError::InvalidParameter(message.to_string())
}

fn io_error(error: std::io::Error) -> CertGenError {
    CertGenError::SerializationFailed(format!("persistence io: {error}"))
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(io_error)
}

/// `fsync`s a directory so a `rename`/`unlink` inside it survives a power loss.
///
/// Directories are opened read-only and `fsync`ed through their file descriptor; on Linux that is
/// the only way to force the directory entry itself to disk.
fn sync_dir(dir: &Path) -> Result<()> {
    let handle = File::open(dir).map_err(io_error)?;
    handle.sync_all().map_err(io_error)
}

fn put_bool(out: &mut Vec<u8>, value: bool) {
    out.push(value as u8);
}

fn put_i32(out: &mut Vec<u8>, value: i32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_i64(out: &mut Vec<u8>, value: i64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_blob(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    if bytes.len() > i32::MAX as usize {
        return Err(invalid("blob is too large to length-prefix"));
    }
    put_i32(out, bytes.len() as i32);
    out.extend_from_slice(bytes);
    Ok(())
}

fn put_int_list(out: &mut Vec<u8>, values: &[i32]) -> Result<()> {
    if values.len() > MAX_INT_LIST_COUNT {
        return Err(invalid("parameter list exceeds the maximum length"));
    }
    put_i32(out, values.len() as i32);
    for value in values {
        put_i32(out, *value);
    }
    Ok(())
}

fn put_opt_i32(out: &mut Vec<u8>, value: Option<i32>) {
    match value {
        Some(inner) => {
            put_bool(out, true);
            put_i32(out, inner);
        }
        None => put_bool(out, false),
    }
}

fn put_opt_i64(out: &mut Vec<u8>, value: Option<i64>) {
    match value {
        Some(inner) => {
            put_bool(out, true);
            put_i64(out, inner);
        }
        None => put_bool(out, false),
    }
}

fn put_opt_bool(out: &mut Vec<u8>, value: Option<bool>) {
    match value {
        Some(inner) => {
            put_bool(out, true);
            put_bool(out, inner);
        }
        None => put_bool(out, false),
    }
}

/// Writes `DataOutputStream.writeUTF`'s encoding: a two-byte big-endian length followed by modified
/// UTF-8.
///
/// Modified UTF-8 differs from the standard form in exactly two places, and both matter for byte
/// compatibility with existing records: U+0000 is written as `C0 80` (never a bare NUL), and
/// characters outside the BMP are written as their UTF-16 surrogate pair, three bytes each.
fn put_mutf8(out: &mut Vec<u8>, text: &str) -> Result<()> {
    let mut encoded = Vec::with_capacity(text.len());
    let mut units = [0u16; 2];
    for character in text.chars() {
        for unit in character.encode_utf16(&mut units) {
            let unit = *unit;
            match unit {
                0x0000 => encoded.extend_from_slice(&[0xC0, 0x80]),
                0x0001..=0x007F => encoded.push(unit as u8),
                0x0080..=0x07FF => {
                    encoded.push(0xC0 | ((unit >> 6) as u8));
                    encoded.push(0x80 | ((unit & 0x3F) as u8));
                }
                _ => {
                    encoded.push(0xE0 | ((unit >> 12) as u8));
                    encoded.push(0x80 | (((unit >> 6) & 0x3F) as u8));
                    encoded.push(0x80 | ((unit & 0x3F) as u8));
                }
            }
        }
    }
    if encoded.len() > u16::MAX as usize {
        return Err(invalid("string is too long for a two-byte length prefix"));
    }
    out.extend_from_slice(&(encoded.len() as u16).to_be_bytes());
    out.extend_from_slice(&encoded);
    Ok(())
}

fn read_mutf8(cur: &mut Cursor<'_>) -> Result<String> {
    let length = ((cur.u8()? as usize) << 8) | cur.u8()? as usize;
    let bytes = cur.take_bytes(length)?;
    let mut units: Vec<u16> = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let first = bytes[index];
        let (unit, width) = match first {
            0x00 => return Err(malformed("raw NUL byte in a modified UTF-8 string")),
            0x01..=0x7F => (first as u16, 1),
            0xC0..=0xDF => {
                let second = *bytes
                    .get(index + 1)
                    .ok_or_else(|| malformed("truncated modified UTF-8 string"))?;
                if second & 0xC0 != 0x80 {
                    return Err(malformed(
                        "invalid continuation byte in a modified UTF-8 string",
                    ));
                }
                ((((first as u16) & 0x1F) << 6) | ((second as u16) & 0x3F), 2)
            }
            0xE0..=0xEF => {
                let second = *bytes
                    .get(index + 1)
                    .ok_or_else(|| malformed("truncated modified UTF-8 string"))?;
                let third = *bytes
                    .get(index + 2)
                    .ok_or_else(|| malformed("truncated modified UTF-8 string"))?;
                if second & 0xC0 != 0x80 || third & 0xC0 != 0x80 {
                    return Err(malformed(
                        "invalid continuation byte in a modified UTF-8 string",
                    ));
                }
                (
                    (((first as u16) & 0x0F) << 12)
                        | (((second as u16) & 0x3F) << 6)
                        | ((third as u16) & 0x3F),
                    3,
                )
            }
            _ => return Err(malformed("invalid lead byte in a modified UTF-8 string")),
        };
        units.push(unit);
        index += width;
    }
    // Java decodes to UTF-16 and combines surrogate pairs itself; `from_utf16` does the same, but
    // rejects a lone surrogate, which `readUTF` would happily accept.
    String::from_utf16(&units)
        .map_err(|_| malformed("unpaired surrogate in a modified UTF-8 string"))
}

fn take_blob(cur: &mut Cursor<'_>, min: usize, max: usize, what: &str) -> Result<Vec<u8>> {
    let length = cur.i32()?;
    if length < 0 {
        return Err(malformed(&format!("negative {what} length")));
    }
    check_blob_len(length as usize, min, max, what)?;
    Ok(cur.take_bytes(length as usize)?.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record() -> Record {
        Record {
            uid: 10123,
            alias: "android_key".to_string(),
            security_level: 1,
            skip_leaf_hack: false,
            nspace: 7,
            domain: 0,
            key_pair: Some((vec![0x30, 0x01, 0x02], vec![0x30, 0x03, 0x04])),
            secret_key: Some(("AES".to_string(), vec![9, 9, 9])),
            chain: vec![vec![0xAA, 0xBB], vec![0xCC]],
            metadata: Some(vec![1, 2, 3]),
            params: KeyParams {
                algorithm: 1,
                key_size: 2048,
                ec_curve: -1,
                purpose: vec![2, 4],
                digest: vec![4],
                padding: vec![1],
                block_mode: vec![],
                mgf_digest: vec![4],
                usage_count_limit: 10,
                caller_nonce: Some(true),
                unlocked_device_required: Some(false),
                active_date_time: Some(1_700_000_000_000),
                origination_expire_date_time: Some(1_800_000_000_000),
                usage_expire_date_time: None,
                no_auth_required: Some(true),
                origin: Some(0),
                rsa_public_exponent: Some(vec![0x01, 0x00, 0x01]),
                max_uses_per_boot: 5,
                user_secure_ids: vec![1, 2],
                user_auth_type: Some(2),
                auth_timeout: Some(30),
                allow_while_on_body: Some(true),
                trusted_user_presence_required: Some(false),
                trusted_confirmation_required: Some(true),
                auth_policy_provenance: 1,
                created_at_ms: Some(1_710_000_000_000),
            },
            use_state: Some(UseState {
                lifetime_remaining: Some(9),
                per_boot_remaining: Some(4),
                boot_identity: Some("boot-42".to_string()),
            }),
            owner_identity_fingerprint: Some(vec![7u8; OWNER_FINGERPRINT_BYTES]),
        }
    }

    #[test]
    fn a_record_round_trips_through_the_disk_format() {
        let record = sample_record();
        let bytes = record.encode(FORMAT_VERSION).expect("encode");
        let (decoded, version) = Record::decode(&bytes).expect("decode");
        assert_eq!(version, FORMAT_VERSION);
        assert_eq!(decoded, record);
    }

    #[test]
    fn every_optional_field_survives_a_round_trip_when_unset() {
        let mut record = sample_record();
        record.key_pair = None;
        record.secret_key = None;
        record.metadata = None;
        record.chain.clear();
        record.use_state = None;
        record.owner_identity_fingerprint = None;
        record.params.caller_nonce = None;
        record.params.unlocked_device_required = None;
        record.params.active_date_time = None;
        record.params.origination_expire_date_time = None;
        record.params.usage_expire_date_time = None;
        record.params.no_auth_required = None;
        record.params.origin = None;
        record.params.rsa_public_exponent = None;
        record.params.user_auth_type = None;
        record.params.auth_timeout = None;
        record.params.allow_while_on_body = None;
        record.params.trusted_user_presence_required = None;
        record.params.trusted_confirmation_required = None;
        record.params.created_at_ms = None;
        let bytes = record.encode(FORMAT_VERSION).expect("encode");
        let (decoded, _) = Record::decode(&bytes).expect("decode");
        // A v4 file always carries the three use-state slots, so an unset state comes back as a
        // present-but-empty state rather than `None`: that is what the Kotlin reader builds too.
        record.use_state = Some(UseState {
            lifetime_remaining: None,
            per_boot_remaining: None,
            boot_identity: None,
        });
        assert_eq!(decoded, record);
    }

    #[test]
    fn a_legacy_record_is_read_with_a_zeroed_use_state() {
        // Version 3 files have no use-state block at all: the reader has to synthesize one, or a
        // key with a usage limit would come back with an exhausted budget.
        let mut record = sample_record();
        record.use_state = None;
        record.owner_identity_fingerprint = None;
        let bytes = record.encode(LEGACY_FORMAT_VERSION).expect("encode");
        let (decoded, version) = Record::decode(&bytes).expect("decode");
        assert_eq!(version, LEGACY_FORMAT_VERSION);
        assert_eq!(
            decoded.use_state,
            Some(UseState {
                lifetime_remaining: Some(0),
                per_boot_remaining: Some(0),
                boot_identity: None,
            })
        );
        assert_eq!(decoded.owner_identity_fingerprint, None);
    }

    #[test]
    fn a_legacy_record_without_a_usage_limit_has_no_use_state_budget() {
        let mut record = sample_record();
        record.use_state = None;
        record.owner_identity_fingerprint = None;
        record.params.usage_count_limit = 0;
        let bytes = record.encode(LEGACY_FORMAT_VERSION).expect("encode");
        let (decoded, _) = Record::decode(&bytes).expect("decode");
        assert_eq!(
            decoded.use_state,
            Some(UseState {
                lifetime_remaining: None,
                per_boot_remaining: None,
                boot_identity: None,
            })
        );
    }

    #[test]
    fn an_unknown_format_version_is_refused() {
        let mut bytes = sample_record().encode(FORMAT_VERSION).expect("encode");
        bytes[0] = 99;
        let err = Record::decode(&bytes).expect_err("version 99 must be rejected");
        assert!(
            err.to_string().contains("unsupported record format"),
            "{err}"
        );
    }

    #[test]
    fn trailing_bytes_are_refused() {
        let mut bytes = sample_record().encode(FORMAT_VERSION).expect("encode");
        bytes.push(0);
        let err = Record::decode(&bytes).expect_err("trailing byte must be rejected");
        assert!(err.to_string().contains("trailing bytes"), "{err}");
    }

    #[test]
    fn a_truncated_record_is_refused_at_the_field_that_is_missing() {
        let bytes = sample_record().encode(FORMAT_VERSION).expect("encode");
        // Cut inside the chain: the reader must stop at the length it cannot satisfy rather than
        // reading whatever follows in the buffer.
        let truncated = &bytes[..bytes.len() - 40];
        let err = Record::decode(truncated).expect_err("truncated record must be rejected");
        assert!(err.to_string().contains("malformed request"), "{err}");
    }

    #[test]
    fn an_oversized_alias_is_refused_before_it_reaches_a_path() {
        let mut record = sample_record();
        record.alias = "a".repeat(MAX_ALIAS_LENGTH + 1);
        let err = record
            .encode(FORMAT_VERSION)
            .expect_err("alias must be rejected");
        assert!(err.to_string().contains("alias"), "{err}");
    }

    #[test]
    fn a_negative_uid_is_refused() {
        let mut record = sample_record();
        record.uid = -1;
        assert!(record.encode(FORMAT_VERSION).is_err());
    }

    #[test]
    fn an_owner_fingerprint_of_the_wrong_length_is_refused() {
        let mut record = sample_record();
        record.owner_identity_fingerprint = Some(vec![1, 2, 3]);
        let err = record
            .encode(FORMAT_VERSION)
            .expect_err("fingerprint length must be enforced");
        assert!(err.to_string().contains("32 bytes"), "{err}");
    }

    #[test]
    fn modified_utf8_matches_what_dataoutputstream_writes() {
        // U+0000 becomes C0 80 and U+1F600 becomes its surrogate pair, three bytes each: this is the
        // exact difference between modified UTF-8 and the standard form.
        let mut out = Vec::new();
        put_mutf8(&mut out, "a\u{0}b\u{1F600}").expect("encode");
        assert_eq!(
            out,
            vec![0x00, 0x0A, b'a', 0xC0, 0x80, b'b', 0xED, 0xA0, 0xBD, 0xED, 0xB8, 0x80]
        );
    }

    #[test]
    fn modified_utf8_round_trips_including_nul_and_astral_characters() {
        let text = "a\u{0}b\u{1F600}ünïcode";
        let mut out = Vec::new();
        put_mutf8(&mut out, text).expect("encode");
        let mut cur = Cursor::new(&out);
        assert_eq!(read_mutf8(&mut cur).expect("decode"), text);
    }

    #[test]
    fn a_raw_nul_byte_is_rejected_as_modified_utf8() {
        let blob = [0x00, 0x01, 0x00];
        let mut cur = Cursor::new(&blob);
        assert!(read_mutf8(&mut cur).is_err());
    }

    #[test]
    fn the_record_path_is_the_sha256_of_the_alias_under_the_uid_directory() {
        let path = record_path(Path::new(DEFAULT_DIR), 1000, "my alias").expect("path");
        // sha256("my alias")
        assert_eq!(
            path,
            PathBuf::from(DEFAULT_DIR)
                .join("1000")
                .join("778352de8d186e5e2dc02fc7e9a4708b60630779ef1739e9fc77e6f29a96333c.bin")
        );
    }

    #[test]
    fn a_saved_record_loads_back_and_can_be_deleted() {
        let dir = temp_dir("round-trip");
        let record = sample_record();
        persist_record(
            &dir,
            &record,
            &record.encode(FORMAT_VERSION).expect("encode"),
        )
        .expect("persist");
        let outcome = load(&dir);
        assert!(outcome.failures.is_empty(), "{:?}", outcome.failures);
        assert_eq!(outcome.records.len(), 1);
        let (loaded, version) = Record::decode(&outcome.records[0]).expect("decode");
        assert_eq!(version, FORMAT_VERSION);
        assert_eq!(loaded, record);
        // The written file must not be world-readable.
        use std::os::unix::fs::PermissionsExt;
        let path = record_path(&dir, record.uid, &record.alias).expect("path");
        let mode = fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "record file mode must be 0600");
        delete(&dir, record.uid, &record.alias).expect("delete");
        assert!(load(&dir).records.is_empty());
        // Deleting a record that is already gone is not an error: the daemon retries deletes.
        delete(&dir, record.uid, &record.alias).expect("second delete must succeed");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_corrupt_record_is_reported_and_skipped_without_failing_the_load() {
        let dir = temp_dir("corrupt");
        let good = sample_record();
        persist_record(&dir, &good, &good.encode(FORMAT_VERSION).expect("encode"))
            .expect("persist");
        let bad = dir.join(good.uid.to_string()).join("deadbeef.bin");
        fs::write(&bad, b"not a record").expect("write");
        let outcome = load(&dir);
        assert_eq!(outcome.records.len(), 1, "the good record must still load");
        assert_eq!(outcome.failures.len(), 1);
        assert_eq!(outcome.failures[0].file_name, "deadbeef.bin");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_empty_record_file_is_reported_as_a_failure() {
        let dir = temp_dir("empty");
        let bad = dir.join("1000").join("empty.bin");
        fs::create_dir_all(bad.parent().expect("parent")).expect("mkdirs");
        fs::write(&bad, b"").expect("write");
        let outcome = load(&dir);
        assert!(outcome.records.is_empty());
        assert_eq!(outcome.failures.len(), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn persist_rejects_a_blob_that_is_not_a_record() {
        let dir = temp_dir("invalid-persist");
        let err = persist(&dir, b"garbage").expect_err("garbage must be refused");
        assert!(
            err.to_string().contains("unsupported record format"),
            "{err}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn persist_accepts_a_well_formed_blob_and_stores_the_canonical_form() {
        let dir = temp_dir("canonical");
        let record = sample_record();
        let blob = record.encode(FORMAT_VERSION).expect("encode");
        persist(&dir, &blob).expect("persist");
        let outcome = load(&dir);
        assert_eq!(outcome.records.len(), 1);
        assert_eq!(outcome.records[0], blob);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_load_outcome_wire_layout_reports_records_then_failures() {
        let outcome = LoadOutcome {
            records: vec![vec![1, 2, 3]],
            failures: vec![LoadFailure {
                file_name: "x.bin".to_string(),
                message: "boom".to_string(),
            }],
        };
        let mut encoder = Encoder::new();
        encode_load_outcome(&outcome, &mut encoder);
        let blob = encoder.into_vec();
        let mut cur = Cursor::new(&blob);
        assert_eq!(cur.u32().expect("count"), 1);
        assert_eq!(cur.length_prefixed().expect("record"), vec![1, 2, 3]);
        assert_eq!(cur.u32().expect("failure count"), 1);
        assert_eq!(cur.length_prefixed().expect("name"), b"x.bin".to_vec());
        assert_eq!(cur.length_prefixed().expect("message"), b"boom".to_vec());
        assert!(cur.is_at_end());
    }

    /// A directory unique to one test, so the suite can run its file tests in parallel.
    fn temp_dir(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "certgen-persist-{label}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("temp dir");
        dir
    }
}
