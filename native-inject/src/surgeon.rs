//! Certificate-chain surgery on a KeyMint `KeyCreationResult` reply.
//!
//! ## What is touched and what is not
//!
//! Patch mode changes exactly one field of the reply: the certificate chain. The `keyBlob`, the
//! `keyCharacteristics` and the fact that the TEE minted the key are all left alone, so a caller
//! that stores the blob and later asks the same TEE to use it sees an unmodified `keyBlob`.
//!
//! ## Why the reply is scanned instead of parsed forward
//!
//! `KeyCreationResult` is `{ keyBlob, keyCharacteristics[], certificateChain[] }`. Parsing it
//! forward means interpreting `KeyCharacteristics`, i.e. a `KeyParameter[]` whose values are a
//! union of several wire types. Getting that union's discriminant numbering wrong does not fail
//! loudly: it misaligns the cursor and produces a rewrite range that lands in the middle of a key
//! blob. Depending on a table of numbers we cannot check from here is the worse trade.
//!
//! What we rely on instead is weaker and verifiable: the chain is the *last* field of the reply.
//! So the search runs backwards from the end of the parcel over 4-byte-aligned offsets, and the
//! first candidate that parses as `int32 count`, then `count` length-prefixed DER structures whose
//! declared lengths match their own bytes, and that ends within three padding bytes of the end of
//! the parcel, wins. Every certificate must also be a complete `SEQUENCE`, which is a strong
//! enough shape check that a stray run of key-blob bytes cannot pass for a chain by accident.
//!
//! Anything that does not pass is a `None`, and the hook forwards the untouched reply. A missed
//! patch is a certificate that still describes the real device; a wrong patch is a corrupt parcel
//! inside a system service.
//!
//! ## Where the signing material comes from
//!
//! From the keybox, via [`RuntimeConfig`]. When no config has been installed the answer is always
//! `None`, so a payload that failed to receive its configuration is inert rather than broken.
use std::ops::Range;
use std::sync::OnceLock;

use crate::intercept::ReplyRewrite;

/// Longest tail of the reply that is scanned for the certificate array.
///
/// A chain of three 1 KB certificates, plus the key blob and the characteristics in front of it,
/// fits in a fraction of this. The window exists to keep the per-`generateKey` cost bounded on a
/// large reply, not to accommodate a realistic chain.
const SCAN_WINDOW: usize = 64 * 1024;

/// Sanity bound on the certificate count of a reply we are willing to rewrite.
const MAX_CERTIFICATES: i32 = 12;

/// ASN.1 `SEQUENCE`, the only tag a DER `Certificate` may start with.
const DER_SEQUENCE_TAG: u8 = 0x30;

/// OS version written into the patched `rootOfTrust`.
///
/// Android 14. The daemon overrides this from its own configuration; a fixed fallback keeps the
/// module usable when it does not, instead of writing `0` into the attestation record.
pub const DEFAULT_OS_VERSION: i32 = 140_000;

/// The keybox and the attestation fields used to re-sign a leaf.
pub struct RuntimeConfig {
    /// Keybox certificates, leaf first, concatenated DER.
    pub keybox_chain_der: Vec<u8>,
    /// Keybox signing key as PKCS#8 DER.
    pub keybox_private_key: Vec<u8>,
    /// `osVersion` to write into the attestation record.
    pub os_version: i32,
    /// Replacement for tag 706, or `None` to keep what the TEE reported.
    pub os_patch: Option<i32>,
    /// Replacement for tag 718, or `None` to keep what the TEE reported.
    pub vendor_patch: Option<i32>,
    /// Replacement for tag 719, or `None` to keep what the TEE reported.
    pub boot_patch: Option<i32>,
    /// `verifiedBootKey` for the forged root of trust.
    pub boot_key: Vec<u8>,
    /// `verifiedBootHash`; an empty value means "reuse the hash already in the original chain".
    pub boot_hash: Vec<u8>,
}

impl RuntimeConfig {
    /// Builds a config from a keybox XML document.
    ///
    /// The first EC entry is preferred: the leaf being re-signed carries an EC P-256 key on
    /// KeyMint devices, and re-signing it with an RSA keybox key would change the signature
    /// algorithm of a certificate whose public key stayed EC.
    pub fn from_keybox_xml(xml: &str) -> Option<Self> {
        let entries = certgen::keybox_xml::parse_keybox_xml(xml).ok()?;
        let entry = entries
            .iter()
            .find(|entry| entry.algorithm == "EC")
            .or_else(|| entries.first())?;
        let mut chain = Vec::new();
        for certificate in &entry.certificates {
            chain.extend_from_slice(certificate);
        }
        if chain.is_empty() || entry.private_key_pkcs8.is_empty() {
            return None;
        }
        Some(Self {
            keybox_chain_der: chain,
            keybox_private_key: entry.private_key_pkcs8.clone(),
            os_version: DEFAULT_OS_VERSION,
            os_patch: None,
            vendor_patch: None,
            boot_patch: None,
            // An all-zero key with `deviceLocked = true` is the "verified boot key not disclosed"
            // shape attestation parsers accept; an empty OCTET STRING is not, because the field is
            // 32 bytes wide in every consumer we care about.
            boot_key: vec![0u8; 32],
            boot_hash: Vec::new(),
        })
    }
}

/// The installed configuration. `None` means the hook is a no-op.
static CONFIG: OnceLock<RuntimeConfig> = OnceLock::new();

/// Installs the configuration. Returns `false` when one was already installed.
///
/// Install-once rather than replaceable on purpose: the config carries a private key, and a second
/// install would mean either dropping one key without wiping it or racing two of them.
pub fn install(config: RuntimeConfig) -> bool {
    CONFIG.set(config).is_ok()
}

/// True once a configuration has been installed.
pub fn is_installed() -> bool {
    CONFIG.get().is_some()
}

/// The rewrite for one reply, or `None` to keep the reply untouched.
pub fn plan_reply_rewrite(reply: &[u8]) -> Option<ReplyRewrite> {
    let config = CONFIG.get()?;
    let (range, certificates) = find_certificate_array(reply)?;
    let replacement = resign_chain(config, &certificates)?;
    Some(ReplyRewrite { range, replacement })
}

/// Re-signs the leaf and re-encodes the chain as a parcel fragment.
fn resign_chain(config: &RuntimeConfig, certificates: &[Vec<u8>]) -> Option<Vec<u8>> {
    let leaf = certificates.first()?;
    let request = encode_request(config, leaf);
    // `certgen` owns the DER work and returns leaf-first concatenated DER. It validates that the
    // leaf really carries a KeyMint attestation extension, which is why a candidate chain that is
    // structurally valid but is not an attestation leaf ends up here as `None`.
    let chain = certgen::hack_leaf::hack_certificate_chain_blob(&request).ok()?;
    let resigned = split_der_chain(&chain)?;
    Some(encode_certificate_array(&resigned))
}

/// Finds the trailing `Certificate[]` of the reply.
///
/// Returns the byte range to replace (the array plus the padding that follows it, so the result
/// stays 4-byte aligned) and the certificates it held.
///
/// The scan is byte-wise, not stride-four, and it walks backwards. Striking the array off a
/// 4-byte grid would be wrong twice over: the buffer `AParcel_marshal` hands back begins at the
/// parcel's data start, which is not necessarily the same alignment the writer used, and the
/// number of bytes in front of the chain depends on the key blob and the characteristics array,
/// both of which vary per key. What *is* fixed is that the chain is the last field, so the
/// candidates are checked from the right and the first one that parses to within the trailing
/// padding wins. A rejected candidate costs one big-endian count read.
pub fn find_certificate_array(reply: &[u8]) -> Option<(Range<usize>, Vec<Vec<u8>>)> {
    let lowest = reply.len().saturating_sub(SCAN_WINDOW);
    let last = reply.len().checked_sub(4)?;
    for start in (lowest..last).rev() {
        let Some((consumed, certificates)) = parse_certificate_array(&reply[start..]) else {
            continue;
        };
        // At most three bytes of padding may follow the array: four or more would be another
        // field, and a reply with a field after the chain is not one whose layout we understand.
        if reply.len() - (start + consumed) <= 3 {
            return Some((start..reply.len(), certificates));
        }
    }
    None
}

/// Parses `int32 count` followed by `count` length-prefixed DER certificates.
///
/// Returns the number of bytes the array occupies; the caller decides whether the padding that
/// follows is acceptable.
fn parse_certificate_array(data: &[u8]) -> Option<(usize, Vec<Vec<u8>>)> {
    let count = read_i32(data, 0)?;
    if !(1..=MAX_CERTIFICATES).contains(&count) {
        return None;
    }
    let mut position = 4usize;
    let mut certificates = Vec::new();
    for _ in 0..count {
        let length = read_i32(data, position)?;
        if length <= 0 {
            return None;
        }
        let start = position + 4;
        let end = start.checked_add(length as usize)?;
        let der = data.get(start..end)?;
        if der_total_length(der)? != der.len() {
            return None;
        }
        certificates.push(der.to_vec());
        // Each element is padded to a 4-byte boundary. The last one may end the parcel without its
        // padding, so clamp instead of rejecting.
        position = align4(end).min(data.len());
    }
    Some((position, certificates))
}

/// Reads a big-endian `i32` at `offset`, or `None` when it does not fit.
fn read_i32(data: &[u8], offset: usize) -> Option<i32> {
    let bytes = data.get(offset..offset.checked_add(4)?)?;
    let bytes: [u8; 4] = bytes.try_into().ok()?;
    Some(i32::from_be_bytes(bytes))
}

/// Rounds `value` up to the next multiple of four.
fn align4(value: usize) -> usize {
    (value + 3) & !3
}

/// Total length of the DER structure at the start of `der`, header included.
///
/// Only the `SEQUENCE` header is understood, because that is all a `Certificate` may start with
/// and all we need in order to walk a concatenated chain.
fn der_total_length(der: &[u8]) -> Option<usize> {
    if *der.first()? != DER_SEQUENCE_TAG {
        return None;
    }
    let first = *der.get(1)?;
    if first & 0x80 == 0 {
        return Some(2 + first as usize);
    }
    let count = (first & 0x7f) as usize;
    // Three bytes covers any chain that fits in a binder transaction; a fourth would also accept
    // a length that cannot be backed by a parcel, so it is rejected rather than tried.
    if count == 0 || count > 3 {
        return None;
    }
    let mut length = 0usize;
    for index in 0..count {
        length = (length << 8) | *der.get(2 + index)? as usize;
    }
    Some(2 + count + length)
}

/// Splits back-to-back DER `Certificate`s into one entry each.
fn split_der_chain(data: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut certificates = Vec::new();
    let mut offset = 0usize;
    while offset < data.len() {
        let rest = data.get(offset..)?;
        let total = der_total_length(rest)?;
        if total > rest.len() {
            return None;
        }
        certificates.push(rest[..total].to_vec());
        offset += total;
    }
    if certificates.is_empty() {
        None
    } else {
        Some(certificates)
    }
}

/// Encodes certificates the way the AIDL reply encodes `Certificate[]`.
///
/// Always a multiple of four bytes long, which is what keeps the rebuilt parcel aligned after a
/// replacement of a different length.
fn encode_certificate_array(certificates: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(certificates.len() as i32).to_be_bytes());
    for certificate in certificates {
        out.extend_from_slice(&(certificate.len() as i32).to_be_bytes());
        out.extend_from_slice(certificate);
        while out.len() % 4 != 0 {
            out.push(0);
        }
    }
    out
}

/// Packs the leaf-hack request blob.
///
/// Big-endian and length-prefixed to match `certgen::wire::Cursor`, the decoder on the other side;
/// a `None` for an optional field is a single presence byte.
fn encode_request(config: &RuntimeConfig, leaf: &[u8]) -> Vec<u8> {
    fn blob(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(bytes);
    }
    fn optional(out: &mut Vec<u8>, value: Option<i32>) {
        match value {
            Some(value) => {
                out.push(1);
                out.extend_from_slice(&(value as u32).to_be_bytes());
            }
            None => out.push(0),
        }
    }
    let mut out = Vec::new();
    blob(&mut out, leaf);
    blob(&mut out, &config.keybox_private_key);
    blob(&mut out, &config.keybox_chain_der);
    blob(&mut out, &config.boot_key);
    blob(&mut out, &config.boot_hash);
    out.extend_from_slice(&config.os_version.to_be_bytes());
    optional(&mut out, config.os_patch);
    optional(&mut out, config.vendor_patch);
    optional(&mut out, config.boot_patch);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stand-in certificate: a `SEQUENCE` whose declared length matches its content.
    fn certificate(seed: u8, content: usize) -> Vec<u8> {
        assert!(content < 0x80, "callers stay in the short length form");
        let mut der = vec![DER_SEQUENCE_TAG, content as u8];
        der.extend(std::iter::repeat_n(seed, content));
        der
    }

    /// A reply with a key blob and a characteristics array in front of the chain.
    fn reply_with(certificates: &[Vec<u8>]) -> Vec<u8> {
        let mut reply = Vec::new();
        reply.extend_from_slice(&0i32.to_be_bytes()); // status header
        reply.extend_from_slice(&64i32.to_be_bytes()); // key blob length
        reply.extend(std::iter::repeat_n(0xAAu8, 64));
        reply.extend_from_slice(&0i32.to_be_bytes()); // empty characteristics
        reply.extend_from_slice(&encode_certificate_array(certificates));
        reply
    }

    #[test]
    fn the_trailing_chain_is_found_after_an_unaligned_prefix() {
        let chain = vec![certificate(1, 40), certificate(2, 41), certificate(3, 42)];
        let mut reply = reply_with(&chain);
        // Shift the array off the 4-byte grid. Nothing in a parcel guarantees that the chain
        // starts at a multiple of four from the start of the buffer we were handed, so the
        // scan must not depend on it.
        reply.insert(5, 0xEE);
        let (range, found) = find_certificate_array(&reply).expect("chain is found");
        assert_eq!(found, chain);
        assert_eq!(range.end, reply.len());
    }

    #[test]
    fn a_reply_without_a_chain_is_left_alone() {
        let mut reply = Vec::new();
        reply.extend_from_slice(&0i32.to_be_bytes());
        reply.extend_from_slice(&16i32.to_be_bytes());
        reply.extend(std::iter::repeat_n(0xBBu8, 16));
        assert!(find_certificate_array(&reply).is_none());
    }

    #[test]
    fn a_chain_that_does_not_end_the_parcel_is_not_rewritten() {
        let chain = vec![certificate(7, 8)];
        let mut reply = reply_with(&chain);
        // Four trailing bytes are a field, not padding, so this reply is not one we understand.
        reply.extend_from_slice(&[0, 0, 0, 0]);
        assert!(find_certificate_array(&reply).is_none());
    }

    #[test]
    fn a_count_without_bytes_behind_it_is_rejected() {
        let mut reply = Vec::new();
        reply.extend_from_slice(&2i32.to_be_bytes());
        reply.extend_from_slice(&16i32.to_be_bytes());
        reply.extend(std::iter::repeat_n(0x30u8, 16));
        assert!(find_certificate_array(&reply).is_none());
    }

    #[test]
    fn a_der_length_that_lies_is_rejected() {
        // Declares 0x30 bytes of content but only carries two.
        let mut der = vec![DER_SEQUENCE_TAG, 0x30];
        der.extend_from_slice(&[1, 2]);
        assert_eq!(der_total_length(&der), Some(2 + 0x30));
        let mut reply = Vec::new();
        reply.extend_from_slice(&1i32.to_be_bytes());
        reply.extend_from_slice(&(der.len() as i32).to_be_bytes());
        reply.extend_from_slice(&der);
        assert!(find_certificate_array(&reply).is_none());
    }

    #[test]
    fn an_encoded_array_round_trips_and_stays_aligned() {
        let chain = vec![certificate(9, 5), certificate(9, 6)];
        let encoded = encode_certificate_array(&chain);
        assert_eq!(encoded.len() % 4, 0);
        let (consumed, parsed) = parse_certificate_array(&encoded).expect("array parses");
        assert_eq!(consumed, encoded.len());
        assert_eq!(parsed, chain);
    }

    #[test]
    fn a_concatenated_chain_splits_back_into_certificates() {
        let chain = vec![certificate(3, 120), certificate(4, 1)];
        let joined: Vec<u8> = chain.concat();
        assert_eq!(split_der_chain(&joined), Some(chain));
        assert_eq!(split_der_chain(&[]), None);
    }

    #[test]
    fn the_request_blob_puts_every_field_where_the_cursor_expects_it() {
        let config = RuntimeConfig {
            keybox_chain_der: vec![0xC1, 0xC2],
            keybox_private_key: vec![0xD1],
            os_version: 140_000,
            os_patch: Some(202503),
            vendor_patch: None,
            boot_patch: Some(-1),
            boot_key: vec![0u8; 32],
            boot_hash: Vec::new(),
        };
        let request = encode_request(&config, &[0x30, 0x00]);
        let mut cursor = certgen::wire::Cursor::new(&request);
        assert_eq!(cursor.length_prefixed().ok(), Some(vec![0x30, 0x00]));
        assert_eq!(cursor.length_prefixed().ok(), Some(vec![0xD1]));
        assert_eq!(cursor.length_prefixed().ok(), Some(vec![0xC1, 0xC2]));
        assert_eq!(cursor.length_prefixed().ok().map(|key| key.len()), Some(32));
        assert_eq!(cursor.length_prefixed().ok(), Some(Vec::new()));
        assert_eq!(cursor.i32().ok(), Some(140_000));
        assert_eq!(cursor.optional_i32().ok(), Some(Some(202503)));
        assert_eq!(cursor.optional_i32().ok(), Some(None));
        assert_eq!(cursor.optional_i32().ok(), Some(Some(-1)));
        assert!(cursor.is_at_end());
    }
}
