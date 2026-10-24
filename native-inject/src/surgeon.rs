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
    let Some(config) = CONFIG.get() else {
        crate::probe::mark("surgeon: no config installed");
        return None;
    };
    let Some((range, certificates, encoding)) = find_certificate_array(reply) else {
        crate::probe::mark(&format!("surgeon: no chain found in {} bytes", reply.len()));
        return None;
    };
    crate::probe::mark(&format!(
        "surgeon: chain of {} cert(s) at {:?} as {:?}",
        certificates.len(),
        range,
        encoding
    ));
    let Some(replacement) = resign_chain(config, &certificates, encoding) else {
        crate::probe::mark("surgeon: resign failed");
        return None;
    };
    if let Some((_, again)) = parse_chain(&replacement, encoding) {
        crate::probe::mark(&format!(
            "surgeon: replacement holds {} cert(s) of {:?} bytes",
            again.len(),
            again.iter().map(|c| c.len()).collect::<Vec<_>>()
        ));
    } else {
        crate::probe::mark("surgeon: replacement does not parse");
    }
    let enclosing_sizes = enclosing_size_words(reply, &range);
    crate::probe::mark(&format!(
        "surgeon: replacement {} bytes, totals at {:?}",
        replacement.len(),
        enclosing_sizes
    ));
    Some(ReplyRewrite {
        range,
        replacement,
        enclosing_sizes,
    })
}

/// Re-signs the leaf and re-encodes the chain as a parcel fragment.
fn resign_chain(
    config: &RuntimeConfig,
    certificates: &[Vec<u8>],
    encoding: ChainEncoding,
) -> Option<Vec<u8>> {
    let leaf = certificates.first()?;
    let request = encode_request(config, leaf);
    // `certgen` owns the DER work and returns leaf-first concatenated DER. It validates that the
    // leaf really carries a KeyMint attestation extension, which is why a candidate chain that is
    // structurally valid but is not an attestation leaf ends up here as `None`.
    let chain = certgen::hack_leaf::hack_certificate_chain_blob(&request).ok()?;
    let resigned = split_der_chain(&chain)?;
    Some(encode_certificate_array(&resigned, encoding))
}

/// How the reply frames the `Certificate[]` it carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainEncoding {
    /// `int32 count`, then `count` length-prefixed DER structures.
    Plain,
    /// `int32 count`, `int32 total`, then the elements; `total` is self-inclusive.
    Sized,
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
pub fn find_certificate_array(reply: &[u8]) -> Option<(Range<usize>, Vec<Vec<u8>>, ChainEncoding)> {
    let lowest = reply.len().saturating_sub(SCAN_WINDOW);
    let last = reply.len().checked_sub(4)?;
    for start in (lowest..last).rev() {
        // The sized framing is tried first: a plain parse of the same bytes would read the total
        // as the first certificate's length and reject itself, but there is no reason to pay for
        // that attempt when the leading dialect is the one this device speaks.
        for encoding in [ChainEncoding::Sized, ChainEncoding::Plain] {
            let Some((consumed, certificates)) = parse_chain(&reply[start..], encoding) else {
                continue;
            };
            // At most three bytes of padding may follow the array: four or more would be another
            // field, and a reply with a field after the chain is not one whose layout we
            // understand.
            if reply.len() - (start + consumed) <= 3 {
                return Some((start..reply.len(), certificates, encoding));
            }
        }
    }
    None
}

/// Parses `int32 count` followed by `count` length-prefixed DER certificates.
///
/// `Sized` adds a second `int32` in front of the elements: the byte count of everything after it
/// *plus its own four bytes*. KeyMint on this device writes the chain that way -- a single EC
/// leaf arrives as `01 00 00 00 | cc 02 00 00 | c4 02 00 00 | 30 82 02 c0 ...`, i.e. one
/// certificate, a total of 716 that covers the 712 bytes behind it and itself, then the DER.
///
/// Returns the number of bytes the array occupies, header included; the caller decides whether
/// the padding that follows is acceptable.
fn parse_chain(data: &[u8], encoding: ChainEncoding) -> Option<(usize, Vec<Vec<u8>>)> {
    let count = read_i32(data, 0)?;
    if !(1..=MAX_CERTIFICATES).contains(&count) {
        return None;
    }
    let declared_total = match encoding {
        ChainEncoding::Plain => None,
        ChainEncoding::Sized => {
            let total = read_i32(data, 4)?;
            if total < 8 {
                return None;
            }
            Some(total as usize)
        }
    };
    let mut position = match encoding {
        ChainEncoding::Plain => 4usize,
        ChainEncoding::Sized => 8usize,
    };
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
    if let Some(declared_total) = declared_total {
        // Self-inclusive: the total is the elements plus the four bytes holding the total.
        if declared_total != position.checked_sub(4)? {
            return None;
        }
    }
    Some((position, certificates))
}

/// Reads a little-endian `i32` at `offset`, or `None` when it does not fit.
///
/// Little-endian because that is what a binder parcel is: `libbinder` writes `int32` through a
/// native-endian copy, and every Android ABI this runs on is little-endian. Reading the reply's
/// counters big-endian was why a chain of one certificate was never recognised.
fn read_i32(data: &[u8], offset: usize) -> Option<i32> {
    let bytes = data.get(offset..offset.checked_add(4)?)?;
    let bytes: [u8; 4] = bytes.try_into().ok()?;
    Some(i32::from_le_bytes(bytes))
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
fn encode_certificate_array(certificates: &[Vec<u8>], encoding: ChainEncoding) -> Vec<u8> {
    let mut elements = Vec::new();
    for certificate in certificates {
        elements.extend_from_slice(&(certificate.len() as i32).to_le_bytes());
        elements.extend_from_slice(certificate);
        while elements.len() % 4 != 0 {
            elements.push(0);
        }
    }
    let mut out = Vec::with_capacity(elements.len() + 8);
    out.extend_from_slice(&(certificates.len() as i32).to_le_bytes());
    if encoding == ChainEncoding::Sized {
        out.extend_from_slice(&((elements.len() + 4) as i32).to_le_bytes());
    }
    out.extend_from_slice(&elements);
    out
}

/// Offsets of the self-inclusive `int32` totals that enclose `range`.
///
/// The reply frames its payload with counts that include their own four bytes -- the outermost one
/// of a `generateKey` answer reads `1568` for the 1576-byte parcel. Those totals sit in front of
/// the chain, so a longer or shorter chain has to move them by the same amount, and leaving one
/// behind would hand `keystore2` a parcel whose sizes no longer add up.
fn enclosing_size_words(reply: &[u8], range: &Range<usize>) -> Vec<usize> {
    let limit = range.start.min(reply.len().saturating_sub(3));
    let mut offsets = Vec::new();
    for offset in 0..limit {
        if read_i32(reply, offset) == Some((reply.len() - offset) as i32) {
            offsets.push(offset);
        }
    }
    offsets
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

    /// A reply framed the way this device frames one: status, a presence word, a self-inclusive
    /// total for the payload, then key blob, characteristics and the sized chain.
    fn reply_with(certificates: &[Vec<u8>]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&64i32.to_le_bytes()); // key blob length
        body.extend(std::iter::repeat_n(0xAAu8, 64));
        body.extend_from_slice(&0i32.to_le_bytes()); // empty characteristics
        body.extend_from_slice(&encode_certificate_array(
            certificates,
            ChainEncoding::Sized,
        ));
        let mut reply = Vec::new();
        reply.extend_from_slice(&0i32.to_le_bytes()); // status
        reply.extend_from_slice(&1i32.to_le_bytes()); // presence word
        reply.extend_from_slice(&((body.len() + 4) as i32).to_le_bytes());
        reply.extend_from_slice(&body);
        reply
    }

    /// The same shape with the plain framing: `int32 count`, then the elements.
    fn plain_reply_with(certificates: &[Vec<u8>]) -> Vec<u8> {
        let mut reply = Vec::new();
        reply.extend_from_slice(&0i32.to_le_bytes());
        reply.extend_from_slice(&64i32.to_le_bytes());
        reply.extend(std::iter::repeat_n(0xAAu8, 64));
        reply.extend_from_slice(&0i32.to_le_bytes());
        reply.extend_from_slice(&encode_certificate_array(
            certificates,
            ChainEncoding::Plain,
        ));
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
        let (range, found, encoding) = find_certificate_array(&reply).expect("chain is found");
        assert_eq!(found, chain);
        assert_eq!(encoding, ChainEncoding::Sized);
        assert_eq!(range.end, reply.len());
    }

    #[test]
    fn a_reply_without_a_chain_is_left_alone() {
        let mut reply = Vec::new();
        reply.extend_from_slice(&0i32.to_le_bytes());
        reply.extend_from_slice(&16i32.to_le_bytes());
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
        reply.extend_from_slice(&2i32.to_le_bytes());
        reply.extend_from_slice(&16i32.to_le_bytes());
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
        reply.extend_from_slice(&1i32.to_le_bytes());
        reply.extend_from_slice(&(der.len() as i32).to_le_bytes());
        reply.extend_from_slice(&der);
        assert!(find_certificate_array(&reply).is_none());
    }

    #[test]
    fn an_encoded_array_round_trips_and_stays_aligned() {
        let chain = vec![certificate(9, 5), certificate(9, 6)];
        for encoding in [ChainEncoding::Plain, ChainEncoding::Sized] {
            let encoded = encode_certificate_array(&chain, encoding);
            assert_eq!(encoded.len() % 4, 0);
            let (consumed, parsed) = parse_chain(&encoded, encoding).expect("array parses");
            assert_eq!(consumed, encoded.len());
            assert_eq!(parsed, chain);
        }
    }

    #[test]
    fn a_concatenated_chain_splits_back_into_certificates() {
        let chain = vec![certificate(3, 120), certificate(4, 1)];
        let joined: Vec<u8> = chain.concat();
        assert_eq!(split_der_chain(&joined), Some(chain));
        assert_eq!(split_der_chain(&[]), None);
    }

    #[test]
    fn the_sized_framing_is_preferred_when_both_could_parse() {
        let chain = vec![certificate(4, 44)];
        let reply = reply_with(&chain);
        let (_, found, encoding) = find_certificate_array(&reply).expect("chain is found");
        assert_eq!(found, chain);
        assert_eq!(encoding, ChainEncoding::Sized);
    }

    #[test]
    fn the_plain_framing_is_still_understood() {
        let chain = vec![certificate(5, 12), certificate(6, 13)];
        let reply = plain_reply_with(&chain);
        let (range, found, encoding) = find_certificate_array(&reply).expect("chain is found");
        assert_eq!(found, chain);
        assert_eq!(encoding, ChainEncoding::Plain);
        assert_eq!(range.end, reply.len());
    }

    #[test]
    fn the_enclosing_totals_are_the_ones_that_cover_the_chain() {
        let reply = reply_with(&vec![certificate(8, 20)]);
        let (range, _, _) = find_certificate_array(&reply).expect("chain is found");
        // The payload total at offset 8 and the chain's own total are both self-inclusive; only the
        // first one is in front of the chain, so only that one is left for `rebuild` to move.
        assert_eq!(enclosing_size_words(&reply, &range), vec![8]);
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
