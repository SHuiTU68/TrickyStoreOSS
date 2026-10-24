//! Attestation application id (AAID) assembly and the `unique_id` derivation.
//!
//! Kotlin keeps the `PackageManager` traversal — there is no way to enumerate a uid's packages
//! from the native side without going back through JNI — but everything after that is pure byte
//! work, so it lives here: the RFC 5280 §4.2.1.13 container (a SEQUENCE of two SET OFs) and the
//! HMAC-SHA256 unique id derived from it.
//!
//! The caller hands over the packages already reduced to what the container needs: name bytes,
//! version code, and the SHA-256 digests of each signing certificate. Duplicate digests are
//! collapsed by the caller, since it is the only side that can key them.

use crate::error::{CertGenError, Result};
use crate::wire::{malformed, Cursor};

use ring::hmac;

/// One package entry: the name, its version code, and the digests of its signing certificates.
/// The two `SET OF`s the container holds order their elements by encoding, so the digests are
/// sorted by the writer rather than preserved in the order the caller saw them.
#[derive(Debug, PartialEq, Eq)]
pub struct PackageEntry {
    pub name: Vec<u8>,
    pub version_code: i64,
    pub signature_digests: Vec<Vec<u8>>,
}

/// One entry costs at least `4 + 8 + 4` bytes on the wire (empty name, version code, no
/// signatures), so a count larger than `remaining / 16` cannot be honest. The bound is checked
/// before any allocation so a bogus count cannot make the decoder reserve memory.
const MIN_ENTRY_BYTES: usize = 16;

/// Builds the DER attestation application id from an encoded package list.
///
/// Wire layout (big-endian, matching [`crate::wire::Encoder`]):
///
/// ```text
/// u32 entry count
/// per entry:
///   [u32 len][name bytes]
///   i64 version code
///   u32 signature count
///   per signature: [u32 len][sha-256 digest]
/// ```
pub fn build_application_id(request: &[u8]) -> Result<Vec<u8>> {
    let entries = decode(request)?;
    Ok(assemble(&entries))
}

/// Decodes the package list, rejecting a truncated field, a count the payload cannot hold, or
/// trailing bytes so a malformed request is never partially interpreted.
fn decode(data: &[u8]) -> Result<Vec<PackageEntry>> {
    let mut cursor = Cursor::new(data);
    let count = cursor.u32()? as usize;
    let capacity = cursor.remaining() / MIN_ENTRY_BYTES;
    if count > capacity {
        return Err(malformed("package count exceeds the request payload"));
    }

    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let name = cursor.length_prefixed()?;
        let version_code = cursor.i64()?;
        let signature_count = cursor.u32()? as usize;
        // A digest is at least one byte long on the wire, so the remaining bytes bound the count.
        if signature_count > cursor.remaining() / 4 {
            return Err(malformed("signature count exceeds the request payload"));
        }
        let mut signature_digests = Vec::with_capacity(signature_count);
        for _ in 0..signature_count {
            signature_digests.push(cursor.length_prefixed()?);
        }
        entries.push(PackageEntry {
            name,
            version_code,
            signature_digests,
        });
    }

    if !cursor.is_at_end() {
        return Err(malformed("trailing bytes in application id request"));
    }
    Ok(entries)
}

/// Wraps the decoded entries in the two-level container:
/// `SEQUENCE { SET OF SEQUENCE { OCTET STRING name, INTEGER version }, SET OF OCTET STRING sig }`.
fn assemble(entries: &[PackageEntry]) -> Vec<u8> {
    let mut packages = Vec::with_capacity(entries.len());
    let mut digests = Vec::new();
    for entry in entries {
        let name = crate::certbuilder::encode_der_octet_string(&entry.name);
        let version = encode_version_code(entry.version_code);
        packages.push(crate::certbuilder::encode_der_sequence_of(&[name, version]));
        for digest in &entry.signature_digests {
            digests.push(crate::certbuilder::encode_der_octet_string(digest));
        }
    }
    sort_by_encoding(&mut packages);
    sort_by_encoding(&mut digests);
    // The `SET OF` signatures must not repeat, so a signer shared by two packages — or a signing
    // history listing the same certificate twice — contributes one digest. Sorting first puts the
    // duplicates next to each other.
    digests.dedup();

    let package_set = crate::certbuilder::encode_der_set_slices(&packages);
    let digest_set = crate::certbuilder::encode_der_set_slices(&digests);
    crate::certbuilder::encode_der_sequence_of(&[package_set, digest_set])
}

/// Encodes a `longVersionCode` as a DER INTEGER: two's complement, minimal length, with a single
/// padding byte when dropping a redundant sign byte would flip the sign.
fn encode_version_code(value: i64) -> Vec<u8> {
    let raw = value.to_be_bytes();
    let mut start = 0;
    if value >= 0 {
        while start < 7 && raw[start] == 0x00 {
            start += 1;
        }
        let content = &raw[start..];
        // A positive integer whose first byte has the high bit set would read as negative.
        if content[0] & 0x80 != 0 {
            let mut padded = Vec::with_capacity(1 + content.len());
            padded.push(0x00);
            padded.extend_from_slice(content);
            return crate::certbuilder::encode_der_tag_length_value(0x02, &padded);
        }
        crate::certbuilder::encode_der_tag_length_value(0x02, content)
    } else {
        while start < 7 && raw[start] == 0xFF {
            start += 1;
        }
        let content = &raw[start..];
        if content[0] & 0x80 == 0 {
            let mut padded = Vec::with_capacity(1 + content.len());
            padded.push(0xFF);
            padded.extend_from_slice(content);
            return crate::certbuilder::encode_der_tag_length_value(0x02, &padded);
        }
        crate::certbuilder::encode_der_tag_length_value(0x02, content)
    }
}

/// DER `SET OF` orders its elements by their full encodings compared as unsigned bytes, with the
/// shorter encoding sorting first when one is a prefix of the other.
fn sort_by_encoding(items: &mut [Vec<u8>]) {
    items.sort_by(|a, b| {
        let common = a.len().min(b.len());
        match a[..common].cmp(&b[..common]) {
            std::cmp::Ordering::Equal => a.len().cmp(&b.len()),
            other => other,
        }
    });
}

/// The `unique_id` the KeyMint spec derives from the aaik: HMAC-SHA256 over
/// `[temporal counter i64 BE][application id DER][0x00]`, truncated to its first 16 bytes.
///
/// The counter advances every 30 days, so a key minted later gets a different unique id while
/// staying stable for keys minted in the same window.
pub fn compute_unique_id(
    creation_time_ms: i64,
    application_id_der: &[u8],
    key: &[u8],
) -> Result<Vec<u8>> {
    if key.is_empty() {
        return Err(CertGenError::InvalidParameter(
            "unique id key must not be empty".to_string(),
        ));
    }
    let temporal_counter = creation_time_ms / 2_592_000_000;
    let mut message = Vec::with_capacity(8 + application_id_der.len() + 1);
    message.extend_from_slice(&temporal_counter.to_be_bytes());
    message.extend_from_slice(application_id_der);
    message.push(0x00);

    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    Ok(hmac::sign(&key, &message).as_ref()[..16].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Encoder;

    fn request(entries: &[(Vec<u8>, i64, Vec<Vec<u8>>)]) -> Vec<u8> {
        let mut encoder = Encoder::new();
        encoder.u32(entries.len() as u32);
        for (name, version, digests) in entries {
            encoder.bytes(name);
            // `Encoder::bytes` prefixes a length, so the raw version code is written as two u32 halves.
            encoder.u32((version >> 32) as u32);
            encoder.u32(*version as u32);
            encoder.u32(digests.len() as u32);
            for digest in digests {
                encoder.bytes(digest);
            }
        }
        encoder.into_vec()
    }

    #[test]
    fn builds_an_empty_container_for_an_empty_request() {
        let der = build_application_id(&request(&[])).expect("empty request builds");
        // SEQUENCE { SET OF {} , SET OF {} }
        assert_eq!(der, vec![0x30, 0x04, 0x31, 0x00, 0x31, 0x00]);
    }

    #[test]
    fn packages_and_digests_are_order_independent() {
        let one = request(&[
            (b"com.example.b".to_vec(), 2, vec![vec![0xBB; 4]]),
            (b"com.example.a".to_vec(), 1, vec![vec![0xAA; 4]]),
        ]);
        let two = request(&[
            (b"com.example.a".to_vec(), 1, vec![vec![0xAA; 4]]),
            (b"com.example.b".to_vec(), 2, vec![vec![0xBB; 4]]),
        ]);
        assert_eq!(
            build_application_id(&one).expect("builds"),
            build_application_id(&two).expect("builds")
        );
    }

    #[test]
    fn a_digest_shared_by_two_packages_is_written_once() {
        let shared = vec![0xAA; 4];
        let der = build_application_id(&request(&[
            (b"com.example.a".to_vec(), 1, vec![shared.clone()]),
            (b"com.example.b".to_vec(), 2, vec![shared.clone(), shared]),
        ]))
        .expect("builds");

        // All three digests are the same, so the trailing `SET OF OCTET STRING` holds one entry:
        // `31 06 04 04 AA AA AA AA`.
        let digest_set = [0x31, 0x06, 0x04, 0x04, 0xAA, 0xAA, 0xAA, 0xAA];
        assert_eq!(&der[der.len() - digest_set.len()..], &digest_set[..]);
    }

    #[test]
    fn a_package_entry_is_a_sequence_of_name_and_version() {
        let der = build_application_id(&request(&[(b"a".to_vec(), 1, vec![])])).expect("builds");
        // SEQUENCE { SET { SEQUENCE { OCTET STRING "a", INTEGER 1 } }, SET {} }
        assert_eq!(
            der,
            vec![
                0x30, 0x0C, 0x31, 0x08, 0x30, 0x06, 0x04, 0x01, b'a', 0x02, 0x01, 0x01, 0x31, 0x00,
            ]
        );
    }

    #[test]
    fn positive_version_codes_gain_a_padding_byte_when_the_high_bit_is_set() {
        // 0x80 would read as -128 without the padding, and the leading zeros are stripped.
        assert_eq!(encode_version_code(0x80), vec![0x02, 0x02, 0x00, 0x80]);
        assert_eq!(encode_version_code(0), vec![0x02, 0x01, 0x00]);
        assert_eq!(encode_version_code(127), vec![0x02, 0x01, 0x7F]);
        assert_eq!(encode_version_code(128), vec![0x02, 0x02, 0x00, 0x80]);
        assert_eq!(
            encode_version_code(i64::MAX),
            vec![0x02, 0x08, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        );
    }

    #[test]
    fn negative_version_codes_keep_their_sign_in_one_byte() {
        assert_eq!(encode_version_code(-1), vec![0x02, 0x01, 0xFF]);
        assert_eq!(encode_version_code(-128), vec![0x02, 0x01, 0x80]);
        // -129 needs an extra 0xFF so the leading byte does not read as positive.
        assert_eq!(encode_version_code(-129), vec![0x02, 0x02, 0xFF, 0x7F]);
        assert_eq!(
            encode_version_code(i64::MIN),
            vec![0x02, 0x08, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn a_count_the_payload_cannot_hold_is_rejected() {
        let mut encoder = Encoder::new();
        encoder.u32(4);
        assert!(build_application_id(&encoder.into_vec()).is_err());
    }

    #[test]
    fn truncated_entries_are_rejected() {
        // Claims one entry but supplies no bytes for it.
        assert!(build_application_id(&[0, 0, 0, 1]).is_err());
        // Name present, version code cut short.
        let mut encoder = Encoder::new();
        encoder.u32(1);
        encoder.bytes(b"pkg");
        assert!(build_application_id(&encoder.into_vec()).is_err());
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut blob = request(&[(b"a".to_vec(), 1, vec![])]);
        blob.push(0x00);
        assert!(build_application_id(&blob).is_err());
    }

    #[test]
    fn unique_id_is_sixteen_bytes_and_stable_for_the_same_inputs() {
        let key = [0x42u8; 32];
        let der = build_application_id(&request(&[(b"a".to_vec(), 1, vec![])])).expect("builds");
        let first = compute_unique_id(1_700_000_000_000, &der, &key).expect("derived");
        let second = compute_unique_id(1_700_000_000_000, &der, &key).expect("derived");
        assert_eq!(first.len(), 16);
        assert_eq!(first, second);
    }

    #[test]
    fn unique_id_changes_with_the_key_and_with_the_application_id() {
        let der = build_application_id(&request(&[(b"a".to_vec(), 1, vec![])])).expect("builds");
        let other_der =
            build_application_id(&request(&[(b"b".to_vec(), 1, vec![])])).expect("builds");
        let base = compute_unique_id(1_700_000_000_000, &der, &[0x01; 32]).expect("derived");
        assert_ne!(
            base,
            compute_unique_id(1_700_000_000_000, &der, &[0x02; 32]).expect("derived")
        );
        assert_ne!(
            base,
            compute_unique_id(1_700_000_000_000, &other_der, &[0x01; 32]).expect("derived")
        );
    }

    #[test]
    fn unique_id_counter_advances_in_thirty_day_steps() {
        let der = build_application_id(&request(&[(b"a".to_vec(), 1, vec![])])).expect("builds");
        let key = [0x11u8; 32];
        let month = 2_592_000_000i64;
        let start = compute_unique_id(0, &der, &key).expect("derived");
        // Anything inside the same 30-day window shares the counter, and therefore the id.
        assert_eq!(
            start,
            compute_unique_id(month - 1, &der, &key).expect("derived")
        );
        // Crossing the boundary moves the counter, so the id changes.
        assert_ne!(
            start,
            compute_unique_id(month, &der, &key).expect("derived")
        );
    }

    #[test]
    fn an_empty_key_is_rejected() {
        assert!(compute_unique_id(0, &[0x30, 0x00], &[]).is_err());
    }
}
