//! Native parsing of the KeyMint attestation extension on a probe certificate.
//!
//! The startup probe has the TEE mint an attested key and then reads the verified-boot data back
//! out of the returned leaf. This mirrors the Kotlin `AttestUtils.parseAttestationData` path — the
//! same field positions, the same challenge check and the same "missing extension means no data"
//! outcome — but reads the DER directly, so the probe no longer needs BouncyCastle's ASN.1 provider.

use crate::error::{CertGenError, Result};
use crate::tlv::{iter_tlvs, read_tlv, TAG_OCTET_STRING, TAG_SEQUENCE};
use crate::wire::{malformed, Cursor};

use const_oid::ObjectIdentifier;
use der::Decode;
use x509_cert::Certificate;

const ATTESTATION_OID_STR: &str = "1.3.6.1.4.1.11129.2.1.17";

/// Universal-class tag for an INTEGER, used by the `KeyDescription` version fields.
const TAG_INTEGER: u32 = 0x02;

/// The fields the probe reads back out of the attestation extension; mirrors the Kotlin
/// `AttestUtils.AttestationData`.
pub struct AttestationData {
    pub attest_version: i32,
    pub keymaster_version: i32,
    pub verified_boot_key: Option<Vec<u8>>,
    pub verified_boot_hash: Option<Vec<u8>>,
    pub os_version: Option<i32>,
    pub module_hash: Option<Vec<u8>>,
}

/// Parses the leaf named by a request blob and encodes the attested fields it carries as
/// `[i32 attestVersion][i32 keymasterVersion][opt blob verifiedBootKey][opt blob verifiedBootHash]
/// [opt i32 osVersion][opt blob moduleHash]`, all big-endian, each optional field led by a presence
/// byte. Kotlin rebuilds `AttestationData` from it.
///
/// The request is `[u32 certLen][certificate DER][u32 challengeLen][challenge]`; any malformed
/// input, a certificate without an attestation extension, or a challenge mismatch is an error so
/// the Kotlin caller falls back to BouncyCastle.
pub fn parse_attestation_blob(request: &[u8]) -> Result<Vec<u8>> {
    let mut cursor = Cursor::new(request);
    let certificate_der = cursor.length_prefixed()?;
    let expected_challenge = cursor.length_prefixed()?;
    if !cursor.is_at_end() {
        return Err(malformed("trailing bytes in attestation-parse request"));
    }

    let data = parse_attestation(&certificate_der, &expected_challenge)?;
    Ok(encode_attestation_data(&data))
}

fn parse_attestation(certificate_der: &[u8], expected_challenge: &[u8]) -> Result<AttestationData> {
    let certificate = Certificate::from_der(certificate_der)
        .map_err(|e| attest_error(format!("probe certificate parse: {e}")))?;
    let attest_oid: ObjectIdentifier = ATTESTATION_OID_STR
        .parse()
        .map_err(|_| attest_error("attestation OID parse"))?;
    let extensions = certificate
        .tbs_certificate
        .extensions
        .as_ref()
        .ok_or_else(|| attest_error("probe certificate has no extensions"))?;
    let extension = extensions
        .iter()
        .find(|e| e.extn_id == attest_oid)
        .ok_or_else(|| attest_error("probe certificate has no attestation extension"))?;

    let key_description = extension.extn_value.as_bytes();
    let (tag, content, _) = read_tlv(key_description)?;
    if tag != TAG_SEQUENCE {
        return Err(attest_error("attestation extension is not a SEQUENCE"));
    }
    let fields = iter_tlvs(content)?;
    if fields.len() < 8 {
        return Err(attest_error(format!(
            "KeyDescription has {} elements, expected 8",
            fields.len()
        )));
    }

    let attest_version = integer(fields[0])? as i32;
    let keymaster_version = integer(fields[2])? as i32;

    let challenge = octet_string(fields[4])?;
    if challenge != expected_challenge {
        return Err(attest_error("attestation challenge mismatch"));
    }

    // The TEE-enforced list carries the root of trust (tag 704) and the OS version (705).
    let mut verified_boot_key = None;
    let mut verified_boot_hash = None;
    let mut os_version = None;
    for field in iter_tlvs(sequence_content(fields[7])?)? {
        let (tag, inner, _) = read_tlv(field)?;
        match tag {
            704 => {
                let elements = iter_tlvs(sequence_content(inner)?)?;
                if elements.len() >= 4 {
                    verified_boot_key = Some(octet_string(elements[0])?);
                    verified_boot_hash = Some(octet_string(elements[3])?);
                }
            }
            705 => os_version = Some(integer(inner)? as i32),
            _ => {}
        }
    }

    // The software-enforced list carries the module hash (tag 724).
    let mut module_hash = None;
    for field in iter_tlvs(sequence_content(fields[6])?)? {
        let (tag, inner, _) = read_tlv(field)?;
        if tag == 724 {
            module_hash = Some(octet_string(inner)?);
        }
    }

    Ok(AttestationData {
        attest_version,
        keymaster_version,
        verified_boot_key,
        verified_boot_hash,
        os_version,
        module_hash,
    })
}

/// Reads a DER INTEGER as a signed value. Only the range the attestation fields use is accepted.
fn integer(data: &[u8]) -> Result<i64> {
    let (tag, content, _) = read_tlv(data)?;
    if tag != TAG_INTEGER {
        return Err(attest_error("attestation value is not an INTEGER"));
    }
    if content.is_empty() || content.len() > 8 {
        return Err(attest_error("attestation INTEGER is out of range"));
    }
    // Two's complement, big-endian: seed with the sign so sign-extension falls out of the shifts.
    let mut value: i64 = if content[0] & 0x80 != 0 { -1 } else { 0 };
    for &byte in content {
        value = (value << 8) | byte as i64;
    }
    Ok(value)
}

/// Reads a DER OCTET STRING's content.
fn octet_string(data: &[u8]) -> Result<Vec<u8>> {
    let (tag, content, _) = read_tlv(data)?;
    if tag != TAG_OCTET_STRING {
        return Err(attest_error("attestation value is not an OCTET STRING"));
    }
    Ok(content.to_vec())
}

/// Reads a DER SEQUENCE and returns its content bytes.
fn sequence_content(data: &[u8]) -> Result<&[u8]> {
    let (tag, content, _) = read_tlv(data)?;
    if tag != TAG_SEQUENCE {
        return Err(attest_error("attestation value is not a SEQUENCE"));
    }
    Ok(content)
}

fn encode_attestation_data(data: &AttestationData) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&data.attest_version.to_be_bytes());
    out.extend_from_slice(&data.keymaster_version.to_be_bytes());
    push_optional_blob(&mut out, data.verified_boot_key.as_deref());
    push_optional_blob(&mut out, data.verified_boot_hash.as_deref());
    push_optional_int(&mut out, data.os_version);
    push_optional_blob(&mut out, data.module_hash.as_deref());
    out
}

fn push_optional_blob(out: &mut Vec<u8>, value: Option<&[u8]>) {
    match value {
        Some(bytes) => {
            out.push(1);
            out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            out.extend_from_slice(bytes);
        }
        None => out.push(0),
    }
}

fn push_optional_int(out: &mut Vec<u8>, value: Option<i32>) {
    match value {
        Some(number) => {
            out.push(1);
            out.extend_from_slice(&number.to_be_bytes());
        }
        None => out.push(0),
    }
}

fn attest_error(message: impl Into<String>) -> CertGenError {
    CertGenError::CertBuildFailed(message.into())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // test assertions are allowed to unwrap
mod tests {
    use super::*;
    use crate::attestation::build_attestation_extension;
    use crate::certbuilder::{build_certificate_chain, build_self_signed_cert};
    use crate::keybox::parse_keybox;
    use crate::keygen::generate_key_pair;
    use crate::types::{Algorithm, CertGenParams, EcCurve};

    const CHALLENGE: &[u8] = &[0x11; 16];

    fn params() -> CertGenParams {
        CertGenParams {
            algorithm: Algorithm::Ec,
            key_size: 256,
            ec_curve: Some(EcCurve::P256),
            attestation_challenge: Some(CHALLENGE.to_vec()),
            purposes: vec![2],
            digests: vec![4],
            security_level: 1,
            attest_version: 400,
            keymaster_version: 41,
            os_version: 140000,
            os_patch_level: 202503,
            vendor_patch_level: 20250301,
            boot_patch_level: 20250301,
            boot_key: vec![0x01; 32],
            boot_hash: vec![0x02; 32],
            module_hash: Some(vec![0x33; 32]),
            creation_datetime: 1_709_913_600_000,
            caller_nonce: true,
            no_auth_required: true,
            ..Default::default()
        }
    }

    /// A keybox pair plus a leaf that carries the attestation extension for [`params`].
    fn leaf_with_attestation() -> Vec<u8> {
        let params = params();
        let ca_key = generate_key_pair(Algorithm::Ec, 256, Some(EcCurve::P256), 0).unwrap();
        let ca_cert = build_self_signed_cert(&ca_key, &params).unwrap();
        let keybox = parse_keybox(&ca_cert[0], &ca_key.private_key_pkcs8).unwrap();

        let leaf_key = generate_key_pair(Algorithm::Ec, 256, Some(EcCurve::P256), 0).unwrap();
        let key_description = build_attestation_extension(&params).unwrap();
        let chain = build_certificate_chain(&leaf_key, Some(&key_description), &keybox, &params).unwrap();
        chain[0].clone()
    }

    fn request(certificate: &[u8], challenge: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(certificate.len() as u32).to_be_bytes());
        out.extend_from_slice(certificate);
        out.extend_from_slice(&(challenge.len() as u32).to_be_bytes());
        out.extend_from_slice(challenge);
        out
    }

    /// Decodes the response blob the same way the Kotlin caller does.
    fn decode(blob: &[u8]) -> (i32, i32, Option<Vec<u8>>, Option<Vec<u8>>, Option<i32>, Option<Vec<u8>>) {
        let mut cursor = Cursor::new(blob);
        let attest_version = cursor.i32().unwrap();
        let keymaster_version = cursor.i32().unwrap();
        let verified_boot_key = optional_blob(&mut cursor);
        let verified_boot_hash = optional_blob(&mut cursor);
        let os_version = cursor.optional_i32().unwrap();
        let module_hash = optional_blob(&mut cursor);
        assert!(cursor.is_at_end(), "response must not have trailing bytes");
        (attest_version, keymaster_version, verified_boot_key, verified_boot_hash, os_version, module_hash)
    }

    /// Reads a presence byte then a length-prefixed blob, mirroring the encoder's optional format.
    fn optional_blob(cursor: &mut Cursor) -> Option<Vec<u8>> {
        cursor.bool().unwrap().then(|| cursor.length_prefixed().unwrap())
    }

    #[test]
    fn parses_the_attested_fields() {
        let leaf = leaf_with_attestation();
        let blob = parse_attestation_blob(&request(&leaf, CHALLENGE)).unwrap();
        let (attest_version, keymaster_version, boot_key, boot_hash, os_version, module_hash) = decode(&blob);

        assert_eq!(attest_version, 400);
        assert_eq!(keymaster_version, 41);
        assert_eq!(boot_key, Some(vec![0x01; 32]));
        assert_eq!(boot_hash, Some(vec![0x02; 32]));
        assert_eq!(os_version, Some(140000));
        assert_eq!(module_hash, Some(vec![0x33; 32]));
    }

    #[test]
    fn challenge_mismatch_is_rejected() {
        let leaf = leaf_with_attestation();
        assert!(parse_attestation_blob(&request(&leaf, &[0u8; 16])).is_err());
    }

    #[test]
    fn missing_attestation_extension_is_rejected() {
        let key = generate_key_pair(Algorithm::Ec, 256, Some(EcCurve::P256), 0).unwrap();
        let leaf = build_self_signed_cert(&key, &params()).unwrap();
        assert!(parse_attestation_blob(&request(&leaf[0], CHALLENGE)).is_err());
    }

    #[test]
    fn optional_fields_are_absent_on_a_bare_description() {
        // Drop the root of trust and module hash so the optionals come back as None.
        let mut params = params();
        params.boot_key = Vec::new();
        params.boot_hash = Vec::new();
        params.module_hash = None;
        let ca_key = generate_key_pair(Algorithm::Ec, 256, Some(EcCurve::P256), 0).unwrap();
        let ca_cert = build_self_signed_cert(&ca_key, &params).unwrap();
        let keybox = parse_keybox(&ca_cert[0], &ca_key.private_key_pkcs8).unwrap();
        let leaf_key = generate_key_pair(Algorithm::Ec, 256, Some(EcCurve::P256), 0).unwrap();
        let key_description = build_attestation_extension(&params).unwrap();
        let chain = build_certificate_chain(&leaf_key, Some(&key_description), &keybox, &params).unwrap();

        let blob = parse_attestation_blob(&request(&chain[0], CHALLENGE)).unwrap();
        let (_, _, boot_key, boot_hash, os_version, module_hash) = decode(&blob);
        // The root of trust still carries empty boot key/hash octet strings, so those stay Some.
        assert_eq!(boot_key, Some(Vec::new()));
        assert_eq!(boot_hash, Some(Vec::new()));
        assert_eq!(os_version, Some(140000));
        assert_eq!(module_hash, None);
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let leaf = leaf_with_attestation();
        let mut request = request(&leaf, CHALLENGE);
        request.push(0x00);
        assert!(parse_attestation_blob(&request).is_err());
    }
}
