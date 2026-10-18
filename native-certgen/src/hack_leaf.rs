//! Native leaf-certificate hack.
//!
//! The keybox path mints a brand-new leaf from scratch. The hack path instead keeps an existing
//! leaf — one the device's TEE already issued — and rewrites only the parts that leak hardware
//! state: the `rootOfTrust` (tag 704) inside the KeyMint attestation extension is replaced with a
//! forged verified-boot key/state/hash, and the patch-level fields (706/718/719) are overridden or
//! dropped per the per-package configuration. The leaf is then re-signed with the keybox key, so
//! the chain still verifies against the shipped keybox root.
//!
//! This mimics the Kotlin `CertificateHack.hackLeaf` path: it tolerates the Android 11 Keymasters
//! that swap `softwareEnforced`/`teeEnforced` (the tee list is found by looking for tag 704), it
//! sources the boot hash from the original root of trust when present and falls back to the caller
//! otherwise, and it re-sorts the rebuilt authorization list by tag number. Parsing is
//! hand-rolled over raw DER so the untouched fields are copied byte for byte.

use crate::attestation::{
    enc_boolean, enc_enumerated, enc_explicit_tag, enc_integer, enc_octet_string, enc_sequence,
};
use crate::certbuilder::{
    detect_ec_signing_algorithm, detect_signing_key_algorithm, encode_der_bit_string, encode_der_oid,
};
use crate::error::{CertGenError, Result};
use crate::keybox::{parse_keybox, ParsedKeybox};
use crate::tlv::{iter_tlvs, read_tlv, TAG_OCTET_STRING, TAG_SEQUENCE};
use crate::types::Algorithm;
use crate::wire::{malformed, Cursor};

use const_oid::ObjectIdentifier;
use der::{Decode, Encode};
use ring::rand::SystemRandom;
use ring::signature::EcdsaKeyPair;
use x509_cert::Certificate;

const ATTESTATION_OID_STR: &str = "1.3.6.1.4.1.11129.2.1.17";
const ATTESTATION_OID_COMPS: &[u64] = &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17];

/// The raw value the Kotlin patch-level config uses to mean "omit this tag entirely".
const DO_NOT_REPORT: i32 = -1;

const TAG_ROOT_OF_TRUST: u32 = 704;
const TAG_OS_VERSION: u32 = 705;
const TAG_OS_PATCHLEVEL: u32 = 706;
const TAG_VENDOR_PATCHLEVEL: u32 = 718;
const TAG_BOOT_PATCHLEVEL: u32 = 719;

/// Builds the hacked chain from a packed request blob and returns it as concatenated DER
/// certificates, leaf first (see the Kotlin encoder for the field layout).
pub fn hack_certificate_chain_blob(request: &[u8]) -> Result<Vec<u8>> {
    let req = HackRequest::decode(request)?;
    let keybox = parse_keybox(&req.signing_chain_der, &req.signing_private_key_pkcs8)?;

    let hacked_leaf = hack_leaf(&req, &keybox)?;

    let mut out = Vec::new();
    out.extend_from_slice(&hacked_leaf);
    for cert in &keybox.cert_chain_ders {
        out.extend_from_slice(cert);
    }
    Ok(out)
}

/// Rewrites the leaf's attestation extension and re-signs the leaf with the keybox key.
fn hack_leaf(req: &HackRequest, keybox: &ParsedKeybox) -> Result<Vec<u8>> {
    let leaf = Certificate::from_der(&req.leaf_cert_der)
        .map_err(|e| CertGenError::CertBuildFailed(format!("leaf cert parse: {e}")))?;

    let attest_oid: ObjectIdentifier = ATTESTATION_OID_STR
        .parse()
        .map_err(|_| CertGenError::CertBuildFailed("attestation OID parse".into()))?;
    let extensions = leaf
        .tbs_certificate
        .extensions
        .as_ref()
        .ok_or_else(|| CertGenError::CertBuildFailed("leaf has no extensions".into()))?;
    let attest_ext = extensions
        .iter()
        .find(|e| e.extn_id == attest_oid)
        .ok_or_else(|| CertGenError::CertBuildFailed("leaf has no attestation extension".into()))?;

    let new_keydesc = rebuild_key_description(attest_ext.extn_value.as_bytes(), req)?;
    let new_attest_ext = build_attestation_extension(&new_keydesc);

    // Every original extension except the attestation one is kept verbatim.
    let mut extensions_inner = Vec::new();
    extensions_inner.extend_from_slice(&new_attest_ext);
    for ext in extensions.iter() {
        if ext.extn_id == attest_oid {
            continue;
        }
        extensions_inner.extend_from_slice(
            &ext.to_der()
                .map_err(|e| CertGenError::CertBuildFailed(format!("extension encode: {e}")))?,
        );
    }
    let extensions_der = enc_sequence(&extensions_inner);

    let digest = leaf_digest(&leaf)?;
    let signing_algorithm = detect_signing_key_algorithm(&req.signing_private_key_pkcs8)?;
    let sig_alg_der = signature_algorithm_der(signing_algorithm, digest);

    // TBS Certificate: issuer is the keybox leaf's subject, every other field is the original.
    let version_der = enc_explicit_tag(0, &enc_integer(2));
    let serial_der = leaf
        .tbs_certificate
        .serial_number
        .to_der()
        .map_err(|e| CertGenError::CertBuildFailed(format!("serial encode: {e}")))?;
    let validity_der = leaf
        .tbs_certificate
        .validity
        .to_der()
        .map_err(|e| CertGenError::CertBuildFailed(format!("validity encode: {e}")))?;
    let subject_der = leaf
        .tbs_certificate
        .subject
        .to_der()
        .map_err(|e| CertGenError::CertBuildFailed(format!("subject encode: {e}")))?;
    let spki_der = leaf
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| CertGenError::CertBuildFailed(format!("spki encode: {e}")))?;
    let extensions_tagged = enc_explicit_tag(3, &extensions_der);

    let mut tbs_inner = Vec::new();
    tbs_inner.extend_from_slice(&version_der);
    tbs_inner.extend_from_slice(&serial_der);
    tbs_inner.extend_from_slice(&sig_alg_der);
    tbs_inner.extend_from_slice(&keybox.issuer_dn_der);
    tbs_inner.extend_from_slice(&validity_der);
    tbs_inner.extend_from_slice(&subject_der);
    tbs_inner.extend_from_slice(&spki_der);
    tbs_inner.extend_from_slice(&extensions_tagged);
    let tbs_der = enc_sequence(&tbs_inner);

    let signature = sign_tbs(&tbs_der, &req.signing_private_key_pkcs8, signing_algorithm, digest)?;
    let signature_bits = encode_der_bit_string(&signature);

    let mut cert_inner = Vec::new();
    cert_inner.extend_from_slice(&tbs_der);
    cert_inner.extend_from_slice(&sig_alg_der);
    cert_inner.extend_from_slice(&signature_bits);
    Ok(enc_sequence(&cert_inner))
}

/// Rebuilds the KeyMint `KeyDescription`, swapping in a rewritten `teeEnforced` list.
fn rebuild_key_description(keydesc: &[u8], req: &HackRequest) -> Result<Vec<u8>> {
    let (_, content, _) = read_tlv(keydesc)?;
    let elements = iter_tlvs(content)?;
    if elements.len() < 8 {
        return Err(CertGenError::CertBuildFailed(format!(
            "attestation extension has {} elements, expected 8",
            elements.len()
        )));
    }

    // Android 11 Keymasters may emit softwareEnforced/teeEnforced swapped; the TEE list is the one
    // carrying the root of trust (tag 704).
    let tee_index = if sequence_contains_tag(elements[6], TAG_ROOT_OF_TRUST)? {
        6
    } else {
        7
    };
    let tee_element = *elements
        .get(tee_index)
        .ok_or_else(|| CertGenError::CertBuildFailed("attestation extension is missing the TEE list".into()))?;
    let (_, tee_content, _) = read_tlv(tee_element)?;
    let tee_fields = iter_tlvs(tee_content)?;
    let new_tee = rebuild_tee_enforced(&tee_fields, req)?;

    let mut inner = Vec::new();
    for (i, &element) in elements.iter().enumerate() {
        if i == tee_index {
            inner.extend_from_slice(&new_tee);
        } else {
            inner.extend_from_slice(element);
        }
    }
    Ok(enc_sequence(&inner))
}

/// Rebuilds one `AuthorizationList`: drops the root of trust and the patch fields we override,
/// then re-adds the forged root of trust, the OS version and any configured patch levels, sorted
/// by tag number.
fn rebuild_tee_enforced(fields: &[&[u8]], req: &HackRequest) -> Result<Vec<u8>> {
    let mut original_root_of_trust: Option<&[u8]> = None;
    let mut rebuilt: Vec<(u32, Vec<u8>)> = Vec::new();

    for &field in fields {
        let tag = read_tlv(field)?.0;
        if tag == TAG_ROOT_OF_TRUST {
            original_root_of_trust = Some(field);
            continue;
        }
        if tag == TAG_OS_VERSION {
            // Always rebuilt from the (possibly spoofed) OS version.
            continue;
        }
        if (tag == TAG_OS_PATCHLEVEL && req.os_patch_override.is_some())
            || (tag == TAG_VENDOR_PATCHLEVEL && req.vendor_patch_override.is_some())
            || (tag == TAG_BOOT_PATCHLEVEL && req.boot_patch_override.is_some())
        {
            continue;
        }
        rebuilt.push((tag, field.to_vec()));
    }

    // Prefer the hash already baked into the original root of trust; only fall back to the caller's
    // value when the original is missing or malformed.
    let boot_hash = extract_root_of_trust_hash(original_root_of_trust)
        .unwrap_or_else(|| req.boot_hash.clone());

    rebuilt.push((
        TAG_OS_VERSION,
        enc_explicit_tag(TAG_OS_VERSION, &enc_integer(req.os_version as i64)),
    ));
    push_patch_level(&mut rebuilt, TAG_OS_PATCHLEVEL, req.os_patch_override);
    push_patch_level(&mut rebuilt, TAG_VENDOR_PATCHLEVEL, req.vendor_patch_override);
    push_patch_level(&mut rebuilt, TAG_BOOT_PATCHLEVEL, req.boot_patch_override);
    rebuilt.push((
        TAG_ROOT_OF_TRUST,
        enc_explicit_tag(TAG_ROOT_OF_TRUST, &build_root_of_trust(&req.boot_key, &boot_hash)),
    ));

    rebuilt.sort_by_key(|(tag, _)| *tag);

    let mut inner = Vec::new();
    for (_, value) in &rebuilt {
        inner.extend_from_slice(value);
    }
    Ok(enc_sequence(&inner))
}

/// Adds a patch-level tag unless the override is absent ("keep the original") or `DO_NOT_REPORT`.
fn push_patch_level(fields: &mut Vec<(u32, Vec<u8>)>, tag: u32, override_value: Option<i32>) {
    if let Some(value) = override_value {
        if value != DO_NOT_REPORT {
            fields.push((tag, enc_explicit_tag(tag, &enc_integer(value as i64))));
        }
    }
}

/// `RootOfTrust ::= SEQUENCE { verifiedBootKey OCTET STRING, deviceLocked BOOLEAN,
/// verifiedBootState ENUMERATED, verifiedBootHash OCTET STRING }`.
fn build_root_of_trust(boot_key: &[u8], boot_hash: &[u8]) -> Vec<u8> {
    let mut inner = Vec::new();
    inner.extend_from_slice(&enc_octet_string(boot_key));
    inner.extend_from_slice(&enc_boolean(true));
    inner.extend_from_slice(&enc_enumerated(0));
    inner.extend_from_slice(&enc_octet_string(boot_hash));
    enc_sequence(&inner)
}

/// Pulls the `verifiedBootHash` (element 3) out of an existing root of trust, if present.
fn extract_root_of_trust_hash(root_of_trust: Option<&[u8]>) -> Option<Vec<u8>> {
    // `root_of_trust` is the raw `[704]` field; descend through the explicit tag into the
    // `RootOfTrust` SEQUENCE before reading its elements.
    let root_of_trust = root_of_trust?;
    let (tag, sequence, _) = read_tlv(root_of_trust).ok()?;
    if tag != TAG_ROOT_OF_TRUST {
        return None;
    }
    let (sequence_tag, content, _) = read_tlv(sequence).ok()?;
    if sequence_tag != TAG_SEQUENCE {
        return None;
    }
    let elements = iter_tlvs(content).ok()?;
    let hash = elements.get(3)?;
    let (tag, value, _) = read_tlv(hash).ok()?;
    if tag != TAG_OCTET_STRING {
        return None;
    }
    Some(value.to_vec())
}

/// The keymint attestation extension as DER: `SEQUENCE { OID, OCTET STRING (KeyDescription) }`,
/// matching the certbuilder's `build_extension` so the two paths agree.
fn build_attestation_extension(keydesc_der: &[u8]) -> Vec<u8> {
    let oid_der = encode_der_oid(ATTESTATION_OID_COMPS);
    let value_der = enc_octet_string(keydesc_der);
    enc_sequence(&[oid_der, value_der].concat())
}

/// True when the given element is a SEQUENCE carrying a child with the wanted context tag.
fn sequence_contains_tag(element: &[u8], wanted: u32) -> Result<bool> {
    let (tag, content, _) = read_tlv(element)?;
    if tag != TAG_SEQUENCE {
        return Ok(false);
    }
    for child in iter_tlvs(content)? {
        if read_tlv(child)?.0 == wanted {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The digest named by the leaf's own signature algorithm — the new signature keeps that digest
/// while switching to the keybox key's algorithm, mirroring the Kotlin `leaf.sigAlgName` handling.
fn leaf_digest(leaf: &Certificate) -> Result<Digest> {
    let oid = leaf.tbs_certificate.signature.oid.to_string();
    match oid.as_str() {
        "1.2.840.10045.4.1" | "1.2.840.113549.1.1.5" => Ok(Digest::Sha1),
        "1.2.840.10045.4.3.2" | "1.2.840.113549.1.1.11" => Ok(Digest::Sha256),
        "1.2.840.10045.4.3.3" | "1.2.840.113549.1.1.12" => Ok(Digest::Sha384),
        "1.2.840.10045.4.3.4" | "1.2.840.113549.1.1.13" => Ok(Digest::Sha512),
        other => Err(CertGenError::CertBuildFailed(format!(
            "unsupported leaf signature algorithm: {other}"
        ))),
    }
}

/// Builds the `AlgorithmIdentifier` for the new signature: ECDSA carries no parameters, RSA a NULL.
fn signature_algorithm_der(algorithm: Algorithm, digest: Digest) -> Vec<u8> {
    match algorithm {
        Algorithm::Ec => {
            let oid: &[u64] = match digest {
                Digest::Sha1 => &[1, 2, 840, 10045, 4, 1],
                Digest::Sha256 => &[1, 2, 840, 10045, 4, 3, 2],
                Digest::Sha384 => &[1, 2, 840, 10045, 4, 3, 3],
                Digest::Sha512 => &[1, 2, 840, 10045, 4, 3, 4],
            };
            enc_sequence(&encode_der_oid(oid))
        }
        Algorithm::Rsa => {
            let oid: &[u64] = match digest {
                Digest::Sha1 => &[1, 2, 840, 113549, 1, 1, 5],
                Digest::Sha256 => &[1, 2, 840, 113549, 1, 1, 11],
                Digest::Sha384 => &[1, 2, 840, 113549, 1, 1, 12],
                Digest::Sha512 => &[1, 2, 840, 113549, 1, 1, 13],
            };
            enc_sequence(&[encode_der_oid(oid), vec![0x05, 0x00]].concat())
        }
    }
}

/// Signs the TBS with the keybox key, using `digest`. ring couples an EC key's curve to a single
/// digest and cannot hash from the SHA-1 family, so those combinations throw and surface to the
/// Kotlin caller as an error.
fn sign_tbs(tbs_der: &[u8], signing_key_der: &[u8], algorithm: Algorithm, digest: Digest) -> Result<Vec<u8>> {
    match algorithm {
        Algorithm::Ec => {
            let ring_algorithm = detect_ec_signing_algorithm(signing_key_der)?;
            let native_digest =
                if std::ptr::eq(ring_algorithm, &ring::signature::ECDSA_P384_SHA384_ASN1_SIGNING) {
                    Digest::Sha384
                } else {
                    Digest::Sha256
                };
            if digest != native_digest {
                return Err(CertGenError::SigningFailed(format!(
                    "EC key digest {native_digest:?} does not match leaf digest {digest:?}"
                )));
            }
            let rng = SystemRandom::new();
            let key_pair = EcdsaKeyPair::from_pkcs8(ring_algorithm, signing_key_der, &rng)
                .map_err(|e| CertGenError::SigningFailed(format!("EC key parse: {e}")))?;
            let signature = key_pair
                .sign(&rng, tbs_der)
                .map_err(|e| CertGenError::SigningFailed(format!("EC sign: {e}")))?;
            Ok(signature.as_ref().to_vec())
        }
        Algorithm::Rsa => {
            use rsa::pkcs1v15::SigningKey;
            use rsa::pkcs8::DecodePrivateKey;
            use rsa::signature::{SignatureEncoding, SignerMut};

            let private_key = rsa::RsaPrivateKey::from_pkcs8_der(signing_key_der)
                .map_err(|e| CertGenError::SigningFailed(format!("RSA key parse: {e}")))?;
            let signature = match digest {
                Digest::Sha256 => SigningKey::<rsa::sha2::Sha256>::new(private_key).sign(tbs_der),
                Digest::Sha384 => SigningKey::<rsa::sha2::Sha384>::new(private_key).sign(tbs_der),
                Digest::Sha512 => SigningKey::<rsa::sha2::Sha512>::new(private_key).sign(tbs_der),
                Digest::Sha1 => {
                    return Err(CertGenError::SigningFailed("RSA with SHA-1 is unsupported natively".into()))
                }
            };
            Ok(signature.to_vec())
        }
    }
}

/// The digest families the leaf-hack path recognises.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Digest {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

// ---------------------------------------------------------------------------
// Request wire format (mirrors the Kotlin encoder)
// ---------------------------------------------------------------------------

struct HackRequest {
    leaf_cert_der: Vec<u8>,
    signing_private_key_pkcs8: Vec<u8>,
    signing_chain_der: Vec<u8>,
    boot_key: Vec<u8>,
    boot_hash: Vec<u8>,
    os_version: i32,
    os_patch_override: Option<i32>,
    vendor_patch_override: Option<i32>,
    boot_patch_override: Option<i32>,
}

impl Drop for HackRequest {
    /// Wipes the signing key that arrived in the request blob.
    ///
    /// Same reasoning as `ChainBuildRequest`: the decoded copy is a private key that would otherwise
    /// stay readable in freed heap memory, and the release profile aborts on panic instead of
    /// unwinding, so nothing else can be relied on to clean it up.
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.signing_private_key_pkcs8.zeroize();
    }
}

impl HackRequest {
    /// Decodes the blob, rejecting a truncated field or trailing bytes so a malformed request can
    /// never be partially interpreted.
    fn decode(data: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(data);
        let leaf_cert_der = cursor.length_prefixed()?;
        let signing_private_key_pkcs8 = cursor.length_prefixed()?;
        let signing_chain_der = cursor.length_prefixed()?;
        let boot_key = cursor.length_prefixed()?;
        let boot_hash = cursor.length_prefixed()?;
        let os_version = cursor.i32()?;
        let os_patch_override = cursor.optional_i32()?;
        let vendor_patch_override = cursor.optional_i32()?;
        let boot_patch_override = cursor.optional_i32()?;

        if !cursor.is_at_end() {
            return Err(malformed("trailing bytes in leaf-hack request"));
        }

        Ok(Self {
            leaf_cert_der,
            signing_private_key_pkcs8,
            signing_chain_der,
            boot_key,
            boot_hash,
            os_version,
            os_patch_override,
            vendor_patch_override,
            boot_patch_override,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // test assertions are allowed to unwrap
mod tests {
    use super::*;
    use crate::attestation::build_attestation_extension as build_key_description;
    use crate::certbuilder::{build_certificate_chain, build_self_signed_cert};
    use crate::keygen::generate_key_pair;
    use crate::types::{CertGenParams, EcCurve};
    use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1};

    fn ec_key() -> crate::types::GeneratedKeyPair {
        generate_key_pair(Algorithm::Ec, 256, Some(EcCurve::P256), 0).unwrap()
    }

    fn leaf_params() -> CertGenParams {
        CertGenParams {
            algorithm: Algorithm::Ec,
            key_size: 256,
            ec_curve: Some(EcCurve::P256),
            purposes: vec![2],
            security_level: 1,
            attest_version: 200,
            keymaster_version: 41,
            os_version: 140000,
            os_patch_level: 202503,
            vendor_patch_level: 20250301,
            boot_patch_level: 20250301,
            boot_key: vec![0x01; 32],
            boot_hash: vec![0xAB; 32],
            creation_datetime: 1_709_913_600_000,
            caller_nonce: true,
            no_auth_required: true,
            ..Default::default()
        }
    }

    /// Builds a CA/keybox pair plus a leaf that already carries an attestation extension.
    fn leaf_with_attestation() -> (crate::types::GeneratedKeyPair, Vec<u8>, Vec<u8>) {
        let params = leaf_params();
        let ca_key = ec_key();
        let ca_certs = build_self_signed_cert(&ca_key, &params).unwrap();
        let keybox = parse_keybox(&ca_certs[0], &ca_key.private_key_pkcs8).unwrap();

        let leaf_key = ec_key();
        let key_description = build_key_description(&params).unwrap();
        let chain = build_certificate_chain(&leaf_key, Some(&key_description), &keybox, &params).unwrap();
        (ca_key, ca_certs[0].clone(), chain[0].clone())
    }

    fn encode_request(leaf_der: &[u8], key: &crate::types::GeneratedKeyPair, chain: &[u8], req: &HackSpec) -> Vec<u8> {
        let mut out = Vec::new();
        push(&mut out, leaf_der);
        push(&mut out, &key.private_key_pkcs8);
        push(&mut out, chain);
        push(&mut out, &req.boot_key);
        push(&mut out, &req.boot_hash);
        out.extend_from_slice(&req.os_version.to_be_bytes());
        push_opt_i32(&mut out, req.os_patch);
        push_opt_i32(&mut out, req.vendor_patch);
        push_opt_i32(&mut out, req.boot_patch);
        out
    }

    #[derive(Default)]
    struct HackSpec {
        boot_key: Vec<u8>,
        boot_hash: Vec<u8>,
        os_version: i32,
        os_patch: Option<i32>,
        vendor_patch: Option<i32>,
        boot_patch: Option<i32>,
    }

    fn push(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(bytes);
    }

    fn push_opt_i32(out: &mut Vec<u8>, value: Option<i32>) {
        match value {
            Some(v) => {
                out.push(1);
                out.extend_from_slice(&v.to_be_bytes());
            }
            None => out.push(0),
        }
    }

    fn tee_fields(leaf_der: &[u8]) -> Vec<(u32, Vec<u8>)> {
        let leaf = Certificate::from_der(leaf_der).unwrap();
        let oid: ObjectIdentifier = ATTESTATION_OID_STR.parse().unwrap();
        let ext = leaf
            .tbs_certificate
            .extensions
            .as_ref()
            .unwrap()
            .iter()
            .find(|e| e.extn_id == oid)
            .unwrap();
        let (_, content, _) = read_tlv(ext.extn_value.as_bytes()).unwrap();
        for element in iter_tlvs(content).unwrap() {
            let (tag, inner, _) = read_tlv(element).unwrap();
            if tag != TAG_SEQUENCE {
                continue;
            }
            let children = iter_tlvs(inner).unwrap();
            if children.iter().any(|c| read_tlv(c).unwrap().0 == TAG_ROOT_OF_TRUST) {
                return children
                    .iter()
                    .map(|c| {
                        let (t, v, _) = read_tlv(c).unwrap();
                        (t, v.to_vec())
                    })
                    .collect();
            }
        }
        panic!("leaf has no TEE authorization list");
    }

    fn field(fields: &[(u32, Vec<u8>)], tag: u32) -> Option<Vec<u8>> {
        fields.iter().find(|(t, _)| *t == tag).map(|(_, v)| v.clone())
    }

    fn first_tlv_len(blob: &[u8]) -> usize {
        let (_, _, total) = read_tlv(blob).unwrap();
        total
    }

    #[test]
    fn forged_root_of_trust_replaces_the_original() {
        let (ca_key, ca_cert, leaf_der) = leaf_with_attestation();
        let spec = HackSpec {
            boot_key: vec![0x22; 32],
            boot_hash: vec![0xCD; 32],
            os_version: 150000,
            os_patch: Some(202505),
            vendor_patch: None,
            boot_patch: None,
        };
        // Reuse the CA key as the signing key by re-parsing the keybox from its own cert.
        let keybox = parse_keybox(&ca_cert, &ca_key.private_key_pkcs8).unwrap();
        let request = encode_request(&leaf_der, &ca_key, &keybox.cert_chain_ders.concat(), &spec);
        let blob = hack_certificate_chain_blob(&request).unwrap();

        let leaf_len = first_tlv_len(&blob);
        let leaf = Certificate::from_der(&blob[..leaf_len]).unwrap();

        // issuer reuses the keybox leaf's subject bytes
        assert_eq!(leaf.tbs_certificate.issuer.to_der().unwrap(), keybox.issuer_dn_der);

        // signature must verify against the CA/keybox public key
        let ca_parsed = Certificate::from_der(&ca_cert).unwrap();
        let point = ca_parsed
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes()
            .to_vec();
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &point)
            .verify(&leaf.tbs_certificate.to_der().unwrap(), leaf.signature.raw_bytes())
            .unwrap();

        let fields = tee_fields(&blob[..leaf_len]);

        // root of trust carries the caller's boot key, but the ORIGINAL boot hash (0xAB), not 0xCD
        let rot = field(&fields, TAG_ROOT_OF_TRUST).unwrap();
        let (_, rot_content, _) = read_tlv(&rot).unwrap();
        let rot_elements = iter_tlvs(rot_content).unwrap();
        let boot_key = read_tlv(rot_elements[0]).unwrap().1;
        let boot_hash = read_tlv(rot_elements[3]).unwrap().1;
        assert_eq!(boot_key, vec![0x22; 32]);
        assert_eq!(boot_hash, vec![0xAB; 32], "original boot hash must be preserved");

        // OS version was rebuilt, the OS patch level overridden, vendor/boot kept from the original
        assert_eq!(field(&fields, TAG_OS_VERSION).unwrap(), enc_integer(150000));
        assert_eq!(field(&fields, TAG_OS_PATCHLEVEL).unwrap(), enc_integer(202505));
        assert_eq!(field(&fields, TAG_VENDOR_PATCHLEVEL).unwrap(), enc_integer(20250301));
        assert_eq!(field(&fields, TAG_BOOT_PATCHLEVEL).unwrap(), enc_integer(20250301));
    }

    #[test]
    fn do_not_report_drops_patch_levels() {
        let (ca_key, ca_cert, leaf_der) = leaf_with_attestation();
        let spec = HackSpec {
            boot_key: vec![0x22; 32],
            boot_hash: vec![],
            os_version: 150000,
            os_patch: Some(DO_NOT_REPORT),
            vendor_patch: Some(DO_NOT_REPORT),
            boot_patch: Some(DO_NOT_REPORT),
        };
        let keybox = parse_keybox(&ca_cert, &ca_key.private_key_pkcs8).unwrap();
        let request = encode_request(&leaf_der, &ca_key, &keybox.cert_chain_ders.concat(), &spec);
        let blob = hack_certificate_chain_blob(&request).unwrap();
        let fields = tee_fields(&blob[..first_tlv_len(&blob)]);

        assert!(field(&fields, TAG_OS_PATCHLEVEL).is_none());
        assert!(field(&fields, TAG_VENDOR_PATCHLEVEL).is_none());
        assert!(field(&fields, TAG_BOOT_PATCHLEVEL).is_none());
        // caller nonce rides along untouched
        assert!(fields.iter().any(|(t, _)| *t == 1005));
    }

    #[test]
    fn missing_attestation_extension_is_rejected() {
        let params = leaf_params();
        let ca_key = ec_key();
        let ca_cert = build_self_signed_cert(&ca_key, &params).unwrap();
        // A leaf with no attestation extension at all.
        let leaf = build_self_signed_cert(&ec_key(), &params).unwrap();

        let keybox = parse_keybox(&ca_cert[0], &ca_key.private_key_pkcs8).unwrap();
        let spec = HackSpec {
            os_version: 140000,
            ..Default::default()
        };
        let request = encode_request(&leaf[0], &ca_key, &keybox.cert_chain_ders.concat(), &spec);
        assert!(hack_certificate_chain_blob(&request).is_err());
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let (ca_key, ca_cert, leaf_der) = leaf_with_attestation();
        let keybox = parse_keybox(&ca_cert, &ca_key.private_key_pkcs8).unwrap();
        let spec = HackSpec {
            os_version: 140000,
            ..Default::default()
        };
        let mut request = encode_request(&leaf_der, &ca_key, &keybox.cert_chain_ders.concat(), &spec);
        request.push(0x00);
        assert!(HackRequest::decode(&request).is_err());
    }

    #[test]
    fn decoded_request_roundtrips() {
        let request = encode_request(
            &[0x30, 0x00],
            &ec_key(),
            &[0x30, 0x00],
            &HackSpec {
                boot_key: vec![1, 2, 3],
                boot_hash: vec![4, 5],
                os_version: 150000,
                os_patch: Some(202505),
                vendor_patch: None,
                boot_patch: Some(DO_NOT_REPORT),
            },
        );
        let decoded = HackRequest::decode(&request).unwrap();
        assert_eq!(decoded.boot_key, vec![1, 2, 3]);
        assert_eq!(decoded.os_version, 150000);
        assert_eq!(decoded.os_patch_override, Some(202505));
        assert_eq!(decoded.vendor_patch_override, None);
        assert_eq!(decoded.boot_patch_override, Some(DO_NOT_REPORT));
    }

    #[test]
    fn read_tlv_parses_high_tag_numbers() {
        // Tag 704 wrapping an empty SEQUENCE -> BF 85 40 02 01 00? Use a known encoding.
        let tlv = enc_explicit_tag(TAG_ROOT_OF_TRUST, &enc_sequence(&[]));
        let (tag, content, total) = read_tlv(&tlv).unwrap();
        assert_eq!(tag, TAG_ROOT_OF_TRUST);
        assert_eq!(content, enc_sequence(&[]));
        assert_eq!(total, tlv.len());
    }
}
