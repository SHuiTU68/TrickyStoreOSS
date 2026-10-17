//! Native X.509 certificate construction for the attestation chain.
//!
//! Ported from the Rust certificate generator used by TEESimulator-RS. Both entry points emit DER
//! directly: [`build_self_signed_cert`] handles the no-challenge case (AOSP `ta/src/keys.rs:451-478`
//! produces a self-signed leaf of chain depth 1) and [`build_certificate_chain`] signs a leaf with
//! the keybox key before appending the keybox's own certificates. The DER primitives below are
//! hand-rolled so the wire format matches AOSP byte for byte — in particular the issuer DN is copied
//! as raw bytes from the keybox leaf instead of being re-encoded.

use crate::error::{CertGenError, Result};
use crate::keybox::ParsedKeybox;
use crate::types::{Algorithm, CertGenParams, GeneratedKeyPair};

use time::OffsetDateTime;

const ATTESTATION_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17];

// Signature algorithm OIDs
const OID_SHA256_WITH_ECDSA: &[u64] = &[1, 2, 840, 10045, 4, 3, 2];
const OID_SHA384_WITH_ECDSA: &[u64] = &[1, 2, 840, 10045, 4, 3, 3];
const OID_SHA256_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 11];

// Extension OIDs
const OID_KEY_USAGE: &[u64] = &[2, 5, 29, 15];

/// Builds a single self-signed certificate for the no-challenge case (AOSP `ta/src/keys.rs:451-478`:
/// no challenge means a self-signed leaf, chain depth 1).
///
/// The app always signs through a keybox, so only the tests exercise this AOSP parity path today.
#[allow(dead_code)]
pub fn build_self_signed_cert(
    key_pair: &GeneratedKeyPair,
    params: &CertGenParams,
) -> Result<Vec<Vec<u8>>> {
    let spki_der = extract_spki_from_pkcs8(&key_pair.private_key_pkcs8)?;
    let sig_alg_der =
        signature_algorithm_for_signing_key(&key_pair.private_key_pkcs8, params.algorithm)?;

    let serial_bytes = if let Some(ref serial) = params.cert_serial {
        serial.clone()
    } else {
        vec![1u8]
    };

    let subject_dn_der = if let Some(ref subject) = params.cert_subject {
        subject.clone()
    } else {
        encode_simple_cn_dn("Android Keystore Key")
    };

    let not_before = timestamp_to_datetime(params.cert_not_before)?;
    let not_after = if params.cert_not_after == -1 {
        // No keybox fallback available; use far-future (year 9999).
        OffsetDateTime::from_unix_timestamp(253402300799)
            .unwrap_or_else(|_| OffsetDateTime::now_utc() + time::Duration::days(365 * 30))
    } else {
        timestamp_to_datetime(params.cert_not_after)?
    };

    let extensions_der = build_extensions(None, &params.purposes)?;

    let version_der = encode_der_explicit_tag(0, &encode_der_integer(&[2]));
    let serial_der = encode_der_integer(&serial_bytes);
    let validity_der = encode_validity(&not_before, &not_after);
    let extensions_tagged = encode_der_explicit_tag(3, &extensions_der);

    // issuer == subject (self-signed, per AOSP ta/src/cert.rs:111-114)
    let tbs_der = encode_der_sequence(&[
        &version_der,
        &serial_der,
        &sig_alg_der,
        &subject_dn_der,
        &validity_der,
        &subject_dn_der,
        &spki_der,
        &extensions_tagged,
    ]);

    let signature_bytes = sign_tbs(&tbs_der, &key_pair.private_key_pkcs8, params.algorithm)?;
    let signature_bit_string = encode_der_bit_string(&signature_bytes);

    let cert_der = encode_der_sequence(&[&tbs_der, &sig_alg_der, &signature_bit_string]);

    Ok(vec![cert_der])
}

/// Builds the leaf certificate signed by the keybox key and appends the keybox's own certificates,
/// yielding the full chain the attestation path returns (leaf first).
pub fn build_certificate_chain(
    key_pair: &GeneratedKeyPair,
    attestation_ext_der: Option<&[u8]>,
    keybox: &ParsedKeybox,
    params: &CertGenParams,
) -> Result<Vec<Vec<u8>>> {
    let leaf_der = build_leaf_cert(key_pair, attestation_ext_der, keybox, params)?;

    let mut chain = Vec::with_capacity(1 + keybox.cert_chain_ders.len());
    chain.push(leaf_der);
    for cert_der in &keybox.cert_chain_ders {
        chain.push(cert_der.clone());
    }

    Ok(chain)
}

fn build_leaf_cert(
    key_pair: &GeneratedKeyPair,
    attestation_ext_der: Option<&[u8]>,
    keybox: &ParsedKeybox,
    params: &CertGenParams,
) -> Result<Vec<u8>> {
    let spki_der = extract_spki_from_pkcs8(&key_pair.private_key_pkcs8)?;
    // The leaf is signed by the keybox (or designated attest) key, which is independent of the
    // leaf key's algorithm, so the signing algorithm must come from the signing key itself.
    let signing_algorithm = detect_signing_key_algorithm(&keybox.signing_key_der)?;
    let sig_alg_der = signature_algorithm_for_signing_key(&keybox.signing_key_der, signing_algorithm)?;

    // Serial number
    let serial_bytes = if let Some(ref serial) = params.cert_serial {
        serial.clone()
    } else {
        vec![1u8]
    };

    // Subject DN
    let subject_dn_der = if let Some(ref subject) = params.cert_subject {
        subject.clone()
    } else {
        encode_simple_cn_dn("Android Keystore Key")
    };

    // Validity
    let not_before = timestamp_to_datetime(params.cert_not_before)?;
    let not_after = if params.cert_not_after == -1 {
        OffsetDateTime::from_unix_timestamp(keybox.leaf_not_after)
            .unwrap_or_else(|_| OffsetDateTime::now_utc() + time::Duration::days(365))
    } else {
        timestamp_to_datetime(params.cert_not_after)?
    };

    let extensions_der = build_extensions(attestation_ext_der, &params.purposes)?;

    // TBS Certificate
    let version_der = encode_der_explicit_tag(0, &encode_der_integer(&[2]));
    let serial_der = encode_der_integer(&serial_bytes);
    let validity_der = encode_validity(&not_before, &not_after);
    let extensions_tagged = encode_der_explicit_tag(3, &extensions_der);

    let tbs_der = encode_der_sequence(&[
        &version_der,
        &serial_der,
        &sig_alg_der,
        &keybox.issuer_dn_der, // RAW bytes — no re-encoding
        &validity_der,
        &subject_dn_der,
        &spki_der,
        &extensions_tagged,
    ]);

    // Sign the TBS
    let signature_bytes = sign_tbs(&tbs_der, &keybox.signing_key_der, signing_algorithm)?;
    let signature_bit_string = encode_der_bit_string(&signature_bytes);

    // Final certificate: SEQUENCE { TBS, sigAlgorithm, signature }
    let cert_der = encode_der_sequence(&[&tbs_der, &sig_alg_der, &signature_bit_string]);

    Ok(cert_der)
}

fn sign_tbs(tbs_der: &[u8], signing_key_der: &[u8], algorithm: Algorithm) -> Result<Vec<u8>> {
    match algorithm {
        Algorithm::Ec => sign_tbs_ec(tbs_der, signing_key_der),
        Algorithm::Rsa => sign_tbs_rsa(tbs_der, signing_key_der),
    }
}

/// Reads the signature algorithm to use from the signing key's PKCS#8 `AlgorithmIdentifier`, so a
/// keybox key whose algorithm differs from the leaf key still signs with the right primitive.
fn detect_signing_key_algorithm(pkcs8_der: &[u8]) -> Result<Algorithm> {
    use der::Decode;
    let info = pkcs8::PrivateKeyInfo::from_der(pkcs8_der)
        .map_err(|e| CertGenError::SigningFailed(format!("PKCS8 parse: {e}")))?;

    let ec_oid: const_oid::ObjectIdentifier = "1.2.840.10045.2.1"
        .parse()
        .map_err(|_| CertGenError::SigningFailed("OID parse".into()))?;

    if info.algorithm.oid == ec_oid {
        Ok(Algorithm::Ec)
    } else {
        Ok(Algorithm::Rsa)
    }
}

fn sign_tbs_ec(tbs_der: &[u8], signing_key_der: &[u8]) -> Result<Vec<u8>> {
    // Determine EC curve from the signing key's PKCS8 AlgorithmIdentifier
    let alg = detect_ec_signing_algorithm(signing_key_der)?;

    let key_pair =
        ring::signature::EcdsaKeyPair::from_pkcs8(alg, signing_key_der, &ring::rand::SystemRandom::new())
            .map_err(|e| CertGenError::SigningFailed(format!("EC key parse: {e}")))?;

    let rng = ring::rand::SystemRandom::new();
    let sig = key_pair
        .sign(&rng, tbs_der)
        .map_err(|e| CertGenError::SigningFailed(format!("EC sign: {e}")))?;

    Ok(sig.as_ref().to_vec())
}

fn detect_ec_signing_algorithm(
    pkcs8_der: &[u8],
) -> Result<&'static ring::signature::EcdsaSigningAlgorithm> {
    use der::Decode;
    let info = pkcs8::PrivateKeyInfo::from_der(pkcs8_der)
        .map_err(|e| CertGenError::SigningFailed(format!("PKCS8 parse: {e}")))?;

    let params_oid = info
        .algorithm
        .parameters_oid()
        .map_err(|e| CertGenError::SigningFailed(format!("EC curve OID: {e}")))?;

    let p256_oid: const_oid::ObjectIdentifier = "1.2.840.10045.3.1.7"
        .parse()
        .map_err(|_| CertGenError::SigningFailed("OID parse".into()))?;
    let p384_oid: const_oid::ObjectIdentifier = "1.3.132.0.34"
        .parse()
        .map_err(|_| CertGenError::SigningFailed("OID parse".into()))?;

    if params_oid == p256_oid {
        Ok(&ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING)
    } else if params_oid == p384_oid {
        Ok(&ring::signature::ECDSA_P384_SHA384_ASN1_SIGNING)
    } else {
        Err(CertGenError::SigningFailed(format!("unsupported EC curve OID: {params_oid}")))
    }
}

fn sign_tbs_rsa(tbs_der: &[u8], signing_key_der: &[u8]) -> Result<Vec<u8>> {
    use rsa::pkcs1v15::SigningKey;
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::sha2::Sha256;
    use rsa::signature::{SignatureEncoding, SignerMut};

    let private_key = rsa::RsaPrivateKey::from_pkcs8_der(signing_key_der)
        .map_err(|e| CertGenError::SigningFailed(format!("RSA key parse: {e}")))?;

    let mut signing_key = SigningKey::<Sha256>::new(private_key);
    let signature = signing_key.sign(tbs_der);

    Ok(signature.to_vec())
}

fn signature_algorithm_for_signing_key(signing_key_der: &[u8], algorithm: Algorithm) -> Result<Vec<u8>> {
    match algorithm {
        Algorithm::Ec => {
            let ring_alg = detect_ec_signing_algorithm(signing_key_der)?;
            // Determine OID from the algorithm used
            let oid = if std::ptr::eq(ring_alg, &ring::signature::ECDSA_P384_SHA384_ASN1_SIGNING) {
                OID_SHA384_WITH_ECDSA
            } else {
                OID_SHA256_WITH_ECDSA
            };
            let oid_der = encode_der_oid(oid);
            Ok(encode_der_sequence(&[&oid_der]))
        }
        Algorithm::Rsa => {
            let oid_der = encode_der_oid(OID_SHA256_WITH_RSA);
            let null_der = vec![0x05, 0x00];
            Ok(encode_der_sequence(&[&oid_der, &null_der]))
        }
    }
}

fn extract_spki_from_pkcs8(pkcs8_der: &[u8]) -> Result<Vec<u8>> {
    use der::Decode;

    let info = pkcs8::PrivateKeyInfo::from_der(pkcs8_der)
        .map_err(|e| CertGenError::CertBuildFailed(format!("PKCS8 parse for SPKI: {e}")))?;

    // Reconstruct SPKI from AlgorithmIdentifier + public key
    // For EC: derive public key from private key via ring
    // For RSA: derive from rsa crate
    let alg_id_oid = info.algorithm.oid;
    let ec_oid: const_oid::ObjectIdentifier = "1.2.840.10045.2.1"
        .parse()
        .map_err(|_| CertGenError::CertBuildFailed("OID parse".into()))?;

    if alg_id_oid == ec_oid {
        extract_ec_spki(pkcs8_der, &info)
    } else {
        extract_rsa_spki(pkcs8_der)
    }
}

fn extract_ec_spki(pkcs8_der: &[u8], info: &pkcs8::PrivateKeyInfo) -> Result<Vec<u8>> {
    use ring::signature::KeyPair as _;
    let params_oid = info
        .algorithm
        .parameters_oid()
        .map_err(|e| CertGenError::CertBuildFailed(format!("EC curve OID: {e}")))?;

    let p256_oid: const_oid::ObjectIdentifier = "1.2.840.10045.3.1.7"
        .parse()
        .map_err(|_| CertGenError::CertBuildFailed("OID parse".into()))?;
    let p384_oid: const_oid::ObjectIdentifier = "1.3.132.0.34"
        .parse()
        .map_err(|_| CertGenError::CertBuildFailed("OID parse".into()))?;

    let (ring_alg, curve_oid_der): (&ring::signature::EcdsaSigningAlgorithm, Vec<u8>) =
        if params_oid == p256_oid {
            (
                &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                encode_der_oid(&[1, 2, 840, 10045, 3, 1, 7]),
            )
        } else if params_oid == p384_oid {
            (
                &ring::signature::ECDSA_P384_SHA384_ASN1_SIGNING,
                encode_der_oid(&[1, 3, 132, 0, 34]),
            )
        } else {
            return Err(CertGenError::CertBuildFailed(format!("unsupported EC curve: {params_oid}")));
        };

    let kp = ring::signature::EcdsaKeyPair::from_pkcs8(ring_alg, pkcs8_der, &ring::rand::SystemRandom::new())
        .map_err(|e| CertGenError::CertBuildFailed(format!("EC key parse: {e}")))?;
    let ec_kp = kp.public_key().as_ref().to_vec();

    // SPKI = SEQUENCE { AlgorithmIdentifier, BIT STRING (public key) }
    // AlgorithmIdentifier = SEQUENCE { ecPublicKey OID, curve OID }
    let ec_oid_der = encode_der_oid(&[1, 2, 840, 10045, 2, 1]);
    let alg_id = encode_der_sequence(&[&ec_oid_der, &curve_oid_der]);
    let pub_key_bits = encode_der_bit_string(&ec_kp);

    Ok(encode_der_sequence(&[&alg_id, &pub_key_bits]))
}

fn extract_rsa_spki(pkcs8_der: &[u8]) -> Result<Vec<u8>> {
    use rsa::pkcs8::DecodePrivateKey;

    let private_key = rsa::RsaPrivateKey::from_pkcs8_der(pkcs8_der)
        .map_err(|e| CertGenError::CertBuildFailed(format!("RSA key parse: {e}")))?;

    let public_key = rsa::RsaPublicKey::from(&private_key);

    // Encode RSA public key as DER: SEQUENCE { n INTEGER, e INTEGER }
    use rsa::traits::PublicKeyParts;
    let n_bytes = public_key.n().to_bytes_be();
    let e_bytes = public_key.e().to_bytes_be();
    let rsa_pub_der =
        encode_der_sequence(&[&encode_der_integer(&n_bytes), &encode_der_integer(&e_bytes)]);

    // SPKI = SEQUENCE { AlgorithmIdentifier, BIT STRING (DER-encoded RSAPublicKey) }
    let rsa_oid_der = encode_der_oid(&[1, 2, 840, 113549, 1, 1, 1]);
    let null_der = vec![0x05, 0x00];
    let alg_id = encode_der_sequence(&[&rsa_oid_der, &null_der]);
    let pub_key_bits = encode_der_bit_string(&rsa_pub_der);

    Ok(encode_der_sequence(&[&alg_id, &pub_key_bits]))
}

fn build_extensions(attestation_ext_der: Option<&[u8]>, purposes: &[i32]) -> Result<Vec<u8>> {
    let mut extensions: Vec<Vec<u8>> = Vec::new();

    let ku_byte = map_key_usage_byte(purposes);
    if ku_byte != 0 {
        let ku_ext = build_key_usage_extension(ku_byte);
        extensions.push(ku_ext);
    }

    if let Some(attest_der) = attestation_ext_der {
        let attest_ext = build_extension(&encode_der_oid(ATTESTATION_OID), false, attest_der);
        extensions.push(attest_ext);
    }

    Ok(encode_der_sequence_of(&extensions))
}

fn build_extension(oid_der: &[u8], critical: bool, value_der: &[u8]) -> Vec<u8> {
    let value_octet_string = encode_der_octet_string(value_der);
    if critical {
        let critical_der = encode_der_boolean(true);
        encode_der_sequence(&[oid_der, &critical_der, &value_octet_string])
    } else {
        encode_der_sequence(&[oid_der, &value_octet_string])
    }
}

fn build_key_usage_extension(ku_byte: u8) -> Vec<u8> {
    // DER BIT STRING: minimal encoding requires trimming trailing zero bits
    let unused_bits = ku_byte.trailing_zeros().min(7) as u8;

    // BIT STRING = tag (0x03) + length(2) + unused_bits + byte
    let bit_string = vec![0x03, 0x02, unused_bits, ku_byte];

    let oid_der = encode_der_oid(OID_KEY_USAGE);
    let value_octet_string = encode_der_octet_string(&bit_string);
    let critical_der = encode_der_boolean(true);

    encode_der_sequence(&[&oid_der, &critical_der, &value_octet_string])
}

// KeyUsage BIT STRING byte layout (RFC 5280):
//   byte[0] bit 7 = digitalSignature (0x80)
//   byte[0] bit 6 = nonRepudiation   (0x40)
//   byte[0] bit 5 = keyEncipherment  (0x20)
//   byte[0] bit 4 = dataEncipherment (0x10)
//   byte[0] bit 3 = keyAgreement     (0x08)
//   byte[0] bit 2 = keyCertSign      (0x04)
//   byte[0] bit 1 = cRLSign          (0x02)
//   byte[0] bit 0 = encipherOnly     (0x01)
//   byte[1] bit 7 = decipherOnly     (0x80)
fn map_key_usage_byte(purposes: &[i32]) -> u8 {
    let mut bits: u8 = 0;
    for &purpose in purposes {
        match purpose {
            2 => bits |= 0x80, // SIGN -> digitalSignature
            1 => bits |= 0x10, // DECRYPT -> dataEncipherment
            5 => bits |= 0x20, // WRAP_KEY -> keyEncipherment
            6 => bits |= 0x08, // AGREE_KEY -> keyAgreement
            7 => bits |= 0x04, // ATTEST_KEY -> keyCertSign
            _ => {}
        }
    }
    bits
}

fn encode_validity(not_before: &OffsetDateTime, not_after: &OffsetDateTime) -> Vec<u8> {
    let nb = encode_time(not_before);
    let na = encode_time(not_after);
    encode_der_sequence(&[&nb, &na])
}

fn encode_time(dt: &OffsetDateTime) -> Vec<u8> {
    let year = dt.year();
    if (1950..2050).contains(&year) {
        encode_utctime(dt)
    } else {
        encode_gentime(dt)
    }
}

fn encode_utctime(dt: &OffsetDateTime) -> Vec<u8> {
    // UTCTime: YYMMDDHHMMSSZ
    let year = dt.year() % 100;
    let s = format!(
        "{:02}{:02}{:02}{:02}{:02}{:02}Z",
        year,
        dt.month() as u8,
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second()
    );
    let mut out = Vec::with_capacity(2 + s.len());
    out.push(0x17); // UTCTime tag
    out.extend_from_slice(&encode_der_length_bytes(s.len()));
    out.extend_from_slice(s.as_bytes());
    out
}

fn encode_gentime(dt: &OffsetDateTime) -> Vec<u8> {
    // GeneralizedTime: YYYYMMDDHHMMSSZ
    let s = format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}Z",
        dt.year(),
        dt.month() as u8,
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second()
    );
    let mut out = Vec::with_capacity(2 + s.len());
    out.push(0x18); // GeneralizedTime tag
    out.extend_from_slice(&encode_der_length_bytes(s.len()));
    out.extend_from_slice(s.as_bytes());
    out
}

fn encode_simple_cn_dn(cn: &str) -> Vec<u8> {
    // Name = SEQUENCE OF RelativeDistinguishedName
    // RDN = SET OF AttributeTypeAndValue
    // ATV = SEQUENCE { OID, UTF8String }
    let cn_oid = encode_der_oid(&[2, 5, 4, 3]);
    let cn_value = encode_der_utf8string(cn);
    let atv = encode_der_sequence(&[&cn_oid, &cn_value]);
    let rdn = encode_der_set(&[&atv]);
    encode_der_sequence(&[&rdn])
}

fn timestamp_to_datetime(ts: i64) -> Result<OffsetDateTime> {
    if ts == -1 {
        return Ok(OffsetDateTime::now_utc());
    }
    OffsetDateTime::from_unix_timestamp(ts / 1000)
        .map_err(|e| CertGenError::CertBuildFailed(format!("invalid timestamp {ts}: {e}")))
}

// ---------------------------------------------------------------------------
// DER encoding primitives
// ---------------------------------------------------------------------------

fn encode_der_length_bytes(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len <= 0xFF {
        vec![0x81, len as u8]
    } else if len <= 0xFFFF {
        vec![0x82, (len >> 8) as u8, len as u8]
    } else if len <= 0xFF_FFFF {
        vec![0x83, (len >> 16) as u8, (len >> 8) as u8, len as u8]
    } else {
        vec![0x84, (len >> 24) as u8, (len >> 16) as u8, (len >> 8) as u8, len as u8]
    }
}

fn encode_der_tag_length_value(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + content.len());
    out.push(tag);
    out.extend_from_slice(&encode_der_length_bytes(content.len()));
    out.extend_from_slice(content);
    out
}

fn encode_der_sequence(items: &[&[u8]]) -> Vec<u8> {
    let total: usize = items.iter().map(|i| i.len()).sum();
    let mut content = Vec::with_capacity(total);
    for item in items {
        content.extend_from_slice(item);
    }
    encode_der_tag_length_value(0x30, &content)
}

fn encode_der_sequence_of(items: &[Vec<u8>]) -> Vec<u8> {
    let total: usize = items.iter().map(|i| i.len()).sum();
    let mut content = Vec::with_capacity(total);
    for item in items {
        content.extend_from_slice(item);
    }
    encode_der_tag_length_value(0x30, &content)
}

fn encode_der_set(items: &[&[u8]]) -> Vec<u8> {
    let total: usize = items.iter().map(|i| i.len()).sum();
    let mut content = Vec::with_capacity(total);
    for item in items {
        content.extend_from_slice(item);
    }
    encode_der_tag_length_value(0x31, &content)
}

fn encode_der_explicit_tag(tag_num: u8, content: &[u8]) -> Vec<u8> {
    encode_der_tag_length_value(0xA0 | tag_num, content)
}

fn encode_der_integer(value: &[u8]) -> Vec<u8> {
    // DER INTEGER must have minimal encoding and a leading 0x00 if the high bit is set
    if value.is_empty() {
        return encode_der_tag_length_value(0x02, &[0x00]);
    }

    // Strip leading zeros (but keep at least one byte)
    let mut start = 0;
    while start < value.len() - 1 && value[start] == 0 {
        start += 1;
    }
    let trimmed = &value[start..];

    // Add leading 0x00 if the high bit is set (positive integer)
    if trimmed[0] & 0x80 != 0 {
        let mut padded = Vec::with_capacity(1 + trimmed.len());
        padded.push(0x00);
        padded.extend_from_slice(trimmed);
        encode_der_tag_length_value(0x02, &padded)
    } else {
        encode_der_tag_length_value(0x02, trimmed)
    }
}

fn encode_der_bit_string(bits: &[u8]) -> Vec<u8> {
    // BIT STRING: tag 0x03, length, unused_bits (0), content
    let mut content = Vec::with_capacity(1 + bits.len());
    content.push(0x00); // 0 unused bits
    content.extend_from_slice(bits);
    encode_der_tag_length_value(0x03, &content)
}

fn encode_der_octet_string(content: &[u8]) -> Vec<u8> {
    encode_der_tag_length_value(0x04, content)
}

fn encode_der_utf8string(s: &str) -> Vec<u8> {
    encode_der_tag_length_value(0x0C, s.as_bytes())
}

fn encode_der_boolean(val: bool) -> Vec<u8> {
    encode_der_tag_length_value(0x01, &[if val { 0xFF } else { 0x00 }])
}

fn encode_der_oid(components: &[u64]) -> Vec<u8> {
    if components.len() < 2 {
        return encode_der_tag_length_value(0x06, &[]);
    }

    let mut content = Vec::new();
    // First two components encoded as 40 * c[0] + c[1]
    content.push((components[0] * 40 + components[1]) as u8);

    for &c in &components[2..] {
        encode_oid_subidentifier(&mut content, c);
    }

    encode_der_tag_length_value(0x06, &content)
}

fn encode_oid_subidentifier(buf: &mut Vec<u8>, mut value: u64) {
    if value == 0 {
        buf.push(0);
        return;
    }

    // Encode in base-128 with continuation bits
    let mut bytes = Vec::new();
    while value > 0 {
        bytes.push((value & 0x7F) as u8);
        value >>= 7;
    }
    bytes.reverse();

    // Set the high bit on all but the last byte
    for i in 0..bytes.len() - 1 {
        bytes[i] |= 0x80;
    }

    buf.extend_from_slice(&bytes);
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // test assertions are allowed to unwrap
mod tests {
    use super::*;
    use crate::keybox::parse_keybox;
    use crate::keygen::generate_key_pair;
    use crate::types::{Algorithm, CertGenParams, EcCurve, GeneratedKeyPair};
    use der::{Decode, Encode};
    use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1};

    fn test_params() -> CertGenParams {
        CertGenParams {
            algorithm: Algorithm::Ec,
            key_size: 256,
            ec_curve: Some(EcCurve::P256),
            rsa_public_exponent: 0,
            attestation_challenge: None,
            purposes: vec![2], // SIGN
            digests: vec![],
            cert_serial: None,
            cert_subject: None,
            cert_not_before: 1_700_000_000_000,
            cert_not_after: -1,
            keybox_private_key: vec![],
            keybox_cert_chain: vec![],
            security_level: 1,
            attest_version: 200,
            keymaster_version: 200,
            os_version: 140000,
            os_patch_level: 202503,
            vendor_patch_level: 20250301,
            boot_patch_level: 20250301,
            boot_key: vec![],
            boot_hash: vec![],
            creation_datetime: 1_700_000_000_000,
            attestation_application_id: vec![],
            module_hash: None,
            id_brand: None,
            id_device: None,
            id_product: None,
            id_serial: None,
            id_imei: None,
            id_meid: None,
            id_manufacturer: None,
            id_model: None,
            id_second_imei: None,
            active_datetime: -1,
            origination_expire_datetime: -1,
            usage_expire_datetime: -1,
            usage_count_limit: -1,
            caller_nonce: false,
            unlocked_device_required: false,
            no_auth_required: false,
            uid: 0,
            debug_logging: false,
            ..Default::default()
        }
    }

    fn ec_key() -> GeneratedKeyPair {
        generate_key_pair(Algorithm::Ec, 256, Some(EcCurve::P256), 0).unwrap()
    }

    /// The self-signed certificate must re-parse as a valid X.509 cert, embed the generated key,
    /// and carry a signature that verifies against that key.
    #[test]
    fn self_signed_cert_is_valid_and_carries_the_key() {
        let key = ec_key();
        let chain = build_self_signed_cert(&key, &test_params()).unwrap();
        assert_eq!(chain.len(), 1);

        let cert = x509_cert::Certificate::from_der(&chain[0]).unwrap();
        // issuer == subject for a self-signed certificate
        assert_eq!(cert.tbs_certificate.issuer, cert.tbs_certificate.subject);
        // the embedded subjectPublicKeyInfo matches the generated key's SPKI byte for byte
        assert_eq!(
            cert.tbs_certificate.subject_public_key_info.to_der().unwrap(),
            key.public_key_spki
        );

        let point = cert.tbs_certificate.subject_public_key_info.subject_public_key.raw_bytes();
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, point)
            .verify(&cert.tbs_certificate.to_der().unwrap(), cert.signature.raw_bytes())
            .unwrap();
    }

    /// The chain's leaf must be issued by the keybox, keep the keybox's raw issuer DN, bound its
    /// validity to the keybox leaf, and verify against the keybox key; the keybox certs follow.
    #[test]
    fn chain_leaf_is_signed_by_the_keybox() {
        // A self-signed certificate doubles as the keybox that signs the leaf.
        let ca_key = ec_key();
        let ca_certs = build_self_signed_cert(&ca_key, &test_params()).unwrap();
        let keybox = parse_keybox(&ca_certs[0], &ca_key.private_key_pkcs8).unwrap();

        let leaf_key = ec_key();
        let chain = build_certificate_chain(&leaf_key, None, &keybox, &test_params()).unwrap();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[1], ca_certs[0], "keybox certificates are appended verbatim");

        let leaf = x509_cert::Certificate::from_der(&chain[0]).unwrap();
        // issuer DN reuses the keybox leaf's subject bytes verbatim
        assert_eq!(leaf.tbs_certificate.issuer.to_der().unwrap(), keybox.issuer_dn_der);
        // the leaf carries its own public key
        assert_eq!(
            leaf.tbs_certificate.subject_public_key_info.to_der().unwrap(),
            leaf_key.public_key_spki
        );
        // the leaf notAfter is bounded by the keybox leaf (params.cert_not_after == -1)
        assert_eq!(
            leaf.tbs_certificate.validity.not_after.to_unix_duration().as_secs() as i64,
            keybox.leaf_not_after
        );

        // signature verifies against the keybox CA key
        let ca_point = x509_cert::Certificate::from_der(&ca_certs[0])
            .unwrap()
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes()
            .to_vec();
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &ca_point)
            .verify(&leaf.tbs_certificate.to_der().unwrap(), leaf.signature.raw_bytes())
            .unwrap();
    }

    /// Covers the RSA signing path: the certificate must re-parse, embed the RSA key, and verify.
    #[test]
    fn rsa_self_signed_cert_is_valid() {
        use rsa::pkcs1v15::{Signature, VerifyingKey};
        use rsa::pkcs8::DecodePublicKey;
        use rsa::sha2::Sha256;
        use rsa::signature::Verifier;

        let key = generate_key_pair(Algorithm::Rsa, 2048, None, 0).unwrap();
        let mut params = test_params();
        params.algorithm = Algorithm::Rsa;
        params.ec_curve = None;
        params.key_size = 2048;

        let chain = build_self_signed_cert(&key, &params).unwrap();
        let cert = x509_cert::Certificate::from_der(&chain[0]).unwrap();
        assert_eq!(
            cert.tbs_certificate.subject_public_key_info.to_der().unwrap(),
            key.public_key_spki
        );

        let public = rsa::RsaPublicKey::from_public_key_der(&key.public_key_spki).unwrap();
        let verifying = VerifyingKey::<Sha256>::new(public);
        let signature = Signature::try_from(cert.signature.raw_bytes()).unwrap();
        verifying
            .verify(&cert.tbs_certificate.to_der().unwrap(), &signature)
            .unwrap();
    }
}
