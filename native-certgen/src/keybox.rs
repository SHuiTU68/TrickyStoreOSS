//! Keybox parsing for the native certificate-chain builder.
//!
//! Ported from the Rust certificate generator used by TEESimulator-RS so the chain-building stage
//! can run natively. The keybox is the PEM/DER bundle the module signs attestation chains with; here
//! we only split the concatenated DER certificates and pull out the leaf's issuer DN and validity,
//! which the later certbuilder/attestation stages consume. The same shape is exposed to Kotlin so the
//! JNI entry point can hand the values straight to the builder.

use crate::error::{CertGenError, Result};
use der::{Decode, Encode};
use x509_cert::Certificate;

/// The pieces of a keybox needed to sign an attestation certificate chain.
pub struct ParsedKeybox {
    /// The leaf/signing private key as PKCS#8 DER, exactly as supplied by the caller.
    pub signing_key_der: Vec<u8>,
    /// The leaf certificate's subject, re-encoded, used as the issuer DN of the certificates we mint.
    pub issuer_dn_der: Vec<u8>,
    /// The full certificate chain in DER form, leaf first.
    pub cert_chain_ders: Vec<Vec<u8>>,
    /// The leaf certificate's `notAfter` as a Unix timestamp, bounding the validity we may issue.
    pub leaf_not_after: i64,
}

/// Parses a concatenated DER certificate chain plus its private key into a [`ParsedKeybox`].
///
/// `cert_chain_bytes` is one or more DER certificates back to back (leaf first); `private_key_bytes`
/// is the PKCS#8 DER key that signed the chain.
pub fn parse_keybox(cert_chain_bytes: &[u8], private_key_bytes: &[u8]) -> Result<ParsedKeybox> {
    let certs = split_der_certificates(cert_chain_bytes)?;

    let leaf = Certificate::from_der(&certs[0])
        .map_err(|e| CertGenError::KeyboxParseFailed(format!("leaf cert parse: {e}")))?;
    let issuer_dn_der = leaf
        .tbs_certificate
        .subject
        .to_der()
        .map_err(|e| CertGenError::KeyboxParseFailed(format!("subject DN encode: {e}")))?;
    let leaf_not_after = leaf.tbs_certificate.validity.not_after.to_unix_duration().as_secs() as i64;

    Ok(ParsedKeybox {
        signing_key_der: private_key_bytes.to_vec(),
        issuer_dn_der,
        cert_chain_ders: certs,
        leaf_not_after,
    })
}

/// Splits a buffer of back-to-back DER `Certificate` structures into one `Vec<u8>` per certificate.
fn split_der_certificates(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut certs = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        if data[offset] != 0x30 {
            return Err(CertGenError::KeyboxParseFailed(format!(
                "expected SEQUENCE tag 0x30 at offset {offset}, got 0x{:02x}",
                data[offset]
            )));
        }
        let (content_len, header_len) = parse_der_length(&data[offset + 1..])?;
        let total_len = 1 + header_len + content_len;
        if offset + total_len > data.len() {
            return Err(CertGenError::KeyboxParseFailed(format!(
                "cert at offset {offset} extends beyond buffer: need {total_len}, have {}",
                data.len() - offset
            )));
        }
        certs.push(data[offset..offset + total_len].to_vec());
        offset += total_len;
    }
    if certs.is_empty() {
        return Err(CertGenError::KeyboxParseFailed("no certificates in chain".into()));
    }
    Ok(certs)
}

/// Decodes a DER length field, returning `(content_length, number_of_length_bytes_consumed)`.
fn parse_der_length(data: &[u8]) -> Result<(usize, usize)> {
    let first = match data.first() {
        Some(&b) => b,
        None => return Err(CertGenError::KeyboxParseFailed("truncated DER length".into())),
    };
    if first < 0x80 {
        // Short form: the byte is the length itself.
        return Ok((first as usize, 1));
    }
    // Long form: the low 7 bits give the number of following length bytes.
    let num_bytes = (first & 0x7f) as usize;
    if num_bytes == 0 || num_bytes > 4 {
        return Err(CertGenError::KeyboxParseFailed(format!(
            "unsupported DER length encoding: 0x{first:02x}"
        )));
    }
    if 1 + num_bytes > data.len() {
        return Err(CertGenError::KeyboxParseFailed("truncated multi-byte DER length".into()));
    }
    let mut len: usize = 0;
    for i in 0..num_bytes {
        len = (len << 8) | (data[1 + i] as usize);
    }
    Ok((len, 1 + num_bytes))
}
