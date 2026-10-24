//! Keybox parsing for the native certificate-chain builder.
//!
//! Ported from the Rust certificate generator used by TEESimulator-RS so the chain-building stage
//! can run natively. The keybox is the PEM/DER bundle the module signs attestation chains with; here
//! we only split the concatenated DER certificates and pull out the leaf's issuer DN and validity,
//! which the later certbuilder/attestation stages consume. The same shape is exposed to Kotlin so the
//! JNI entry point can hand the values straight to the builder.
//!
//! The chain comes from a keybox document the user supplies, so every length in it is attacker
//! controlled. Splitting therefore goes through [`crate::tlv::read_tlv`] rather than a second copy of
//! the DER length decoder: that reader already rejects indefinite lengths, lengths wider than four
//! octets and high-tag numbers that overflow, using checked arithmetic throughout. This module used
//! to carry its own `len = (len << 8) | byte` loop, which on a 32-bit target would have wrapped a
//! four-octet length into a small plausible one.
use crate::error::{CertGenError, Result};
use crate::tlv;
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
impl Drop for ParsedKeybox {
    /// Wipes the signing key before the allocation is returned to the allocator.
    ///
    /// The keybox holds the private key that signs every certificate this crate mints, and the
    /// release profile uses `panic = "abort"`, so nothing may rely on cleanup running at unwind time.
    /// Wiping in `Drop` covers the ordinary paths, where `parse_keybox` returns and the caller drops
    /// the value once the chain is built.
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.signing_key_der);
    }
}
/// Parses a concatenated DER certificate chain plus its private key into a [`ParsedKeybox`].
///
/// `cert_chain_bytes` is one or more DER certificates back to back (leaf first); `private_key_bytes`
/// is the PKCS#8 DER key that signed the chain.
pub fn parse_keybox(cert_chain_bytes: &[u8], private_key_bytes: &[u8]) -> Result<ParsedKeybox> {
    let certs = split_der_certificates(cert_chain_bytes)?;
    // `split_der_certificates` never returns an empty vector, but taking the leaf through `first`
    // keeps this function free of an indexing expression that would panic if that changed.
    let leaf_der = certs
        .first()
        .ok_or_else(|| CertGenError::KeyboxParseFailed("no certificates in chain".into()))?;
    let leaf = Certificate::from_der(leaf_der)
        .map_err(|e| CertGenError::KeyboxParseFailed(format!("leaf cert parse: {e}")))?;
    let issuer_dn_der = leaf
        .tbs_certificate
        .subject
        .to_der()
        .map_err(|e| CertGenError::KeyboxParseFailed(format!("subject DN encode: {e}")))?;
    // `notAfter` is an unsigned second count, while the JNI surface carries a signed timestamp. A
    // certificate dated past 2262 cannot be represented, so report it instead of wrapping negative
    // and letting a bogus validity bound through.
    let leaf_not_after = i64::try_from(
        leaf.tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs(),
    )
    .map_err(|_| CertGenError::KeyboxParseFailed("leaf notAfter is out of range".into()))?;

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
    let mut offset = 0usize;
    while offset < data.len() {
        let rest = data.get(offset..).ok_or_else(|| {
            CertGenError::KeyboxParseFailed("certificate offset out of range".into())
        })?;
        let (tag, _, total_len) = tlv::read_tlv(rest).map_err(|e| {
            CertGenError::KeyboxParseFailed(format!("malformed cert at offset {offset}: {e}"))
        })?;
        if tag != tlv::TAG_SEQUENCE {
            // `read_tlv` strips the class and constructed bits, so a SEQUENCE reads back as 0x10
            // while the encoded first octet is 0x30. Report the encoded byte, which is what a user
            // comparing against a hex dump will look for.
            let first = rest.first().copied().unwrap_or(0);
            return Err(CertGenError::KeyboxParseFailed(format!(
                "expected SEQUENCE tag 0x30 at offset {offset}, got 0x{first:02x}"
            )));
        }
        // `read_tlv` checks `total_len` against `rest.len()`, so this cannot fail; it is still an
        // explicit `get` so this loop contains no slice that could panic.
        let cert = data.get(offset..offset + total_len).ok_or_else(|| {
            CertGenError::KeyboxParseFailed(format!(
                "cert at offset {offset} extends beyond buffer: need {total_len}, have {}",
                data.len().saturating_sub(offset)
            ))
        })?;
        certs.push(cert.to_vec());
        offset += total_len;
    }
    if certs.is_empty() {
        return Err(CertGenError::KeyboxParseFailed(
            "no certificates in chain".into(),
        ));
    }
    Ok(certs)
}
