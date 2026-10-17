//! Request/response wire format for the native certificate-chain JNI entry point.
//!
//! The Kotlin caller packs everything the native chain builder needs into a single byte blob and
//! receives the DER chain back as another. Keeping the JNI surface to one byte array mirrors the
//! keygen entry point and avoids a wide, brittle parameter list. The attestation extension is
//! built by the Kotlin layer and handed over already encoded, so the native side only parses the
//! keybox, signs the leaf and assembles the chain.

use crate::certbuilder::build_certificate_chain;
use crate::error::{CertGenError, Result};
use crate::keybox::parse_keybox;
use crate::types::{Algorithm, CertGenParams, GeneratedKeyPair};

/// Decodes the request blob, builds the chain, and returns the concatenated DER certificates
/// (leaf first). An empty `attestation_ext_der` means the leaf carries no attestation extension.
pub fn build_certificate_chain_blob(request: &[u8]) -> Result<Vec<u8>> {
    let ChainBuildRequest {
        algorithm,
        cert_not_before,
        cert_not_after,
        append_signing_chain,
        leaf_private_key_pkcs8,
        attestation_ext_der,
        signing_private_key_pkcs8,
        signing_chain_der,
        purposes,
        cert_serial,
        cert_subject,
    } = ChainBuildRequest::decode(request)?;

    let keybox = parse_keybox(&signing_chain_der, &signing_private_key_pkcs8)?;

    // The chain builder only reads the private key (it derives the SPKI itself), so the public
    // half stays empty.
    let leaf_key = GeneratedKeyPair {
        private_key_pkcs8: leaf_private_key_pkcs8,
        public_key_spki: Vec::new(),
    };

    let params = CertGenParams {
        algorithm,
        purposes,
        cert_serial,
        cert_subject,
        cert_not_before,
        cert_not_after,
        ..Default::default()
    };

    let attestation = if attestation_ext_der.is_empty() {
        None
    } else {
        Some(attestation_ext_der.as_slice())
    };

    let mut chain = build_certificate_chain(&leaf_key, attestation, &keybox, &params)?;
    if !append_signing_chain {
        // The designated-attestation-key path returns only the freshly minted leaf.
        chain.truncate(1);
    }

    Ok(encode_cert_chain(&chain))
}

/// Concatenates the DER certificates back to back, the form `CertificateFactory` parses.
fn encode_cert_chain(chain: &[Vec<u8>]) -> Vec<u8> {
    let total: usize = chain.iter().map(Vec::len).sum();
    let mut out = Vec::with_capacity(total);
    for cert in chain {
        out.extend_from_slice(cert);
    }
    out
}

/// The decoded request blob.
struct ChainBuildRequest {
    algorithm: Algorithm,
    cert_not_before: i64,
    cert_not_after: i64,
    append_signing_chain: bool,
    leaf_private_key_pkcs8: Vec<u8>,
    attestation_ext_der: Vec<u8>,
    signing_private_key_pkcs8: Vec<u8>,
    signing_chain_der: Vec<u8>,
    purposes: Vec<i32>,
    cert_serial: Option<Vec<u8>>,
    cert_subject: Option<Vec<u8>>,
}

impl ChainBuildRequest {
    /// Decodes the blob, rejecting any truncated field or trailing bytes so a malformed request
    /// can never be partially interpreted.
    fn decode(data: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(data);

        let algorithm = Algorithm::try_from(cursor.i32()?)?;
        let cert_not_before = cursor.i64()?;
        let cert_not_after = cursor.i64()?;
        let append_signing_chain = cursor.u8()? != 0;
        let leaf_private_key_pkcs8 = cursor.length_prefixed()?;
        let attestation_ext_der = cursor.length_prefixed()?;
        let signing_private_key_pkcs8 = cursor.length_prefixed()?;
        let signing_chain_der = cursor.length_prefixed()?;
        let purposes = cursor.i32_vec()?;
        let cert_serial = cursor.optional_length_prefixed()?;
        let cert_subject = cursor.optional_length_prefixed()?;

        if !cursor.is_at_end() {
            return Err(malformed("trailing bytes in request"));
        }

        Ok(Self {
            algorithm,
            cert_not_before,
            cert_not_after,
            append_signing_chain,
            leaf_private_key_pkcs8,
            attestation_ext_der,
            signing_private_key_pkcs8,
            signing_chain_der,
            purposes,
            cert_serial,
            cert_subject,
        })
    }
}

/// A bounds-checked forward reader over the request blob.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| malformed("field length overflow"))?;
        if end > self.data.len() {
            return Err(malformed("unexpected end of request"));
        }
        let slice = &self.data[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    /// Reads a big-endian `u32`; used for both lengths and raw `i32` values reinterpreted at the
    /// call site.
    fn u32(&mut self) -> Result<u32> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn i32(&mut self) -> Result<i32> {
        Ok(self.u32()? as i32)
    }

    fn i64(&mut self) -> Result<i64> {
        let bytes = self.take(8)?;
        let mut value = [0u8; 8];
        value.copy_from_slice(bytes);
        Ok(i64::from_be_bytes(value))
    }

    fn length_prefixed(&mut self) -> Result<Vec<u8>> {
        let len = self.u32()? as usize;
        Ok(self.take(len)?.to_vec())
    }

    fn optional_length_prefixed(&mut self) -> Result<Option<Vec<u8>>> {
        let bytes = self.length_prefixed()?;
        Ok(if bytes.is_empty() { None } else { Some(bytes) })
    }

    fn i32_vec(&mut self) -> Result<Vec<i32>> {
        let count = self.u32()? as usize;
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            values.push(self.i32()?);
        }
        Ok(values)
    }

    fn is_at_end(&self) -> bool {
        self.pos >= self.data.len()
    }
}

fn malformed(msg: &str) -> CertGenError {
    CertGenError::InvalidParameter(format!("malformed chain request: {msg}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // test assertions are allowed to unwrap
mod tests {
    use super::*;
    use crate::certbuilder::build_self_signed_cert;
    use crate::keygen::generate_key_pair;
    use crate::types::EcCurve;
    use der::{Decode, Encode};

    fn ec_key() -> GeneratedKeyPair {
        generate_key_pair(Algorithm::Ec, 256, Some(EcCurve::P256), 0).unwrap()
    }

    fn push_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(bytes);
    }

    /// Builds a request blob matching the Kotlin encoder for a given keybox and leaf key.
    fn encode_request(
        leaf_key: &GeneratedKeyPair,
        signing_key: &GeneratedKeyPair,
        signing_chain: &[u8],
        append: bool,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(Algorithm::Ec as i32).to_be_bytes());
        out.extend_from_slice(&1_700_000_000_000i64.to_be_bytes());
        out.extend_from_slice(&253_402_300_799_000i64.to_be_bytes());
        out.push(if append { 1 } else { 0 });
        push_len_prefixed(&mut out, &leaf_key.private_key_pkcs8);
        push_len_prefixed(&mut out, &[]);
        push_len_prefixed(&mut out, &signing_key.private_key_pkcs8);
        push_len_prefixed(&mut out, signing_chain);
        out.extend_from_slice(&1u32.to_be_bytes());
        out.extend_from_slice(&2i32.to_be_bytes()); // SIGN
        push_len_prefixed(&mut out, &[]);
        push_len_prefixed(&mut out, &[]);
        out
    }

    #[test]
    fn request_roundtrips_through_the_reader() {
        let leaf = ec_key();
        let signing = ec_key();
        let chain = encode_request(&leaf, &signing, &[0x30, 0x00], true);

        let request = ChainBuildRequest::decode(&chain).unwrap();
        assert_eq!(request.algorithm, Algorithm::Ec);
        assert_eq!(request.cert_not_before, 1_700_000_000_000);
        assert_eq!(request.purposes, vec![2]);
        assert!(request.append_signing_chain);
        assert_eq!(request.signing_chain_der, vec![0x30, 0x00]);
        assert!(request.cert_serial.is_none());
        assert!(request.cert_subject.is_none());
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let leaf = ec_key();
        let signing = ec_key();
        let mut chain = encode_request(&leaf, &signing, &[0x30, 0x00], true);
        chain.push(0x00);
        assert!(ChainBuildRequest::decode(&chain).is_err());
    }

    #[test]
    fn truncated_length_prefixed_field_is_rejected() {
        // Length says 4 bytes but none follow.
        let data = vec![0, 0, 0, 4];
        assert!(ChainBuildRequest::decode(&data).is_err());
    }

    #[test]
    fn appended_chain_produces_leaf_then_keybox_certificate() {
        let ca_key = ec_key();
        let ca_cert = build_self_signed_cert(&ca_key, &CertGenParams::default()).unwrap();
        let leaf = ec_key();

        let request = encode_request(&leaf, &ca_key, &ca_cert[0], true);
        let blob = build_certificate_chain_blob(&request).unwrap();

        // The leaf comes first, followed by the keybox certificate copied verbatim.
        let leaf_len = first_tlv_len(&blob);
        assert_eq!(&blob[leaf_len..], ca_cert[0].as_slice());

        let leaf_cert = x509_cert::Certificate::from_der(&blob[..leaf_len]).unwrap();
        // The leaf issuer reuses the keybox certificate's subject bytes.
        let ca_parsed = x509_cert::Certificate::from_der(&ca_cert[0]).unwrap();
        assert_eq!(
            leaf_cert.tbs_certificate.issuer.to_der().unwrap(),
            ca_parsed.tbs_certificate.subject.to_der().unwrap()
        );
    }

    #[test]
    fn designated_key_path_emits_only_the_leaf() {
        let signing_key = ec_key();
        let signing_cert = build_self_signed_cert(&signing_key, &CertGenParams::default()).unwrap();
        let leaf = ec_key();

        let request = encode_request(&leaf, &signing_key, &signing_cert[0], false);
        let blob = build_certificate_chain_blob(&request).unwrap();

        // Exactly one certificate: the whole blob is the leaf and nothing is appended.
        assert_eq!(first_tlv_len(&blob), blob.len());
        assert!(x509_cert::Certificate::from_der(&blob).is_ok());
    }

    /// Length of the first DER TLV (one certificate) in a concatenated blob.
    fn first_tlv_len(blob: &[u8]) -> usize {
        assert_eq!(blob[0], 0x30, "certificate must start with a SEQUENCE");
        let first = blob[1];
        if first < 0x80 {
            first as usize + 2
        } else {
            let num = (first & 0x7f) as usize;
            let mut len = 0usize;
            for i in 0..num {
                len = (len << 8) | blob[2 + i] as usize;
            }
            len + 2 + num
        }
    }
}
