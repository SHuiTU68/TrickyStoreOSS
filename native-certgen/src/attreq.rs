//! Request wire format for the attestation-extension JNI entry point.
//!
//! Mirrors [`crate::chaingen`]: the Kotlin caller packs every field `buildAttestationDer` reads
//! into one byte blob and receives the DER `KeyDescription` back. Fields are laid out in the order
//! the encoder writes them, and every field is bounds-checked before use. Values whose Kotlin
//! source is nullable are carried as presence-tagged optionals so an unset field maps to the same
//! "omit this tag" behaviour as the BouncyCastle path.

use crate::error::Result;
use crate::types::{Algorithm, CertGenParams, EcCurve};
use crate::wire::{malformed, Cursor};

/// Decodes the request blob and returns the DER-encoded KeyMint `KeyDescription`.
pub fn build_attestation_extension_blob(request: &[u8]) -> Result<Vec<u8>> {
    let params = decode(request)?;
    crate::attestation::build_attestation_extension(&params)
}

/// Decodes the request blob into the shared [`CertGenParams`], rejecting a truncated field or
/// trailing bytes so a malformed request can never be partially interpreted. Fields no attestation
/// stage reads keep their [`Default`] value.
fn decode(data: &[u8]) -> Result<CertGenParams> {
    let mut cursor = Cursor::new(data);
    let mut params = CertGenParams::default();

    params.algorithm = Algorithm::try_from(cursor.i32()?)?;
    params.key_size = cursor.i32()? as u32;
    let ec_curve = cursor.i32()?;
    params.ec_curve = if ec_curve == 0 {
        None
    } else {
        Some(EcCurve::try_from(ec_curve)?)
    };
    params.rsa_public_exponent = cursor.i64()? as u64;

    params.security_level = cursor.i32()?;
    params.attest_version = cursor.i32()?;
    params.keymaster_version = cursor.i32()?;

    params.os_version = cursor.i32()?;
    params.os_patch_level = cursor.i32()?;
    params.vendor_patch_level = cursor.i32()?;
    params.boot_patch_level = cursor.i32()?;

    params.creation_datetime = cursor.i64()?;
    params.origin = cursor.i32()?;

    params.attestation_challenge = cursor.optional_length_prefixed()?;
    params.unique_id = cursor.length_prefixed()?;
    params.attestation_application_id = cursor.length_prefixed()?;
    params.module_hash = cursor.optional_length_prefixed()?;
    params.boot_key = cursor.length_prefixed()?;
    params.boot_hash = cursor.length_prefixed()?;

    params.purposes = cursor.i32_vec()?;
    params.digests = cursor.i32_vec()?;
    params.block_mode = cursor.i32_vec()?;
    params.padding = cursor.i32_vec()?;
    params.mgf_digest = cursor.i32_vec()?;
    params.user_secure_ids = cursor.i64_vec()?;

    params.user_auth_type = cursor.optional_i32()?;
    params.auth_timeout = cursor.optional_i32()?;
    params.allow_while_on_body = cursor.bool()?;
    params.trusted_user_presence_required = cursor.bool()?;
    params.trusted_confirmation_required = cursor.bool()?;
    params.unlocked_device_required = cursor.bool()?;
    params.no_auth_required = cursor.bool()?;
    params.caller_nonce = cursor.bool()?;

    params.active_datetime = cursor.i64()?;
    params.origination_expire_datetime = cursor.i64()?;
    params.usage_expire_datetime = cursor.i64()?;
    params.max_uses_per_boot = cursor.i32()?;
    params.usage_count_limit = cursor.i32()?;

    params.id_brand = cursor.optional_length_prefixed()?;
    params.id_device = cursor.optional_length_prefixed()?;
    params.id_product = cursor.optional_length_prefixed()?;
    params.id_serial = cursor.optional_length_prefixed()?;
    params.id_imei = cursor.optional_length_prefixed()?;
    params.id_meid = cursor.optional_length_prefixed()?;
    params.id_manufacturer = cursor.optional_length_prefixed()?;
    params.id_model = cursor.optional_length_prefixed()?;
    params.id_second_imei = cursor.optional_length_prefixed()?;

    if !cursor.is_at_end() {
        return Err(malformed("trailing bytes in attestation request"));
    }
    Ok(params)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // test assertions are allowed to unwrap
mod tests {
    use super::*;
    use crate::attestation::build_attestation_extension;

    /// Mirrors the Kotlin `DataOutputStream` encoder so the tests exercise the exact on-wire
    /// layout the app produces.
    #[derive(Default)]
    struct Encoder {
        out: Vec<u8>,
    }

    impl Encoder {
        fn i32(&mut self, v: i32) -> &mut Self {
            self.out.extend_from_slice(&v.to_be_bytes());
            self
        }

        fn i64(&mut self, v: i64) -> &mut Self {
            self.out.extend_from_slice(&v.to_be_bytes());
            self
        }

        fn bool(&mut self, v: bool) -> &mut Self {
            self.out.push(if v { 1 } else { 0 });
            self
        }

        fn bytes(&mut self, b: &[u8]) -> &mut Self {
            self.out.extend_from_slice(&(b.len() as u32).to_be_bytes());
            self.out.extend_from_slice(b);
            self
        }

        fn opt_bytes(&mut self, b: Option<&[u8]>) -> &mut Self {
            self.bytes(b.unwrap_or(&[]))
        }

        fn opt_i32(&mut self, v: Option<i32>) -> &mut Self {
            self.bool(v.is_some());
            if let Some(x) = v {
                self.i32(x);
            }
            self
        }

        fn vec_i32(&mut self, vs: &[i32]) -> &mut Self {
            self.out.extend_from_slice(&(vs.len() as u32).to_be_bytes());
            for v in vs {
                self.out.extend_from_slice(&v.to_be_bytes());
            }
            self
        }

        fn vec_i64(&mut self, vs: &[i64]) -> &mut Self {
            self.out.extend_from_slice(&(vs.len() as u32).to_be_bytes());
            for v in vs {
                self.out.extend_from_slice(&v.to_be_bytes());
            }
            self
        }
    }

    fn encode(params: &CertGenParams) -> Vec<u8> {
        let mut e = Encoder::default();
        e.i32(params.algorithm as i32)
            .i32(params.key_size as i32)
            .i32(params.ec_curve.map(|c| c as i32).unwrap_or(0))
            .i64(params.rsa_public_exponent as i64)
            .i32(params.security_level)
            .i32(params.attest_version)
            .i32(params.keymaster_version)
            .i32(params.os_version)
            .i32(params.os_patch_level)
            .i32(params.vendor_patch_level)
            .i32(params.boot_patch_level)
            .i64(params.creation_datetime)
            .i32(params.origin)
            .opt_bytes(params.attestation_challenge.as_deref())
            .bytes(&params.unique_id)
            .bytes(&params.attestation_application_id)
            .opt_bytes(params.module_hash.as_deref())
            .bytes(&params.boot_key)
            .bytes(&params.boot_hash)
            .vec_i32(&params.purposes)
            .vec_i32(&params.digests)
            .vec_i32(&params.block_mode)
            .vec_i32(&params.padding)
            .vec_i32(&params.mgf_digest)
            .vec_i64(&params.user_secure_ids)
            .opt_i32(params.user_auth_type)
            .opt_i32(params.auth_timeout)
            .bool(params.allow_while_on_body)
            .bool(params.trusted_user_presence_required)
            .bool(params.trusted_confirmation_required)
            .bool(params.unlocked_device_required)
            .bool(params.no_auth_required)
            .bool(params.caller_nonce)
            .i64(params.active_datetime)
            .i64(params.origination_expire_datetime)
            .i64(params.usage_expire_datetime)
            .i32(params.max_uses_per_boot)
            .i32(params.usage_count_limit)
            .opt_bytes(params.id_brand.as_deref())
            .opt_bytes(params.id_device.as_deref())
            .opt_bytes(params.id_product.as_deref())
            .opt_bytes(params.id_serial.as_deref())
            .opt_bytes(params.id_imei.as_deref())
            .opt_bytes(params.id_meid.as_deref())
            .opt_bytes(params.id_manufacturer.as_deref())
            .opt_bytes(params.id_model.as_deref())
            .opt_bytes(params.id_second_imei.as_deref());
        e.out
    }

    fn sample_params() -> CertGenParams {
        CertGenParams {
            algorithm: Algorithm::Ec,
            key_size: 256,
            ec_curve: Some(EcCurve::P256),
            rsa_public_exponent: 0,
            attestation_challenge: Some(vec![0xAB; 32]),
            purposes: vec![2, 3],
            digests: vec![4],
            block_mode: vec![1],
            padding: vec![],
            mgf_digest: vec![],
            user_secure_ids: vec![],
            user_auth_type: Some(2),
            auth_timeout: None,
            allow_while_on_body: false,
            trusted_user_presence_required: false,
            trusted_confirmation_required: false,
            max_uses_per_boot: 0,
            origin: 0,
            security_level: 1,
            attest_version: 200,
            keymaster_version: 41,
            os_version: 140000,
            os_patch_level: 202503,
            vendor_patch_level: 20250301,
            boot_patch_level: 20250301,
            boot_key: vec![0x01; 32],
            boot_hash: vec![0x02; 32],
            creation_datetime: 1_709_913_600_000,
            attestation_application_id: vec![0xDE, 0xAD],
            unique_id: vec![0xBE, 0xEF],
            module_hash: None,
            id_brand: Some(b"google".to_vec()),
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
            caller_nonce: true,
            unlocked_device_required: false,
            no_auth_required: true,
            ..Default::default()
        }
    }

    /// The decoded request must produce exactly the bytes the in-process builder produces for the
    /// same parameters — that is what keeps the native path byte-identical to BouncyCastle.
    #[test]
    fn decoded_request_matches_direct_build() {
        let params = sample_params();
        let blob = encode(&params);
        let from_blob = build_attestation_extension_blob(&blob).unwrap();
        let direct = build_attestation_extension(&params).unwrap();
        assert_eq!(from_blob, direct);
    }

    #[test]
    fn decode_roundtrips_optionals() {
        let params = sample_params();
        let decoded = decode(&encode(&params)).unwrap();
        assert_eq!(decoded.algorithm, Algorithm::Ec);
        assert_eq!(decoded.ec_curve, Some(EcCurve::P256));
        assert_eq!(decoded.attestation_challenge, Some(vec![0xAB; 32]));
        assert_eq!(decoded.user_auth_type, Some(2));
        assert_eq!(decoded.auth_timeout, None);
        assert!(decoded.caller_nonce);
        assert!(decoded.no_auth_required);
        assert_eq!(decoded.id_brand, Some(b"google".to_vec()));
        assert_eq!(decoded.id_device, None);
    }

    #[test]
    fn unset_curve_decodes_as_none() {
        let mut params = sample_params();
        params.algorithm = Algorithm::Rsa;
        params.ec_curve = None;
        let decoded = decode(&encode(&params)).unwrap();
        assert_eq!(decoded.ec_curve, None);
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut blob = encode(&sample_params());
        blob.push(0x00);
        assert!(decode(&blob).is_err());
    }

    #[test]
    fn truncated_field_is_rejected() {
        // Algorithm i32 is 4 bytes; three bytes must fail.
        let data = vec![0, 0, 0];
        assert!(decode(&data).is_err());
    }

    #[test]
    fn unsupported_algorithm_is_rejected() {
        let mut params = sample_params();
        params.algorithm = Algorithm::Ec;
        let mut blob = encode(&params);
        // Overwrite the algorithm field (first 4 bytes) with AES (32), which has no native path.
        blob[..4].copy_from_slice(&32i32.to_be_bytes());
        assert!(decode(&blob).is_err());
    }
}
