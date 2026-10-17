//! Key generation, ported from `CertificateGen.generateKeyPair` in the Kotlin app.
//!
//! Both private and public key material is emitted as DER so Kotlin can rebuild a normal
//! `java.security.KeyPair` from it while the key math runs natively.

use crate::error::{CertGenError, Result};
use crate::types::{Algorithm, EcCurve, GeneratedKeyPair};

pub fn generate_key_pair(
    algorithm: Algorithm,
    key_size: u32,
    ec_curve: Option<EcCurve>,
    rsa_public_exponent: u64,
) -> Result<GeneratedKeyPair> {
    match algorithm {
        Algorithm::Ec => generate_ec_key_pair(
            ec_curve.ok_or_else(|| CertGenError::InvalidParameter("ec_curve required for EC".into()))?,
        ),
        Algorithm::Rsa => generate_rsa_key_pair(key_size, rsa_public_exponent),
    }
}

fn generate_ec_key_pair(curve: EcCurve) -> Result<GeneratedKeyPair> {
    use pkcs8::EncodePrivateKey as _;
    use spki::EncodePublicKey as _;

    match curve {
        EcCurve::P256 => {
            let secret = p256::SecretKey::random(&mut rand::thread_rng());
            let private = secret.to_pkcs8_der().map_err(serialization_failed)?;
            let public = secret.public_key().to_public_key_der().map_err(serialization_failed)?;
            Ok(GeneratedKeyPair {
                private_key_pkcs8: private.as_bytes().to_vec(),
                public_key_spki: public.as_bytes().to_vec(),
            })
        }
        EcCurve::P384 => {
            let secret = p384::SecretKey::random(&mut rand::thread_rng());
            let private = secret.to_pkcs8_der().map_err(serialization_failed)?;
            let public = secret.public_key().to_public_key_der().map_err(serialization_failed)?;
            Ok(GeneratedKeyPair {
                private_key_pkcs8: private.as_bytes().to_vec(),
                public_key_spki: public.as_bytes().to_vec(),
            })
        }
    }
}

fn generate_rsa_key_pair(key_size: u32, rsa_public_exponent: u64) -> Result<GeneratedKeyPair> {
    use pkcs8::EncodePrivateKey as _;
    use spki::EncodePublicKey as _;

    if !matches!(key_size, 2048 | 3072 | 4096) {
        return Err(CertGenError::InvalidParameter(format!(
            "RSA key size must be 2048, 3072, or 4096; got {key_size}"
        )));
    }

    // F4 (65537) is the only exponent KeyMint uses in practice; 0 means "unspecified".
    let exponent = if rsa_public_exponent == 0 {
        rsa::BigUint::from(65537u64)
    } else {
        rsa::BigUint::from(rsa_public_exponent)
    };

    let mut rng = rand::thread_rng();
    let private_key = rsa::RsaPrivateKey::new_with_exp(&mut rng, key_size as usize, &exponent)
        .map_err(|e| CertGenError::KeyGenFailed(e.to_string()))?;

    let private = private_key.to_pkcs8_der().map_err(serialization_failed)?;
    let public = rsa::RsaPublicKey::from(&private_key).to_public_key_der().map_err(serialization_failed)?;

    Ok(GeneratedKeyPair {
        private_key_pkcs8: private.as_bytes().to_vec(),
        public_key_spki: public.as_bytes().to_vec(),
    })
}

fn serialization_failed<E: std::fmt::Display>(e: E) -> CertGenError {
    CertGenError::SerializationFailed(e.to_string())
}
