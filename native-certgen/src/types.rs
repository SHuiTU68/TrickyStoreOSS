use crate::error::CertGenError;

/// Mirrors the KeyMint `Algorithm` constants for the algorithms keygen handles natively.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Algorithm {
    Rsa = 1,
    Ec = 3,
}

impl TryFrom<i32> for Algorithm {
    type Error = CertGenError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Rsa),
            3 => Ok(Self::Ec),
            _ => Err(CertGenError::UnsupportedAlgorithm(value)),
        }
    }
}

/// Mirrors the KeyMint `EcCurve` constants. Only the curves Rust implements are listed; every
/// other value is rejected so the caller falls back to BouncyCastle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum EcCurve {
    P256 = 1,
    P384 = 2,
}

impl TryFrom<i32> for EcCurve {
    type Error = CertGenError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::P256),
            2 => Ok(Self::P384),
            _ => Err(CertGenError::UnsupportedEcCurve(value)),
        }
    }
}

/// A freshly generated key pair in standard DER encodings: the private key as PKCS#8 and the
/// public key as an X.509 `SubjectPublicKeyInfo`. Kotlin rebuilds a `java.security.KeyPair` from
/// these two blobs.
pub struct GeneratedKeyPair {
    pub private_key_pkcs8: Vec<u8>,
    pub public_key_spki: Vec<u8>,
}
