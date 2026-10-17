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

/// Everything the native certificate pipeline needs for one request, mirroring the fields the
/// Kotlin `CertGenConfig` carries. The certificate-builder stage reads the algorithm, validity and
/// purpose fields; the remaining attestation fields are filled in when that stage ports over next,
/// so they are marked dead for now.
#[allow(dead_code)] // staged: only the certbuilder fields are read so far
pub struct CertGenParams {
    pub algorithm: Algorithm,
    pub key_size: u32,
    pub ec_curve: Option<EcCurve>,
    pub rsa_public_exponent: u64,

    pub attestation_challenge: Option<Vec<u8>>,
    pub purposes: Vec<i32>,
    pub digests: Vec<i32>,

    pub cert_serial: Option<Vec<u8>>,
    pub cert_subject: Option<Vec<u8>>,
    pub cert_not_before: i64,
    pub cert_not_after: i64,

    pub keybox_private_key: Vec<u8>,
    pub keybox_cert_chain: Vec<u8>,

    pub security_level: i32,
    pub attest_version: i32,
    pub keymaster_version: i32,

    pub os_version: i32,
    pub os_patch_level: i32,
    pub vendor_patch_level: i32,
    pub boot_patch_level: i32,

    pub boot_key: Vec<u8>,
    pub boot_hash: Vec<u8>,

    pub creation_datetime: i64,
    pub attestation_application_id: Vec<u8>,
    pub module_hash: Option<Vec<u8>>,

    pub id_brand: Option<Vec<u8>>,
    pub id_device: Option<Vec<u8>>,
    pub id_product: Option<Vec<u8>>,
    pub id_serial: Option<Vec<u8>>,
    pub id_imei: Option<Vec<u8>>,
    pub id_meid: Option<Vec<u8>>,
    pub id_manufacturer: Option<Vec<u8>>,
    pub id_model: Option<Vec<u8>>,
    pub id_second_imei: Option<Vec<u8>>,

    pub active_datetime: i64,
    pub origination_expire_datetime: i64,
    pub usage_expire_datetime: i64,
    pub usage_count_limit: i32,
    pub caller_nonce: bool,
    pub unlocked_device_required: bool,
    pub no_auth_required: bool,

    /// Calling app UID, used only to key diagnostic log lines to the requesting app.
    pub uid: i32,
    /// Mirrors the APK debug variant; gates the produced-extension dump so release stays quiet.
    pub debug_logging: bool,
}

/// A freshly generated key pair in standard DER encodings: the private key as PKCS#8 and the
/// public key as an X.509 `SubjectPublicKeyInfo`. Kotlin rebuilds a `java.security.KeyPair` from
/// these two blobs.
pub struct GeneratedKeyPair {
    pub private_key_pkcs8: Vec<u8>,
    pub public_key_spki: Vec<u8>,
}
