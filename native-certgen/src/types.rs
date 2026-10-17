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
/// Kotlin `CertGenConfig` carries. The chain builder reads only the algorithm, validity, subject
/// and purpose fields — the attestation extension itself is built by the Kotlin caller and handed
/// over pre-encoded — so the remaining fields stay as placeholders for a future native attestation
/// stage and are marked dead for now.
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

impl Default for CertGenParams {
    fn default() -> Self {
        Self {
            algorithm: Algorithm::Ec,
            key_size: 256,
            ec_curve: None,
            rsa_public_exponent: 0,
            attestation_challenge: None,
            purposes: Vec::new(),
            digests: Vec::new(),
            cert_serial: None,
            cert_subject: None,
            cert_not_before: -1,
            cert_not_after: -1,
            keybox_private_key: Vec::new(),
            keybox_cert_chain: Vec::new(),
            security_level: 1,
            attest_version: 0,
            keymaster_version: 0,
            os_version: -1,
            os_patch_level: -1,
            vendor_patch_level: -1,
            boot_patch_level: -1,
            boot_key: Vec::new(),
            boot_hash: Vec::new(),
            creation_datetime: 0,
            attestation_application_id: Vec::new(),
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
