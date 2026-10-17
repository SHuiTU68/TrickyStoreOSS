//! Native certificate/key generation for TrickyStoreOSS.
//!
//! Key generation and certificate-chain building both run in Rust and are exposed over JNI. The
//! attestation extension itself is still built by the BouncyCastle path in the app and handed to
//! the native builder pre-encoded; if that stage ever ports over, its JNI entry point will join the
//! ones below.

#![deny(clippy::unwrap_used, clippy::expect_used)]

mod error;
// Parses the keybox ahead of the certbuilder that consumes it.
mod keybox;
// Builds the DER certificates for the attestation chain.
mod certbuilder;
// Staged for a possible native attestation port: builds the KeyMint extension the certbuilder would
// embed in the leaf. The app still builds this in Kotlin, so it is not referenced yet.
#[allow(dead_code)]
mod attestation;
// Request/response wire format for the certificate-chain JNI entry point.
mod chaingen;
mod keygen;
mod types;

use jni::objects::{JByteArray, JClass};
use jni::sys::{jboolean, jbyteArray, jint, jlong, jstring};
use jni::JNIEnv;

use ring::rand::SystemRandom;
use ring::signature::{
    EcdsaKeyPair, KeyPair, UnparsedPublicKey, ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_ASN1_SIGNING,
};

use crate::error::{CertGenError, Result};
use crate::types::{Algorithm, EcCurve, GeneratedKeyPair};

/// Build/version marker surfaced to Kotlin so a successful load can be confirmed in the daemon log.
const VERSION: &str = concat!("certgen ", env!("CARGO_PKG_VERSION"));

/// Returns the crate version string. Proves the shared object loaded and JNI wiring works.
#[no_mangle]
pub extern "system" fn Java_io_github_beakthoven_TrickyStoreOSS_NativeCertGen_nativeVersion(
    env: JNIEnv,
    _this: JClass,
) -> jstring {
    match env.new_string(VERSION) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Exercises the linked crypto stack (ring ECDSA P-256 sign/verify). Proves the dependencies
/// actually compile, link and run inside the .so. Returns true on success.
#[no_mangle]
pub extern "system" fn Java_io_github_beakthoven_TrickyStoreOSS_NativeCertGen_selfTest(
    _env: JNIEnv,
    _this: JClass,
) -> jboolean {
    self_test().is_ok() as jboolean
}

/// Generates a key pair natively and returns it as a length-prefixed blob:
/// `[u32 BE priv_len][PKCS#8 DER][u32 BE pub_len][SubjectPublicKeyInfo DER]`.
/// Kotlin rebuilds the `java.security.KeyPair` from the two DER blobs.
///
/// `algorithm`/`ecCurve` mirror the KeyMint `Algorithm`/`EcCurve` constants. Unsupported
/// combinations throw, so the Kotlin caller falls back to BouncyCastle.
#[no_mangle]
pub extern "system" fn Java_io_github_beakthoven_TrickyStoreOSS_NativeCertGen_nativeGenerateKeyPair(
    mut env: JNIEnv,
    _this: JClass,
    algorithm: jint,
    key_size: jint,
    ec_curve: jint,
    rsa_public_exponent: jlong,
) -> jbyteArray {
    match generate_key_pair_blob(algorithm, key_size, ec_curve, rsa_public_exponent) {
        Ok(blob) => match env.byte_array_from_slice(&blob) {
            Ok(array) => array.into_raw(),
            Err(e) => {
                let _ = env.throw_new(
                    "java/lang/RuntimeException",
                    format!("NativeCertGen: failed to allocate result array: {e}"),
                );
                std::ptr::null_mut()
            }
        },
        Err(e) => {
            let _ = env.throw_new("java/lang/RuntimeException", format!("NativeCertGen: {e}"));
            std::ptr::null_mut()
        }
    }
}

fn generate_key_pair_blob(
    algorithm: jint,
    key_size: jint,
    ec_curve: jint,
    rsa_public_exponent: jlong,
) -> Result<Vec<u8>> {
    let algorithm = Algorithm::try_from(algorithm)?;
    let ec_curve = if algorithm == Algorithm::Ec {
        Some(EcCurve::try_from(ec_curve)?)
    } else {
        None
    };
    let key_pair =
        keygen::generate_key_pair(algorithm, key_size as u32, ec_curve, rsa_public_exponent as u64)?;
    Ok(encode_key_pair(&key_pair))
}

fn encode_key_pair(key_pair: &GeneratedKeyPair) -> Vec<u8> {
    let mut blob =
        Vec::with_capacity(8 + key_pair.private_key_pkcs8.len() + key_pair.public_key_spki.len());
    blob.extend_from_slice(&(key_pair.private_key_pkcs8.len() as u32).to_be_bytes());
    blob.extend_from_slice(&key_pair.private_key_pkcs8);
    blob.extend_from_slice(&(key_pair.public_key_spki.len() as u32).to_be_bytes());
    blob.extend_from_slice(&key_pair.public_key_spki);
    blob
}

/// Builds an attestation certificate chain natively from a packed request blob (see
/// [`chaingen`]) and returns the concatenated DER certificates, leaf first. The leaf key, the
/// Kotlin-built attestation extension and the keybox/signing material are all carried in the blob.
///
/// Any unsupported or malformed input throws, so the Kotlin caller falls back to BouncyCastle.
#[no_mangle]
pub extern "system" fn Java_io_github_beakthoven_TrickyStoreOSS_NativeCertGen_nativeBuildCertificateChain(
    mut env: JNIEnv,
    _this: JClass,
    request: jbyteArray,
) -> jbyteArray {
    let result = read_byte_array(&mut env, request).and_then(|bytes| {
        chaingen::build_certificate_chain_blob(&bytes)
    });

    match result {
        Ok(blob) => match env.byte_array_from_slice(&blob) {
            Ok(array) => array.into_raw(),
            Err(e) => {
                let _ = env.throw_new(
                    "java/lang/RuntimeException",
                    format!("NativeCertGen: failed to allocate result array: {e}"),
                );
                std::ptr::null_mut()
            }
        },
        Err(e) => {
            let _ = env.throw_new("java/lang/RuntimeException", format!("NativeCertGen: {e}"));
            std::ptr::null_mut()
        }
    }
}

/// Copies a JNI byte array into a `Vec`, rejecting a null handle so the builder never sees a
/// missing request.
fn read_byte_array(env: &mut JNIEnv, array: jbyteArray) -> Result<Vec<u8>> {
    if array.is_null() {
        return Err(CertGenError::InvalidParameter("chain request was null".into()));
    }
    let array = unsafe { JByteArray::from_raw(array) };
    env.convert_byte_array(&array)
        .map_err(|e| CertGenError::InvalidParameter(format!("chain request read failed: {e}")))
}

// ring::error::Unspecified does not implement std::error::Error, so map each failure to a
// static tag instead of using `?`.
fn self_test() -> std::result::Result<(), &'static str> {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
        .map_err(|_| "ecdsa keygen failed")?;
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
        .map_err(|_| "ecdsa key parse failed")?;
    let message = b"TrickyStoreOSS native self test";
    let signature = key_pair.sign(&rng, message).map_err(|_| "ecdsa sign failed")?;
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, key_pair.public_key().as_ref())
        .verify(message, signature.as_ref())
        .map_err(|_| "ecdsa verify failed")?;
    Ok(())
}
