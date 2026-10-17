//! Native certificate/key generation for TrickyStoreOSS.
//!
//! Key generation, certificate-chain building and the KeyMint attestation extension all run in
//! Rust and are exposed over JNI. These are the only implementations: the app ships no
//! BouncyCastle fallback, so a missing shared object or an unsupported request surfaces as an
//! error rather than a silent switch to another provider.

#![deny(clippy::unwrap_used, clippy::expect_used)]

mod error;
// Parses the keybox ahead of the certbuilder that consumes it.
mod keybox;
// Parses the keybox XML document itself, handed over by the Kotlin config loader.
mod keybox_xml;
// Builds the DER certificates for the attestation chain.
mod certbuilder;
// Builds the KeyMint attestation extension the certbuilder embeds in the leaf.
mod attestation;
// Rewrites an existing leaf's attestation extension and re-signs it with the keybox.
mod hack_leaf;
// Reads the verified-boot fields back out of a probe certificate's attestation extension.
mod attest_parse;
// Request/response wire format for the certificate-chain JNI entry point.
mod chaingen;
// Request wire format for the attestation-extension JNI entry point.
mod attreq;
mod keygen;
mod types;
// Bounds-checked reader shared by the request blobs.
mod wire;
// Minimal DER reader shared by the hand-rolled parsers.
mod tlv;

use jni::objects::{JByteArray, JClass, JString};
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
/// combinations throw and surface to the Kotlin caller as an error.
#[no_mangle]
pub extern "system" fn Java_io_github_beakthoven_TrickyStoreOSS_NativeCertGen_nativeGenerateKeyPair(
    mut env: JNIEnv,
    _this: JClass,
    algorithm: jint,
    key_size: jint,
    ec_curve: jint,
    rsa_public_exponent: jlong,
) -> jbyteArray {
    let result =
        generate_key_pair_blob(algorithm, key_size, ec_curve, rsa_public_exponent);
    byte_array_result(&mut env, result)
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
/// Any unsupported or malformed input throws and surfaces to the Kotlin caller as an error.
#[no_mangle]
pub extern "system" fn Java_io_github_beakthoven_TrickyStoreOSS_NativeCertGen_nativeBuildCertificateChain(
    mut env: JNIEnv,
    _this: JClass,
    request: jbyteArray,
) -> jbyteArray {
    let result = read_byte_array(&mut env, request)
        .and_then(|bytes| chaingen::build_certificate_chain_blob(&bytes));
    byte_array_result(&mut env, result)
}

/// Builds the KeyMint attestation extension — the DER-encoded `KeyDescription` that the caller
/// wraps in the leaf certificate's `1.3.6.1.4.1.11129.2.1.17` extension — from a packed request
/// blob (see [`attreq`]). The attestation application id and unique id are still computed by the
/// Kotlin layer (they need the PackageManager and the persisted HMAC key) and handed over already
/// encoded.
///
/// Any unsupported or malformed input throws and surfaces to the Kotlin caller as an error.
#[no_mangle]
pub extern "system" fn Java_io_github_beakthoven_TrickyStoreOSS_NativeCertGen_nativeBuildAttestationExtension(
    mut env: JNIEnv,
    _this: JClass,
    request: jbyteArray,
) -> jbyteArray {
    let result = read_byte_array(&mut env, request)
        .and_then(|bytes| attreq::build_attestation_extension_blob(&bytes));
    byte_array_result(&mut env, result)
}

/// Rewrites an existing leaf certificate's KeyMint attestation extension — forging the
/// `rootOfTrust` and patching the patch-level fields — then re-signs it with the keybox, from a
/// packed request blob (see [`hack_leaf`]). Returns the leaf-first concatenated DER chain.
///
/// Any unsupported or malformed input throws and surfaces to the Kotlin caller as an error.
#[no_mangle]
pub extern "system" fn Java_io_github_beakthoven_TrickyStoreOSS_NativeCertGen_nativeHackCertificateChain(
    mut env: JNIEnv,
    _this: JClass,
    request: jbyteArray,
) -> jbyteArray {
    let result = read_byte_array(&mut env, request)
        .and_then(|bytes| hack_leaf::hack_certificate_chain_blob(&bytes));
    byte_array_result(&mut env, result)
}

/// Parses the keybox XML document natively and returns the entries as a length-prefixed blob (see
/// [`keybox_xml`]): `[u32 count]{ [u32 algorithm][u32 PKCS#8 key]{ [u32 certCount]{ [u32 cert] }
/// } }`. Kotlin rebuilds the key pairs and certificates from it.
///
/// Any unsupported or malformed document throws and surfaces to the Kotlin caller as an error.
#[no_mangle]
pub extern "system" fn Java_io_github_beakthoven_TrickyStoreOSS_NativeCertGen_nativeParseKeybox(
    mut env: JNIEnv,
    _this: JClass,
    xml: JString,
) -> jbyteArray {
    let result = read_string(&mut env, &xml).and_then(|text| keybox_xml::parse_keybox_blob(&text));
    byte_array_result(&mut env, result)
}

/// Decodes one PEM private key block natively (see [`keybox_xml::decode_key_blob`]) into
/// `[u32 algLen][algorithm][u32 PKCS#8 len][PKCS#8 DER]`. Kotlin rebuilds the `KeyPair` from the
/// algorithm name and the DER.
///
/// An unsupported label or malformed key throws and surfaces to the Kotlin caller as an error.
#[no_mangle]
pub extern "system" fn Java_io_github_beakthoven_TrickyStoreOSS_NativeCertGen_nativeDecodePemKey(
    mut env: JNIEnv,
    _this: JClass,
    pem: JString,
) -> jbyteArray {
    let result = read_string(&mut env, &pem).and_then(|text| keybox_xml::decode_key_blob(&text));
    byte_array_result(&mut env, result)
}

/// Decodes one PEM certificate block natively (see [`keybox_xml::decode_certificate`]) and returns
/// its DER bytes. A bad label or a non-certificate body throws and surfaces to the Kotlin caller
/// as an error.
#[no_mangle]
pub extern "system" fn Java_io_github_beakthoven_TrickyStoreOSS_NativeCertGen_nativeDecodePemCertificate(
    mut env: JNIEnv,
    _this: JClass,
    pem: JString,
) -> jbyteArray {
    let result = read_string(&mut env, &pem).and_then(|text| keybox_xml::decode_certificate(&text));
    byte_array_result(&mut env, result)
}

/// Reads the verified-boot fields back out of a probe certificate's KeyMint attestation extension,
/// from a packed request blob (see [`attest_parse`]): `[u32 certLen][certificate DER][u32
/// challengeLen][challenge]`. Returns the fields as a length-prefixed blob for Kotlin to rebuild
/// `AttestUtils.AttestationData`.
///
/// Any malformed input or a challenge mismatch throws and surfaces to the Kotlin caller as an
/// error.
#[no_mangle]
pub extern "system" fn Java_io_github_beakthoven_TrickyStoreOSS_NativeCertGen_nativeParseAttestation(
    mut env: JNIEnv,
    _this: JClass,
    request: jbyteArray,
) -> jbyteArray {
    let result = read_byte_array(&mut env, request)
        .and_then(|bytes| attest_parse::parse_attestation_blob(&bytes));
    byte_array_result(&mut env, result)
}

/// Turns the entry point's result into a JNI byte array, throwing the mapped Java exception and
/// returning null on failure. Shared by every entry point that hands a byte blob back.
fn byte_array_result(env: &mut JNIEnv, result: Result<Vec<u8>>) -> jbyteArray {
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

/// Copies a JNI string into a `String`, rejecting a null handle so no parser sees a missing input.
fn read_string(env: &mut JNIEnv, value: &JString) -> Result<String> {
    if value.is_null() {
        return Err(CertGenError::InvalidParameter("string argument was null".into()));
    }
    env.get_string(value)
        .map(String::from)
        .map_err(|e| CertGenError::InvalidParameter(format!("string argument read failed: {e}")))
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
