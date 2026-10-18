//! Native certificate/key generation for TrickyStoreOSS.
//!
//! Key generation, certificate-chain building and the KeyMint attestation extension all run in
//! Rust and are exposed over JNI. These are the only implementations: the app ships no
//! BouncyCastle fallback, so a missing shared object or an unsupported request surfaces as an
//! error rather than a silent switch to another provider.

#![deny(clippy::unwrap_used, clippy::expect_used)]
// Every `unsafe` block has to justify its invariants; there is exactly one, in
// `read_byte_array`, and the reason it is sound is written above it.
#![deny(clippy::undocumented_unsafe_blocks)]

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

use zeroize::Zeroizing;
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
    Ok(encode_key_pair(&key_pair)?)
}

/// Encodes a generated key pair as the blob Kotlin decodes into a `KeyPair`:
/// `[u32 pkcs8Len][PKCS#8][u32 spkiLen][SPKI]`, both lengths big-endian.
fn encode_key_pair(key_pair: &GeneratedKeyPair) -> Result<Vec<u8>> {
    // Both lengths are bounded by `MAX_REQUEST_BYTES` on the way out, so this cannot overflow in
    // practice; the checked arithmetic keeps the encoder honest about that and reports a bogus
    // length instead of wrapping (a wrapped capacity would then be too small and silently truncate).
    let capacity = 8usize
        .checked_add(key_pair.private_key_pkcs8.len())
        .and_then(|size| size.checked_add(key_pair.public_key_spki.len()))
        .ok_or_else(|| CertGenError::SerializationFailed("key pair blob length overflows".into()))?;
    let mut blob = Vec::with_capacity(capacity);
    blob.extend_from_slice(&(key_pair.private_key_pkcs8.len() as u32).to_be_bytes());
    blob.extend_from_slice(&key_pair.private_key_pkcs8);
    blob.extend_from_slice(&(key_pair.public_key_spki.len() as u32).to_be_bytes());
    blob.extend_from_slice(&key_pair.public_key_spki);
    Ok(blob)
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
    let result = read_byte_array(&mut env, request, "certificate chain request")
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
    let result = read_byte_array(&mut env, request, "attestation extension request")
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
    let result = read_byte_array(&mut env, request, "hacked chain request")
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
    let result = read_string(&mut env, &xml, "keybox xml")
        .and_then(|text| keybox_xml::parse_keybox_blob(&text));
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
    let result = read_string(&mut env, &pem, "PEM key")
        .and_then(|text| keybox_xml::decode_key_blob(&text));
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
    let result = read_string(&mut env, &pem, "PEM certificate")
        .and_then(|text| keybox_xml::decode_certificate(&text));
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
    let result = read_byte_array(&mut env, request, "attestation parse request")
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

/// Upper bound for a request blob crossing the JNI boundary. A certificate-chain request carries a
/// leaf key, a signing key, a full signing chain and an attestation extension, so it is the largest
/// thing the Kotlin side ever hands over; 16 MiB is well above any real keybox and small enough that
/// a corrupt or hostile caller cannot make the native heap grow without bound.
const MAX_REQUEST_BYTES: usize = 16 * 1024 * 1024;
/// Upper bound for a text argument (a keybox XML document or one PEM block). Real keyboxes are a
/// few tens of kilobytes; 8 MiB still leaves room for a generously padded document while capping
/// the UTF-8 copy that `get_string` performs.
const MAX_TEXT_BYTES: usize = 8 * 1024 * 1024;
/// Validates a JNI-reported length before any copy happens, so an oversized input is rejected while
/// it is still just a length and never materialised as a native allocation.
fn checked_length(len: i64, limit: usize, what: &str) -> Result<usize> {
    if len < 0 {
        return Err(CertGenError::InvalidParameter(format!(
            "{what} reported a negative length ({len})"
        )));
    }
    let len = len as usize;
    if len > limit {
        return Err(CertGenError::InvalidParameter(format!(
            "{what} is {len} elements, the accepted limit is {limit}"
        )));
    }
    Ok(len)
}
/// Copies a JNI byte array into a [`Zeroizing<Vec<u8>>`], rejecting a null handle so the builder
/// never sees a missing request. `what` names the buffer in the error, so a failure says which
/// entry point was called with bad input.
///
/// The buffer is zeroized on drop because every request blob can carry private key material (the
/// chain and hack requests embed PKCS#8 keys). The decode step copies what it needs into its own
/// `Zeroize`-implementing struct, but the raw transport buffer would otherwise survive in freed
/// heap memory after the call.
fn read_byte_array(env: &mut JNIEnv, array: jbyteArray, what: &str) -> Result<Zeroizing<Vec<u8>>> {
    if array.is_null() {
        return Err(CertGenError::InvalidParameter(format!("{what} was null")));
    }
    // SAFETY: a null handle was rejected above, so `array` points at a live `jbyteArray` that is
    // owned by the calling Java frame for the whole call. `JByteArray` is a transparent wrapper
    // around the raw pointer with no destructor (see `jni 0.21`: only `AutoLocal` issues
    // `DeleteLocalRef`), so `from_raw` cannot double-free, and the returned value never escapes
    // this function. Local references created by the caller are released by the VM when the JNI
    // call returns; no loop here accumulates them.
    let array = unsafe { JByteArray::from_raw(array) };
    // Check the length before copying: the array is still owned by the Java heap here, so an
    // oversized request costs the native side nothing.
    let len = env
        .get_array_length(&array)
        .map_err(|e| CertGenError::InvalidParameter(format!("{what} length read failed: {e}")))?;
    checked_length(len as i64, MAX_REQUEST_BYTES, what)?;
    env.convert_byte_array(&array)
        .map(Zeroizing::new)
        .map_err(|e| CertGenError::InvalidParameter(format!("{what} read failed: {e}")))
}
/// Copies a JNI string into a [`Zeroizing<String>`], rejecting a null handle so no parser sees a
/// missing input.
///
/// `jni` 0.21 exposes no string-length accessor, so the UTF-16 length cannot be inspected before
/// the copy. The cap is therefore enforced on the materialised UTF-8 bytes, which is the form the
/// parsers actually walk; the input is still rejected before any XML/PEM decoding starts.
///
/// The string is zeroized on drop: a keybox document or a PEM private key block carries the key
/// itself, and the decoded copies are wiped by their own `Drop` implementations.
fn read_string(env: &mut JNIEnv, value: &JString, what: &str) -> Result<Zeroizing<String>> {
    if value.is_null() {
        return Err(CertGenError::InvalidParameter(format!("{what} was null")));
    }
    let text: String = env
        .get_string(value)
        .map(String::from)
        .map_err(|e| CertGenError::InvalidParameter(format!("{what} read failed: {e}")))?;
    checked_length(text.len() as i64, MAX_TEXT_BYTES, what)?;
    Ok(Zeroizing::new(text))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_length_accepts_the_limit() {
        assert_eq!(
            checked_length(MAX_REQUEST_BYTES as i64, MAX_REQUEST_BYTES, "blob").ok(),
            Some(MAX_REQUEST_BYTES)
        );
    }

    #[test]
    fn checked_length_rejects_an_oversized_input() {
        assert!(checked_length(MAX_REQUEST_BYTES as i64 + 1, MAX_REQUEST_BYTES, "blob").is_err());
    }

    #[test]
    fn checked_length_rejects_a_negative_length() {
        assert!(checked_length(-1, MAX_REQUEST_BYTES, "blob").is_err());
    }
}
