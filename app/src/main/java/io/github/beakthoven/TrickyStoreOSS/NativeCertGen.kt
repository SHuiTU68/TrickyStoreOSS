/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS

import io.github.beakthoven.TrickyStoreOSS.logging.Logger

/**
 * JNI bridge to the native `libcertgen.so` (Rust `native-certgen` crate).
 *
 * Key generation, the KeyMint attestation extension and certificate-chain building all run
 * natively; callers fall back to the BouncyCastle path whenever [isAvailable] is false or the
 * requested parameters are outside what the native crate supports.
 */
object NativeCertGen {
    // Magisk/KernelSU/APatch all mount modules at this fixed path, and the daemon starts from here.
    private const val LIBRARY_PATH = "/data/adb/modules/tricky_store/libcertgen.so"

    @Volatile var isAvailable: Boolean = false
        private set

    fun initialize() {
        try {
            System.load(LIBRARY_PATH)
            isAvailable = true
            Logger.i("NativeCertGen: loaded $LIBRARY_PATH (version=${nativeVersion()}, selfTest=${selfTest()})")
        } catch (e: UnsatisfiedLinkError) {
            Logger.e("NativeCertGen: failed to load $LIBRARY_PATH, falling back to BouncyCastle", e)
        }
    }

    external fun nativeVersion(): String

    external fun selfTest(): Boolean

    /**
     * Generates a key pair natively, returning `[u32 BE privLen][PKCS#8 DER][u32 BE pubLen][SPKI
     * DER]`, or throws if the algorithm/curve combination is unsupported natively.
     *
     * @param algorithm KeyMint [android.hardware.security.keymint.Algorithm] value.
     * @param ecCurve KeyMint [android.hardware.security.keymint.EcCurve] value; ignored for RSA.
     */
    external fun nativeGenerateKeyPair(
        algorithm: Int,
        keySize: Int,
        ecCurve: Int,
        rsaPublicExponent: Long,
    ): ByteArray

    /**
     * Builds the attestation certificate chain natively from a packed request blob (see the Rust
     * `chaingen` module) and returns the leaf-first, back-to-back concatenated DER certificates, or
     * throws if the request is unsupported or malformed.
     */
    external fun nativeBuildCertificateChain(request: ByteArray): ByteArray

    /**
     * Builds the KeyMint attestation extension — the DER-encoded `KeyDescription` wrapped in the
     * leaf certificate's `1.3.6.1.4.1.11129.2.1.17` extension — natively from a packed request blob
     * (see the Rust `attreq` module), or throws if the request is unsupported or malformed.
     */
    external fun nativeBuildAttestationExtension(request: ByteArray): ByteArray

    /**
     * Rewrites an existing leaf certificate's attestation extension — forging the `rootOfTrust` and
     * overriding the patch-level fields — then re-signs the leaf with the keybox, from a packed
     * request blob (see the Rust `hack_leaf` module). Returns the leaf-first, back-to-back
     * concatenated DER certificates, or throws if the request is unsupported or malformed.
     */
    external fun nativeHackCertificateChain(request: ByteArray): ByteArray

    /**
     * Parses a keybox XML document natively and returns the entries as `[u32 BE count]{ [u32 BE
     * algorithm][u32 BE PKCS#8 key]{ [u32 BE certCount]{ [u32 BE cert] } } }` (see the Rust
     * `keybox_xml` module), or throws if the document is unsupported or malformed.
     */
    external fun nativeParseKeybox(xml: String): ByteArray

    /**
     * Reads the verified-boot fields back out of a probe certificate's KeyMint attestation extension
     * natively from a packed request blob (see the Rust `attest_parse` module), returning them as
     * `[i32 BE attestVersion][i32 BE keymasterVersion][opt blob verifiedBootKey][opt blob
     * verifiedBootHash][opt i32 osVersion][opt blob moduleHash]`, or throws if the certificate is
     * unsupported or the challenge does not match.
     */
    external fun nativeParseAttestation(request: ByteArray): ByteArray
}
