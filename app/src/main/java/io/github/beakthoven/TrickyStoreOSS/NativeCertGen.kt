/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS

import io.github.beakthoven.TrickyStoreOSS.logging.Logger
import java.io.File

/**
 * JNI bridge to the native `libcertgen.so` (Rust `native-certgen` crate).
 *
 * Key generation, the KeyMint attestation extension and certificate-chain building all run
 * natively. Key generation falls back to the platform provider when [isAvailable] is false or the
 * requested parameters are outside what the native crate supports; the certificate builders are
 * native-only and report an error when the library is unavailable.
 */
object NativeCertGen {
    // Magisk/KernelSU/APatch all mount modules at this fixed path, and the daemon starts from here.
    private const val LIBRARY_PATH = "/data/adb/modules/tricky_store/libcertgen.so"
    // Staged copy that exists while an update is pending, before the module directory is swapped in.
    private const val UPDATE_LIBRARY_PATH = "/data/adb/modules_update/tricky_store/libcertgen.so"
    @Volatile var isAvailable: Boolean = false
        private set
    /**
     * Loads `libcertgen.so`, trying the mounted module directory first, then the pending-update
     * directory, and finally the copy AGP unpacked into the APK's own `jniLibs`.
     *
     * Idempotent and synchronized: the daemon calls this once at startup, but tests and tooling may
     * call it again, and a second `System.load` of the same path would raise an error.
     */
    @Synchronized
    fun initialize() {
        if (isAvailable) return
        for (path in listOf(LIBRARY_PATH, UPDATE_LIBRARY_PATH)) {
            if (!File(path).isFile) continue
            if (load(path)) return
        }
        // The module directory is not mounted in this process (first boot after install, or the
        // daemon started from the APK); the APK's own copy is the same object file.
        if (loadLibrary("certgen")) return
        Logger.e("NativeCertGen: libcertgen.so unavailable; native certificate generation is disabled")
    }
    /** Loads one absolute path and records success; logs and returns false when the load fails. */
    private fun load(path: String): Boolean =
        try {
            System.load(path)
            markLoaded(path)
            true
        } catch (e: UnsatisfiedLinkError) {
            Logger.e("NativeCertGen: failed to load $path", e)
            false
        }
    /** Loads the copy resolved from the APK's `jniLibs` (`libcertgen.so`). */
    private fun loadLibrary(name: String): Boolean =
        try {
            System.loadLibrary(name)
            markLoaded("lib$name.so (APK jniLibs)")
            true
        } catch (e: UnsatisfiedLinkError) {
            Logger.d("NativeCertGen: no $name in the APK jniLibs")
            false
        }
    /**
     * Flips [isAvailable] and logs the version/self-test result, which is the only positive proof
     * that JNI is wired up and the linked crypto stack actually runs on this device.
     */
    private fun markLoaded(source: String) {
        isAvailable = true
        Logger.i("NativeCertGen: loaded $source (version=${nativeVersion()}, selfTest=${selfTest()})")
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

    /**
     * Decodes one PEM private key block natively and returns it as `[u32 BE algorithmLen][algorithm]
     * [u32 BE PKCS#8 len][PKCS#8 DER]` (see the Rust `keybox_xml` module), or throws if the label is
     * unsupported or the key is malformed.
     */
    external fun nativeDecodePemKey(pem: String): ByteArray

    /**
     * Decodes one PEM certificate block natively and returns its DER bytes (see the Rust
     * `keybox_xml` module), or throws if the label is unsupported or the body is not a certificate.
     */
    external fun nativeDecodePemCertificate(pem: String): ByteArray
}
