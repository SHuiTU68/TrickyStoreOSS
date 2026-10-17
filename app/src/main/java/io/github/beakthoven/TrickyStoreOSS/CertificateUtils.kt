/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS

import android.security.keymaster.KeymasterDefs
import android.system.keystore2.KeyEntryResponse
import android.system.keystore2.KeyMetadata
import io.github.beakthoven.TrickyStoreOSS.logging.Logger
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.nio.charset.StandardCharsets
import java.security.cert.Certificate
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/** The KeyMint attestation extension OID (`1.3.6.1.4.1.11129.2.1.17`). */
const val ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17"

object CertificateUtils {
    val certificateFactory: CertificateFactory by lazy {
        try {
            CertificateFactory.getInstance("X.509")
        } catch (t: Throwable) {
            Logger.e("Failed to initialize certificate factory", t)
            throw RuntimeException("Cannot initialize certificate factory", t)
        }
    }

    fun digestName(digest: Int, hyphenated: Boolean): String {
        val suffix =
            when (digest) {
                KeymasterDefs.KM_DIGEST_SHA1 -> "1"
                KeymasterDefs.KM_DIGEST_SHA_2_224 -> "224"
                KeymasterDefs.KM_DIGEST_SHA_2_256 -> "256"
                KeymasterDefs.KM_DIGEST_SHA_2_384 -> "384"
                KeymasterDefs.KM_DIGEST_SHA_2_512 -> "512"
                else -> "256"
            }
        return if (hyphenated) "SHA-$suffix" else "SHA$suffix"
    }

    fun ByteArray?.toCertificate(): X509Certificate? {
        return this?.let { bytes ->
            try {
                certificateFactory.generateCertificate(ByteArrayInputStream(bytes)) as? X509Certificate
            } catch (e: CertificateException) {
                Logger.w("Couldn't parse certificate in keystore", e)
                null
            }
        }
    }

    @Suppress("UNCHECKED_CAST")
    fun ByteArray?.toCertificates(): Collection<X509Certificate> {
        return this?.let { bytes ->
            try {
                certificateFactory.generateCertificates(ByteArrayInputStream(bytes)) as Collection<X509Certificate>
            } catch (e: CertificateException) {
                Logger.w("Couldn't parse certificates in keystore", e)
                emptyList()
            }
        } ?: emptyList()
    }

    fun Collection<Certificate>.toByteArray(): ByteArray? {
        val raw = runCatching {
            ByteArrayOutputStream().use { outputStream ->
                forEach { cert -> outputStream.write(cert.encoded) }
                outputStream.toByteArray()
            }
        }
        return raw.onFailure { Logger.w("Failed to convert certificates to byte array", it) }.getOrNull()
    }

    fun KeyEntryResponse?.getCertificateChain(): Array<Certificate>? {
        val metadata = this?.metadata ?: return null
        val leafCert = metadata.certificate?.toCertificate() ?: return null

        return when (val chainBytes = metadata.certificateChain) {
            null -> arrayOf(leafCert)
            else -> (listOf<Certificate>(leafCert) + chainBytes.toCertificates()).toTypedArray()
        }
    }

    /** A decoded PEM private key: the JCA algorithm name plus the PKCS#8 DER. */
    data class PemKey(val algorithm: String, val pkcs8: ByteArray)

    // Private key / certificate parsing runs in the native Rust decoder; there is no BouncyCastle
    // fallback any more.
    fun decodePemKey(keyContent: String): Result<PemKey> = runCatching {
        decodePemKeyNative(keyContent)
            ?: throw IllegalStateException("Native PEM key decoder unavailable")
    }

    fun parseCertificate(certContent: String): Result<Certificate> = runCatching {
        decodePemCertificateNative(certContent)
            ?: throw IllegalStateException("Native PEM certificate decoder unavailable")
    }

    /** Decodes the PEM key with the native Rust reader, returning null when the library is unavailable. */
    private fun decodePemKeyNative(keyContent: String): PemKey? {
        if (!NativeCertGen.isAvailable) return null
        return try {
            val data = DataInputStream(ByteArrayInputStream(NativeCertGen.nativeDecodePemKey(keyContent)))
            val algorithm = String(readNativeBlob(data), StandardCharsets.UTF_8)
            val pkcs8 = readNativeBlob(data)
            if (data.available() != 0) throw IllegalStateException("Trailing bytes in native PEM key response")
            PemKey(algorithm, pkcs8)
        } catch (t: Throwable) {
            Logger.w("Native PEM key decode failed", t)
            null
        }
    }

    /** Decodes the PEM certificate with the native Rust reader, returning null when it is unavailable. */
    private fun decodePemCertificateNative(certContent: String): Certificate? {
        if (!NativeCertGen.isAvailable) return null
        return try {
            certificateFactory.generateCertificate(
                ByteArrayInputStream(NativeCertGen.nativeDecodePemCertificate(certContent))
            )
        } catch (t: Throwable) {
            Logger.w("Native PEM certificate decode failed", t)
            null
        }
    }

    private fun readNativeBlob(data: DataInputStream): ByteArray {
        val length = data.readInt()
        if (length < 0 || length > data.available()) {
            throw IllegalStateException("Invalid native PEM field length: $length")
        }
        val bytes = ByteArray(length)
        data.readFully(bytes)
        return bytes
    }
}

fun KeyMetadata.putCertificateChain(chain: Array<Certificate>): Result<Unit> {
    return runCatching {
        if (chain.isEmpty()) return@runCatching

        certificate = chain[0].encoded

        if (chain.size > 1) {
            ByteArrayOutputStream().use { output ->
                for (i in 1 until chain.size) {
                    output.write(chain[i].encoded)
                }
                certificateChain = output.toByteArray()
            }
        } else {
            certificateChain = null
        }
    }
}

fun KeyEntryResponse.putCertificateChain(chain: Array<Certificate>): Result<Unit> {
    return runCatching { metadata.putCertificateChain(chain).getOrThrow() }
}
