/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS

import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyParameterValue
import android.hardware.security.keymint.Tag
import android.system.keystore2.Authorization
import io.github.beakthoven.TrickyStoreOSS.logging.Logger
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.util.concurrent.ConcurrentHashMap

object CertificateHack {
    data class KeyIdentifier(val alias: String, val uid: Int)

    val leafAlgorithms = ConcurrentHashMap<KeyIdentifier, String>()

    fun patchAuthorizations(authorizations: Array<Authorization>?, uid: Int): Array<Authorization>? {
        if (authorizations == null) return null
        val patch = AndroidUtils.resolvePatchLevels(uid)
        val os = patch.osOverride
        val vendor = patch.vendorOverride
        val boot = patch.bootOverride
        return authorizations
            .mapNotNull { auth ->
                val tag = auth.keyParameter.tag
                val override =
                    when (tag) {
                        Tag.OS_PATCHLEVEL -> os
                        Tag.VENDOR_PATCHLEVEL -> vendor
                        Tag.BOOT_PATCHLEVEL -> boot
                        else -> return@mapNotNull auth
                    }
                if (override == null) return@mapNotNull auth // device_default: keep the real value
                if (override == AndroidUtils.DO_NOT_REPORT) return@mapNotNull null // "no": omit
                Authorization().apply {
                    securityLevel = auth.securityLevel
                    keyParameter =
                        KeyParameter().apply {
                            this.tag = tag
                            this.value = KeyParameterValue.integer(override)
                        }
                }
            }
            .toTypedArray()
    }

    fun clearLeafAlgorithms() {
        leafAlgorithms.clear()
    }

    private fun hackLeaf(certificateChain: Array<Certificate>, uid: Int): Array<Certificate> {
        val leaf =
            CertificateUtils.certificateFactory.generateCertificate(ByteArrayInputStream(certificateChain[0].encoded))
                as X509Certificate
        // The native leaf hack rejects a leaf without the attestation extension, so the chain is
        // returned unchanged whenever the rewrite is unavailable or rejected.
        return hackLeafNative(leaf, uid) ?: certificateChain
    }

    /**
     * Native leaf hack: packs the request the Rust `hack_leaf` module expects, calls it, and parses
     * the returned leaf-first DER chain. Returns null when the native library is unavailable, no
     * keybox matches, or the rewrite fails, so the caller leaves the chain unchanged.
     */
    private fun hackLeafNative(leaf: X509Certificate, uid: Int): Array<Certificate>? {
        if (!NativeCertGen.isAvailable) return null
        val keybox = selectKeybox(leaf.publicKey.algorithm) ?: return null
        return try {
            val hacked = NativeCertGen.nativeHackCertificateChain(buildNativeHackRequest(leaf, keybox, uid))
            val certs = CertificateUtils.run { hacked.toCertificates() }
            if (certs.isEmpty()) return null
            certs.map { it as Certificate }.toTypedArray()
        } catch (t: Throwable) {
            Logger.e("Native leaf hack failed", t)
            null
        }
    }

    private fun selectKeybox(algorithm: String): CertificateGen.KeyBox? =
        KeyBoxUtils.keyboxes[algorithm] ?: KeyBoxUtils.keyboxes.entries.firstOrNull()?.value

    /** Packs the Rust `hack_leaf` request blob: big-endian, length-prefixed (see that module). */
    private fun buildNativeHackRequest(leaf: X509Certificate, keybox: CertificateGen.KeyBox, uid: Int): ByteArray {
        val patch = AndroidUtils.resolvePatchLevels(uid)
        val out = ByteArrayOutputStream()
        DataOutputStream(out).use { data ->
            writeBlob(data, leaf.encoded)
            writeBlob(data, keybox.keyPair.private.encoded)
            writeBlob(data, CertificateUtils.run { keybox.certificates.toByteArray() } ?: ByteArray(0))
            writeBlob(data, AndroidUtils.bootKey)
            writeBlob(data, AndroidUtils.getBootHashFromProp() ?: ByteArray(0))
            data.writeInt(AndroidUtils.osVersion)
            writeOptionalInt(data, patch.osOverride)
            writeOptionalInt(data, patch.vendorOverride)
            writeOptionalInt(data, patch.bootOverride)
        }
        return out.toByteArray()
    }

    private fun writeBlob(data: DataOutputStream, bytes: ByteArray) {
        data.writeInt(bytes.size)
        data.write(bytes)
    }

    private fun writeOptionalInt(data: DataOutputStream, value: Int?) {
        if (value == null) {
            data.writeByte(0)
        } else {
            data.writeByte(1)
            data.writeInt(value)
        }
    }

    fun hackCertificateChain(certificateChain: Array<Certificate>?, uid: Int): Array<Certificate> {
        if (certificateChain == null) throw UnsupportedOperationException("Certificate chain is null!")
        return try {
            hackLeaf(certificateChain, uid)
        } catch (t: Throwable) {
            Logger.e("Failed to hack certificate chain", t)
            certificateChain
        }
    }

    fun hackCACertificateChain(caList: ByteArray?, alias: String, uid: Int): ByteArray {
        if (caList == null) throw UnsupportedOperationException("CA list is null!")
        return try {
            val algorithm =
                leafAlgorithms.remove(KeyIdentifier(alias, uid))
                    ?: throw UnsupportedOperationException("No algorithm found for key ($alias, $uid)")
            val keybox =
                KeyBoxUtils.keyboxes[algorithm]
                    ?: KeyBoxUtils.keyboxes.entries.firstOrNull()?.value
                    ?: throw UnsupportedOperationException("Unsupported algorithm: $algorithm")
            CertificateUtils.run { keybox.certificates.toByteArray() } ?: caList
        } catch (t: Throwable) {
            Logger.e("Failed to hack CA certificate chain", t)
            caList
        }
    }

    fun hackUserCertificate(certificate: ByteArray?, alias: String, uid: Int): ByteArray {
        if (certificate == null) throw UnsupportedOperationException("Leaf certificate is null!")
        return try {
            val leaf =
                CertificateUtils.certificateFactory.generateCertificate(ByteArrayInputStream(certificate))
                    as X509Certificate
            if (leaf.getExtensionValue(ATTESTATION_OID) == null) return certificate
            leafAlgorithms[KeyIdentifier(alias, uid)] = leaf.publicKey.algorithm
            val hacked = hackLeaf(arrayOf(leaf), uid)
            hacked[0].encoded
        } catch (t: Throwable) {
            Logger.e("Failed to hack user certificate", t)
            certificate
        }
    }

}
