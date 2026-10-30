/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS

import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyParameterValue
import android.hardware.security.keymint.Tag
import android.system.keystore2.Authorization
import io.github.beakthoven.TrickyStoreOSS.forge.ForgeClient
import io.github.beakthoven.TrickyStoreOSS.logging.Logger
import java.io.ByteArrayInputStream
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
        // returned unchanged whenever the rewrite is unavailable or rejected. Signing needs the
        // keybox, so the rewrite runs in the daemon and only the DER comes back here.
        return hackLeafRemote(leaf, uid) ?: certificateChain
    }

    /**
     * Daemon-side leaf hack: ships the leaf DER to the forge daemon, which re-signs it with the
     * keybox (the private key never leaves that process). Returns null — the caller keeps the
     * original chain — when the daemon is unreachable or rejects the request, exactly the fallback
     * the in-process native path had.
     */
    private fun hackLeafRemote(leaf: X509Certificate, uid: Int): Array<Certificate>? {
        val hacked = ForgeClient.hackLeaf(leaf.encoded, uid) ?: return null
        return try {
            val certs =
                hacked.mapNotNull { der ->
                    runCatching {
                        CertificateUtils.certificateFactory.generateCertificate(ByteArrayInputStream(der))
                            as Certificate
                    }.onFailure { Logger.e("Failed to parse hacked certificate", it) }.getOrNull()
                }
            if (certs.isEmpty()) return null
            certs.toTypedArray()
        } catch (t: Throwable) {
            Logger.e("Failed to rebuild hacked chain", t)
            null
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
            // The keybox CA chain lives in the daemon; ask it for the public DER only.
            ForgeClient.keyboxCertificates(algorithm) ?: caList
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
