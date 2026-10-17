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
import java.util.LinkedList
import java.util.concurrent.ConcurrentHashMap
import org.bouncycastle.asn1.ASN1Boolean
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERTaggedObject
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder

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
        val leafHolder = X509CertificateHolder(leaf.encoded)
        val extension = leafHolder.getExtension(ATTESTATION_OID) ?: return certificateChain
        hackLeafNative(leaf, uid)?.let { return it }
        val encodables = ASN1Sequence.getInstance(extension.extnValue.octets).toArray()
        // Some Android 11 Keymasters emit softwareEnforced/teeEnforced swapped.
        val teeIndex = if (containsRootOfTrust(encodables[6])) 6 else 7
        val teeEnforced = encodables[teeIndex] as ASN1Sequence

        var rootOfTrust: ASN1Encodable? = null
        val vector = ASN1EncodableVector()
        teeEnforced.forEach {
            (it as ASN1TaggedObject).let {
                if (it.tagNo == 704) rootOfTrust = it.baseObject.toASN1Primitive() else vector.add(it)
            }
        }

        val algorithm = leaf.publicKey.algorithm
        val keybox =
            KeyBoxUtils.keyboxes[algorithm]
                ?: KeyBoxUtils.keyboxes.entries.firstOrNull()?.value
                ?: throw UnsupportedOperationException("No keybox for algorithm: $algorithm")
        val certs = LinkedList(keybox.certificates)
        val builder =
            X509v3CertificateBuilder(
                X509CertificateHolder(certs[0].encoded).subject,
                leafHolder.serialNumber,
                leafHolder.notBefore,
                leafHolder.notAfter,
                leafHolder.subject,
                leafHolder.subjectPublicKeyInfo,
            )
        builder.addExtension(hackAttestExtension(rootOfTrust, vector, encodables, teeIndex, uid))
        leafHolder.extensions.extensionOIDs.forEach { oid ->
            if (oid.id != ATTESTATION_OID.id) builder.addExtension(leafHolder.getExtension(oid))
        }
        val leafDigest = leaf.sigAlgName.substringBefore("with", "SHA256")
        val keyboxSignerAlgo =
            when (keybox.keyPair.private) {
                is java.security.interfaces.ECPrivateKey -> "ECDSA"
                is java.security.interfaces.RSAPrivateKey -> "RSA"
                else ->
                    throw UnsupportedOperationException(
                        "Unsupported keybox signing key algorithm: ${keybox.keyPair.private.algorithm}"
                    )
            }
        certs.addFirst(
            JcaX509CertificateConverter()
                .getCertificate(
                    builder.build(
                        JcaContentSignerBuilder("${leafDigest}with$keyboxSignerAlgo").build(keybox.keyPair.private)
                    )
                )
        )
        return certs.toTypedArray()
    }

    /**
     * Native-first leaf hack: packs the request the Rust `hack_leaf` module expects, calls it, and
     * parses the returned leaf-first DER chain. Returns null — so the caller falls back to the
     * BouncyCastle path — when the native library is unavailable, no keybox matches, or the rewrite
     * fails.
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
            Logger.e("Native leaf hack failed; falling back to BouncyCastle", t)
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
            if (leaf.getExtensionValue(ATTESTATION_OID.id) == null) return certificate
            leafAlgorithms[KeyIdentifier(alias, uid)] = leaf.publicKey.algorithm
            val hacked = hackLeaf(arrayOf(leaf), uid)
            hacked[0].encoded
        } catch (t: Throwable) {
            Logger.e("Failed to hack user certificate", t)
            certificate
        }
    }

    private fun hackAttestExtension(
        originalRootOfTrust: ASN1Encodable?,
        vector: ASN1EncodableVector,
        originalEncodables: Array<ASN1Encodable>,
        teeIndex: Int,
        uid: Int,
    ): Extension {
        val verifiedBootKey = AndroidUtils.bootKey
        var verifiedBootHash: ByteArray? = null

        try {
            if (originalRootOfTrust is ASN1Sequence) {
                verifiedBootHash = CertificateUtils.getByteArrayFromAsn1(originalRootOfTrust.getObjectAt(3))
            }
        } catch (t: Throwable) {
            Logger.e("Failed to get verified boot hash from original, using generated", t)
        }

        if (verifiedBootHash == null) {
            verifiedBootHash = AndroidUtils.getBootHashFromProp()
        }

        val rootOfTrustElements =
            arrayOf(
                DEROctetString(verifiedBootKey),
                ASN1Boolean.TRUE,
                ASN1Enumerated(0),
                DEROctetString(verifiedBootHash),
            )
        val hackedRootOfTrust = DERSequence(rootOfTrustElements)

        val patch = AndroidUtils.resolvePatchLevels(uid)
        val osPatch = patch.osOverride
        val vendorPatch = patch.vendorOverride
        val bootPatch = patch.bootOverride

        val rebuilt = mutableListOf<ASN1TaggedObject>()
        for (i in 0 until vector.size()) {
            val obj = vector.get(i)
            if (obj !is ASN1TaggedObject) continue
            // 704 (root of trust) and 705 (os version) are always rebuilt. A patch level is
            // stripped only when overridden or omitted; device_default (null) keeps the
            // original, correctly-sourced value (e.g. boot from the boot image header).
            when (obj.tagNo) {
                704,
                705 -> continue
                706 -> if (osPatch != null) continue
                718 -> if (vendorPatch != null) continue
                719 -> if (bootPatch != null) continue
            }
            rebuilt.add(obj)
        }
        rebuilt.add(DERTaggedObject(true, 705, ASN1Integer(AndroidUtils.osVersion.toLong())))
        if (osPatch != null && osPatch != AndroidUtils.DO_NOT_REPORT)
            rebuilt.add(DERTaggedObject(true, 706, ASN1Integer(osPatch.toLong())))
        if (vendorPatch != null && vendorPatch != AndroidUtils.DO_NOT_REPORT)
            rebuilt.add(DERTaggedObject(true, 718, ASN1Integer(vendorPatch.toLong())))
        if (bootPatch != null && bootPatch != AndroidUtils.DO_NOT_REPORT)
            rebuilt.add(DERTaggedObject(true, 719, ASN1Integer(bootPatch.toLong())))
        rebuilt.add(DERTaggedObject(704, hackedRootOfTrust))
        rebuilt.sortBy { it.tagNo }

        val rebuiltVector = ASN1EncodableVector()
        rebuilt.forEach { rebuiltVector.add(it) }

        val hackEnforced = DERSequence(rebuiltVector)
        originalEncodables[teeIndex] = hackEnforced
        val hackedSequence = DERSequence(originalEncodables)
        val hackedSequenceOctets = DEROctetString(hackedSequence)

        return Extension(ATTESTATION_OID, false, hackedSequenceOctets)
    }

    private fun containsRootOfTrust(list: ASN1Encodable): Boolean {
        if (list !is ASN1Sequence) return false
        return list.toArray().any { it is ASN1TaggedObject && it.tagNo == 704 }
    }
}
