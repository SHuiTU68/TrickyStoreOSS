/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS

import android.hardware.security.keymint.Algorithm
import io.github.beakthoven.TrickyStoreOSS.CertificateGen.KeyGenParameters
import io.github.beakthoven.TrickyStoreOSS.logging.Logger
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.security.KeyFactory
import java.security.KeyPair
import java.security.cert.Certificate
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

/**
 * Persists issued keys on disk.
 *
 * The record format, its bounds checks, the SHA-256 file naming and the crash-safe write sequence
 * (`.tmp` at mode 0600, `fsync`, `rename`, directory `fsync`) all live in the Rust `persist` module,
 * reached through [NativeCertGen.nativePersistSave], [NativeCertGen.nativePersistLoad] and
 * [NativeCertGen.nativePersistDelete].
 *
 * What stays here is everything that needs a live Java heap: turning `KeyPair`, `SecretKey` and
 * `Certificate` into DER bytes and back, and the owner-identity gate, which has to ask this
 * device's keystore who owns a uid before a stored key may be handed out again.
 */
object PersistenceManager {
    private const val FORMAT_VERSION = 4
    private const val LEGACY_FORMAT_VERSION = 3
    private const val MAX_RECORD_BYTES = 16 * 1024 * 1024
    private const val MAX_INT_LIST_COUNT = 256
    private val dir = File("/data/adb/tricky_store/keys")

    data class UseState(
        val lifetimeRemaining: Int?,
        val perBootRemaining: Int?,
        val bootIdentity: String?,
    )

    sealed class LoadResult {
        data class Loaded(val keys: List<PersistedKey>, val skippedRecords: Int) : LoadResult()

        data class Failed(val reason: String) : LoadResult()
    }

    // single-threaded, off the binder thread — save/delete can't race
    private val keyLocks = java.util.concurrent.ConcurrentHashMap<String, Any>()

    private fun keyLock(uid: Int, alias: String): Any = keyLocks.computeIfAbsent("$uid:$alias") { Any() }

    data class PersistedKey(
        val uid: Int,
        val alias: String,
        val securityLevel: Int,
        val skipLeafHack: Boolean,
        val nspace: Long,
        val domain: Int,
        val keyPair: KeyPair?,
        val secretKey: SecretKey?,
        val chain: List<Certificate>,
        val params: KeyGenParameters,
        val metadataBytes: ByteArray?,
        val useState: UseState? = null,
        val ownerIdentityFingerprint: ByteArray? = null,
    )

    fun saveKey(
        uid: Int,
        alias: String,
        securityLevel: Int,
        skipLeafHack: Boolean,
        nspace: Long,
        domain: Int,
        keyPair: KeyPair?,
        secretKey: SecretKey?,
        chain: List<Certificate>?,
        metadataBytes: ByteArray?,
        params: KeyGenParameters,
    ): Boolean = saveKeySync(uid, alias, securityLevel, skipLeafHack, nspace, domain, keyPair, secretKey, chain, metadataBytes, params, null, null)

    fun saveKey(
        uid: Int,
        alias: String,
        securityLevel: Int,
        skipLeafHack: Boolean,
        nspace: Long,
        domain: Int,
        keyPair: KeyPair?,
        secretKey: SecretKey?,
        chain: List<Certificate>?,
        metadataBytes: ByteArray?,
        params: KeyGenParameters,
        useState: UseState,
    ): Boolean = saveKeySync(uid, alias, securityLevel, skipLeafHack, nspace, domain, keyPair, secretKey, chain, metadataBytes, params, useState, null)

    fun saveKey(
        uid: Int,
        alias: String,
        securityLevel: Int,
        skipLeafHack: Boolean,
        nspace: Long,
        domain: Int,
        keyPair: KeyPair?,
        secretKey: SecretKey?,
        chain: List<Certificate>?,
        metadataBytes: ByteArray?,
        params: KeyGenParameters,
        useState: UseState?,
        ownerIdentityFingerprint: ByteArray?,
    ): Boolean = saveKeySync(uid, alias, securityLevel, skipLeafHack, nspace, domain, keyPair, secretKey, chain, metadataBytes, params, useState, ownerIdentityFingerprint)

    private fun saveKeySync(
        uid: Int,
        alias: String,
        securityLevel: Int,
        skipLeafHack: Boolean,
        nspace: Long,
        domain: Int,
        keyPair: KeyPair?,
        secretKey: SecretKey?,
        chain: List<Certificate>?,
        metadataBytes: ByteArray?,
        params: KeyGenParameters,
        useState: UseState?,
        ownerIdentityFingerprint: ByteArray? = null,
    ): Boolean = synchronized(keyLock(uid, alias)) {
        if (!NativeCertGen.isAvailable) {
            Logger.e("Cannot persist key uid=$uid: native library unavailable")
            return@synchronized false
        }
        runCatching {
            val snapshot = serializeSnapshot(
                uid, alias, securityLevel, skipLeafHack, nspace, domain, keyPair, secretKey,
                chain, metadataBytes, params, useState, ownerIdentityFingerprint,
            )
            NativeCertGen.nativePersistSave(dir.path, snapshot)
        }.onFailure { Logger.e("Failed to persist key uid=$uid", it) }.getOrDefault(false)
    }

    /**
     * Encodes one record in the version-4 layout the Rust reader expects. Every limit the file
     * format enforces is checked natively before the bytes reach the disk, so this side only has to
     * get the field order right.
     */
    private fun serializeSnapshot(
        uid: Int, alias: String, securityLevel: Int, skipLeafHack: Boolean, nspace: Long, domain: Int,
        keyPair: KeyPair?, secretKey: SecretKey?, chain: List<Certificate>?, metadataBytes: ByteArray?,
        params: KeyGenParameters, useState: UseState?, ownerIdentityFingerprint: ByteArray?,
    ): ByteArray {
        val bytes = ByteArrayOutputStream()
        DataOutputStream(bytes).use { out ->
            out.writeByte(FORMAT_VERSION)
            out.writeInt(uid)
            out.writeUTF(alias)
            out.writeInt(securityLevel)
            out.writeBoolean(skipLeafHack)
            out.writeLong(nspace)
            out.writeInt(domain)
            out.writeBoolean(keyPair != null)
            if (keyPair != null) {
                val priv = keyPair.private.encoded
                val pub = keyPair.public.encoded
                out.writeInt(priv.size)
                out.write(priv)
                out.writeInt(pub.size)
                out.write(pub)
            }
            out.writeBoolean(secretKey != null)
            if (secretKey != null) {
                out.writeUTF(secretKey.algorithm)
                val secretBytes = secretKey.encoded
                out.writeInt(secretBytes.size)
                out.write(secretBytes)
            }

            val chainList = chain ?: emptyList()
            out.writeInt(chainList.size)
            chainList.forEach { c ->
                val b = c.encoded
                out.writeInt(b.size)
                out.write(b)
            }
            out.writeBoolean(metadataBytes != null)
            if (metadataBytes != null) {
                out.writeInt(metadataBytes.size)
                out.write(metadataBytes)
            }
            out.writeInt(params.algorithm)
            out.writeInt(params.keySize)
            out.writeInt(params.ecCurve)
            writeIntList(out, params.purpose)
            writeIntList(out, params.digest)
            writeIntList(out, params.padding)
            writeIntList(out, params.blockMode)
            writeIntList(out, params.mgfDigest)
            out.writeInt(params.usageCountLimit)
            val callerNonce = params.callerNonce
            out.writeBoolean(callerNonce != null)
            if (callerNonce != null) out.writeBoolean(callerNonce)
            val unlockedDeviceRequired = params.unlockedDeviceRequired
            out.writeBoolean(unlockedDeviceRequired != null)
            if (unlockedDeviceRequired != null) out.writeBoolean(unlockedDeviceRequired)
            val activeDateTime = params.activeDateTime
            out.writeBoolean(activeDateTime != null)
            if (activeDateTime != null) out.writeLong(activeDateTime)
            val originationExpireDateTime = params.originationExpireDateTime
            out.writeBoolean(originationExpireDateTime != null)
            if (originationExpireDateTime != null) out.writeLong(originationExpireDateTime)
            val usageExpireDateTime = params.usageExpireDateTime
            out.writeBoolean(usageExpireDateTime != null)
            if (usageExpireDateTime != null) out.writeLong(usageExpireDateTime)
            val noAuthRequired = params.noAuthRequired
            out.writeBoolean(noAuthRequired != null)
            if (noAuthRequired != null) out.writeBoolean(noAuthRequired)
            val origin = params.origin
            out.writeBoolean(origin != null)
            if (origin != null) out.writeInt(origin)
            val rsaExp = params.rsaPublicExponent
            out.writeBoolean(rsaExp != null)
            if (rsaExp != null) {
                val b = rsaExp.toByteArray()
                out.writeInt(b.size)
                out.write(b)
            }
            out.writeInt(params.maxUsesPerBoot)
            out.writeInt(params.userSecureIds.size)
            params.userSecureIds.forEach(out::writeLong)
            writeNullableInt(out, params.userAuthType)
            writeNullableInt(out, params.authTimeout)
            writeNullableBoolean(out, params.allowWhileOnBody)
            writeNullableBoolean(out, params.trustedUserPresenceRequired)
            writeNullableBoolean(out, params.trustedConfirmationRequired)
            out.writeInt(params.authPolicyProvenance.ordinal)
            out.writeBoolean(params.createdAtMs != null)
            params.createdAtMs?.let(out::writeLong)
            writeNullableInt(out, useState?.lifetimeRemaining)
            writeNullableInt(out, useState?.perBootRemaining)
            out.writeBoolean(useState?.bootIdentity != null)
            useState?.bootIdentity?.let(out::writeUTF)
            out.writeBoolean(ownerIdentityFingerprint != null)
            ownerIdentityFingerprint?.let { out.write(it.copyOf()) }
        }
        return bytes.toByteArray()
    }

    fun loadAll(): List<PersistedKey> = loadAll(null)

    /**
     * Reads every stored key. The Rust loader validates each file and canonicalises it, so a corrupt
     * record arrives in the failure list instead of aborting the whole sweep; [ownerIdentityForUid]
     * is then asked who owns the uid, and a record whose stored fingerprint is absent or different
     * stays on disk but is never handed out.
     */
    fun loadAll(ownerIdentityForUid: ((Int) -> ByteArray?)?): List<PersistedKey> {
        if (!NativeCertGen.isAvailable) {
            Logger.e("Cannot load persisted keys: native library unavailable")
            return emptyList()
        }
        val outcome = runCatching { decodeLoadOutcome(NativeCertGen.nativePersistLoad(dir.path)) }
            .onFailure { Logger.e("Failed to read persisted keys", it) }
            .getOrNull() ?: return emptyList()
        for ((fileName, message) in outcome.failures) {
            Logger.e("Failed to load persisted key from $fileName: $message")
        }
        val result = mutableListOf<PersistedKey>()
        for (blob in outcome.records) {
            val decoded = runCatching { decodeRecord(blob) }
                .onFailure { Logger.e("Failed to decode persisted key", it) }
                .getOrNull() ?: continue
            val key = decoded.key
            if (ownerIdentityForUid != null) {
                val currentFingerprint = ownerIdentityForUid(key.uid)
                val stored = key.ownerIdentityFingerprint
                if (stored == null || currentFingerprint == null || !stored.contentEquals(currentFingerprint)) {
                    Logger.w(
                        if (decoded.formatVersion == LEGACY_FORMAT_VERSION && stored == null)
                            "Preserved legacy format-3 key uid=${key.uid} alias=${key.alias} on disk; owner identity is unavailable, key access withheld, re-enrollment required"
                        else
                            "Preserved key uid=${key.uid} alias=${key.alias} on disk; owner identity is unknown or changed, key access withheld"
                    )
                    continue
                }
            }
            result.add(key)
        }
        return result
    }

    fun deleteKey(uid: Int, alias: String): Boolean = synchronized(keyLock(uid, alias)) {
        if (!NativeCertGen.isAvailable) {
            Logger.e("Cannot delete persisted key uid=$uid: native library unavailable")
            return@synchronized false
        }
        runCatching {
            NativeCertGen.nativePersistDelete(dir.path, uid, alias)
        }.onFailure { Logger.e("Failed to delete persisted key uid=$uid alias=$alias", it) }.getOrDefault(false)
    }

    private class DecodedRecord(val key: PersistedKey, val formatVersion: Int)

    private class LoadOutcome(val records: List<ByteArray>, val failures: List<Pair<String, String>>)

    /** Walks the loader blob: `[u32 ok]{[u32 len][record]}[u32 failed]{[utf8 name][utf8 message]}`. */
    private fun decodeLoadOutcome(blob: ByteArray): LoadOutcome {
        val ins = DataInputStream(ByteArrayInputStream(blob))
        val okCount = ins.readInt()
        require(okCount >= 0) { "negative record count" }
        val records = List(okCount) {
            val length = ins.readInt()
            require(length in 1..MAX_RECORD_BYTES) { "record length $length outside 1..$MAX_RECORD_BYTES" }
            ByteArray(length).also(ins::readFully)
        }
        val failedCount = ins.readInt()
        require(failedCount >= 0) { "negative failure count" }
        val failures = List(failedCount) { readUtf8(ins) to readUtf8(ins) }
        require(ins.available() == 0) { "trailing bytes after the loader response" }
        return LoadOutcome(records, failures)
    }

    /** Reads a `[u32 BE length][UTF-8]` string, the encoding the Rust `Encoder::text` writes. */
    private fun readUtf8(ins: DataInputStream): String {
        val length = ins.readInt()
        require(length in 0..MAX_RECORD_BYTES) { "string length $length is out of range" }
        val bytes = ByteArray(length)
        ins.readFully(bytes)
        return String(bytes, Charsets.UTF_8)
    }

    /**
     * Rebuilds the Java objects from one record blob. The natively validated bytes still have to be
     * walked here, because only the runtime knows how to turn DER into a `KeyPair` or `Certificate`.
     */
    private fun decodeRecord(blob: ByteArray): DecodedRecord {
        val ins = DataInputStream(ByteArrayInputStream(blob))
        val version = ins.readUnsignedByte()
        require(version == FORMAT_VERSION || version == LEGACY_FORMAT_VERSION) { "unsupported format $version" }
        val uid = ins.readInt()
        val alias = ins.readUTF()
        val securityLevel = ins.readInt()
        val skipLeafHack = ins.readBoolean()
        val nspace = ins.readLong()
        val domain = ins.readInt()
        var privBytes: ByteArray? = null
        var pubBytes: ByteArray? = null
        if (ins.readBoolean()) {
            val privSize = ins.readInt()
            privBytes = ByteArray(privSize).also(ins::readFully)
            val pubSize = ins.readInt()
            pubBytes = ByteArray(pubSize).also(ins::readFully)
        }
        var secretKey: SecretKey? = null
        if (ins.readBoolean()) {
            val algo = ins.readUTF()
            val secretSize = ins.readInt()
            val secretBytes = ByteArray(secretSize).also(ins::readFully)
            secretKey = SecretKeySpec(secretBytes, algo)
        }
        val cf = CertificateUtils.certificateFactory
        val chainSize = ins.readInt()
        val chain = List(chainSize) {
            val size = ins.readInt()
            val b = ByteArray(size).also(ins::readFully)
            cf.generateCertificate(ByteArrayInputStream(b))
        }
        var metadataBytes: ByteArray? = null
        if (ins.readBoolean()) {
            val metadataSize = ins.readInt()
            metadataBytes = ByteArray(metadataSize).also(ins::readFully)
        }
        val algorithm = ins.readInt()
        val keySize = ins.readInt()
        val ecCurve = ins.readInt()
        val purpose = readIntList(ins)
        val digest = readIntList(ins)
        val padding = readIntList(ins)
        val blockMode = readIntList(ins)
        val mgfDigest = readIntList(ins)
        val usageCountLimit = ins.readInt()
        val callerNonce = if (ins.readBoolean()) ins.readBoolean() else null
        val unlockedDeviceRequired = if (ins.readBoolean()) ins.readBoolean() else null
        val activeDateTime = if (ins.readBoolean()) ins.readLong() else null
        val originationExpireDateTime = if (ins.readBoolean()) ins.readLong() else null
        val usageExpireDateTime = if (ins.readBoolean()) ins.readLong() else null
        val noAuthRequired = if (ins.readBoolean()) ins.readBoolean() else null
        val origin = if (ins.readBoolean()) ins.readInt() else null
        val rsaExp =
            if (ins.readBoolean()) {
                val size = ins.readInt()
                val b = ByteArray(size).also(ins::readFully)
                java.math.BigInteger(b)
            } else null
        val maxUsesPerBoot: Int
        val userSecureIds: List<Long>
        val userAuthType: Int?
        val authTimeout: Int?
        val allowWhileOnBody: Boolean?
        val trustedUserPresenceRequired: Boolean?
        val trustedConfirmationRequired: Boolean?
        val authPolicyProvenance: CertificateGen.AuthPolicyProvenance
        val createdAtMs: Long?
        val useState: UseState?
        var ownerIdentityFingerprint: ByteArray? = null
        if (version >= FORMAT_VERSION) {
            maxUsesPerBoot = ins.readInt()
            val sidCount = ins.readInt()
            userSecureIds = List(sidCount) { ins.readLong() }
            userAuthType = readNullableInt(ins)
            authTimeout = readNullableInt(ins)
            allowWhileOnBody = readNullableBoolean(ins)
            trustedUserPresenceRequired = readNullableBoolean(ins)
            trustedConfirmationRequired = readNullableBoolean(ins)
            authPolicyProvenance = CertificateGen.AuthPolicyProvenance.entries.getOrElse(ins.readInt()) { CertificateGen.AuthPolicyProvenance.UNKNOWN }
            createdAtMs = if (ins.readBoolean()) ins.readLong() else null
            val lifetime = readNullableInt(ins)
            val perBoot = readNullableInt(ins)
            val boot = if (ins.readBoolean()) ins.readUTF() else null
            useState = UseState(lifetime, perBoot, boot)
            if (ins.readBoolean()) {
                ownerIdentityFingerprint = ByteArray(32).also(ins::readFully)
            }
        } else {
            maxUsesPerBoot = 0
            userSecureIds = emptyList()
            userAuthType = null
            authTimeout = null
            allowWhileOnBody = null
            trustedUserPresenceRequired = null
            trustedConfirmationRequired = null
            authPolicyProvenance = CertificateGen.AuthPolicyProvenance.UNKNOWN
            createdAtMs = null
            useState = UseState(if (usageCountLimit > 0) 0 else null, if (usageCountLimit > 0) 0 else null, null)
        }
        require(ins.available() == 0) { "trailing bytes in the record" }
        val keyPair: KeyPair? =
            if (privBytes != null && pubBytes != null) {
                val keyAlgo = if (algorithm == Algorithm.RSA) "RSA" else "EC"
                val kf = KeyFactory.getInstance(keyAlgo)
                KeyPair(
                    kf.generatePublic(X509EncodedKeySpec(pubBytes)),
                    kf.generatePrivate(PKCS8EncodedKeySpec(privBytes)),
                )
            } else null
        val params =
            KeyGenParameters().apply {
                this.algorithm = algorithm
                this.keySize = keySize
                this.ecCurve = ecCurve
                this.purpose = purpose.toMutableList()
                this.digest = digest.toMutableList()
                this.padding = padding.toMutableList()
                this.blockMode = blockMode.toMutableList()
                this.mgfDigest = mgfDigest.toMutableList()
                this.usageCountLimit = usageCountLimit
                this.maxUsesPerBoot = maxUsesPerBoot
                this.userSecureIds = userSecureIds.toMutableList()
                this.userAuthType = userAuthType
                this.authTimeout = authTimeout
                this.allowWhileOnBody = allowWhileOnBody
                this.trustedUserPresenceRequired = trustedUserPresenceRequired
                this.trustedConfirmationRequired = trustedConfirmationRequired
                this.authPolicyProvenance = authPolicyProvenance
                this.createdAtMs = createdAtMs
                this.callerNonce = callerNonce
                this.unlockedDeviceRequired = unlockedDeviceRequired
                this.activeDateTime = activeDateTime
                this.originationExpireDateTime = originationExpireDateTime
                this.usageExpireDateTime = usageExpireDateTime
                this.noAuthRequired = noAuthRequired
                this.origin = origin
                this.rsaPublicExponent = rsaExp
            }
        require(keyPair == null || keyPair.public.algorithm.equals(if (algorithm == Algorithm.RSA) "RSA" else "EC", ignoreCase = true))
        require(keyPair == null || chain.isEmpty() || chain.first().publicKey.encoded.contentEquals(keyPair.public.encoded))
        return DecodedRecord(
            PersistedKey(
                uid,
                alias,
                securityLevel,
                skipLeafHack,
                nspace,
                domain,
                keyPair,
                secretKey,
                chain,
                params,
                metadataBytes,
                useState,
                ownerIdentityFingerprint,
            ),
            version,
        )
    }

    private fun writeIntList(out: DataOutputStream, list: List<Int>) {
        require(list.size <= MAX_INT_LIST_COUNT)
        out.writeInt(list.size)
        list.forEach(out::writeInt)
    }

    private fun readIntList(ins: DataInputStream): List<Int> {
        val n = ins.readInt()
        require(n in 0..MAX_INT_LIST_COUNT) { "integer list count $n outside 0..$MAX_INT_LIST_COUNT" }
        return List(n) { ins.readInt() }
    }

    private fun writeNullableInt(out: DataOutputStream, value: Int?) {
        out.writeBoolean(value != null)
        value?.let(out::writeInt)
    }

    private fun readNullableInt(ins: DataInputStream): Int? = if (ins.readBoolean()) ins.readInt() else null

    private fun writeNullableBoolean(out: DataOutputStream, value: Boolean?) {
        out.writeBoolean(value != null)
        value?.let(out::writeBoolean)
    }

    private fun readNullableBoolean(ins: DataInputStream): Boolean? = if (ins.readBoolean()) ins.readBoolean() else null
}
