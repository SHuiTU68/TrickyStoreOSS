/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS

import android.content.pm.PackageManager
import android.hardware.security.keymint.Algorithm
import android.hardware.security.keymint.EcCurve
import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyPurpose
import android.hardware.security.keymint.Tag
import android.os.Build
import android.os.ServiceSpecificException
import android.security.keymaster.KeymasterDefs
import android.security.keystore.KeyProperties
import android.system.keystore2.KeyDescriptor
import io.github.beakthoven.TrickyStoreOSS.config.PkgConfig
import io.github.beakthoven.TrickyStoreOSS.interceptors.SecurityLevelInterceptor
import io.github.beakthoven.TrickyStoreOSS.logging.Logger
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.io.File
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.Certificate
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.RSAKeyGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.Date

object CertificateGen {
    enum class AuthPolicyProvenance { UNKNOWN, RAW_REQUEST }

    data class KeyBox(val keyPair: KeyPair, val certificates: List<Certificate>)

    /**
     * The material used to sign a freshly generated leaf: the signing key and its certificate chain
     * as DER (leaf first). The native builder derives the issuer from that chain itself.
     */
    private class SigningMaterial(
        val keyPair: KeyPair,
        val certChainDer: ByteArray?,
    )

    data class KeyGenParameters(
        var keySize: Int = 0,
        var algorithm: Int = 0,
        var certificateSerial: BigInteger? = null,
        var certificateNotBefore: Date? = null,
        var certificateNotAfter: Date? = null,
        var certificateSubject: ByteArray? = null,
        var rsaPublicExponent: BigInteger? = null,
        var ecCurve: Int = 0,
        var ecCurveName: String? = null,
        var purpose: MutableList<Int> = mutableListOf(),
        var digest: MutableList<Int> = mutableListOf(),
        var padding: MutableList<Int> = mutableListOf(),
        var blockMode: MutableList<Int> = mutableListOf(),
        var mgfDigest: MutableList<Int> = mutableListOf(),
        var usageCountLimit: Int = 0,
        var maxUsesPerBoot: Int = 0,
        var userSecureIds: MutableList<Long> = mutableListOf(),
        var userAuthType: Int? = null,
        var authTimeout: Int? = null,
        var allowWhileOnBody: Boolean? = null,
        var trustedUserPresenceRequired: Boolean? = null,
        var trustedConfirmationRequired: Boolean? = null,
        var authPolicyProvenance: AuthPolicyProvenance = AuthPolicyProvenance.UNKNOWN,
        var createdAtMs: Long? = null,
        var callerNonce: Boolean? = null,
        var unlockedDeviceRequired: Boolean? = null,
        var activeDateTime: Long? = null,
        var originationExpireDateTime: Long? = null,
        var usageExpireDateTime: Long? = null,
        var attestationChallenge: ByteArray? = null,
        var brand: ByteArray? = null,
        var device: ByteArray? = null,
        var product: ByteArray? = null,
        var manufacturer: ByteArray? = null,
        var model: ByteArray? = null,
        var imei1: ByteArray? = null,
        var imei2: ByteArray? = null,
        var meid: ByteArray? = null,
        var serialno: ByteArray? = null,
        var includeUniqueId: Boolean? = null,
        var noAuthRequired: Boolean? = null,
        var origin: Int? = null,
    ) {
        constructor(params: Array<KeyParameter>) : this() {
            var authPolicyParsed = true
            params.forEach { p ->
                runCatching {
                        val v = p.value
                        when (p.tag) {
                            Tag.KEY_SIZE -> keySize = v.integer
                            Tag.ALGORITHM -> algorithm = v.algorithm
                            Tag.CERTIFICATE_SERIAL -> certificateSerial = BigInteger(v.blob)
                            Tag.CERTIFICATE_NOT_BEFORE -> certificateNotBefore = Date(v.dateTime)
                            Tag.CERTIFICATE_NOT_AFTER -> certificateNotAfter = Date(v.dateTime)
                            Tag.CERTIFICATE_SUBJECT -> certificateSubject = v.blob
                            Tag.RSA_PUBLIC_EXPONENT -> rsaPublicExponent = BigInteger.valueOf(v.longInteger)
                            Tag.EC_CURVE -> {
                                ecCurve = v.ecCurve
                                ecCurveName = resolveEcCurveName(ecCurve, 0)
                            }
                            Tag.PURPOSE -> purpose.add(v.keyPurpose)
                            Tag.DIGEST -> digest.add(v.digest)
                            Tag.PADDING -> padding.add(v.paddingMode)
                            Tag.BLOCK_MODE -> blockMode.add(v.blockMode)
                            Tag.RSA_OAEP_MGF_DIGEST -> mgfDigest.add(v.digest)
                            Tag.USAGE_COUNT_LIMIT -> usageCountLimit = v.integer
                            Tag.MAX_USES_PER_BOOT -> maxUsesPerBoot = v.integer
                            Tag.USER_SECURE_ID -> userSecureIds.add(v.longInteger)
                            Tag.USER_AUTH_TYPE -> userAuthType = v.hardwareAuthenticatorType
                            Tag.AUTH_TIMEOUT -> authTimeout = v.integer
                            Tag.ALLOW_WHILE_ON_BODY -> allowWhileOnBody = v.boolValue
                            Tag.TRUSTED_USER_PRESENCE_REQUIRED -> trustedUserPresenceRequired = v.boolValue
                            Tag.TRUSTED_CONFIRMATION_REQUIRED -> trustedConfirmationRequired = v.boolValue
                            Tag.CALLER_NONCE -> callerNonce = v.boolValue
                            Tag.UNLOCKED_DEVICE_REQUIRED -> unlockedDeviceRequired = v.boolValue
                            Tag.ACTIVE_DATETIME -> activeDateTime = v.dateTime
                            Tag.ORIGINATION_EXPIRE_DATETIME -> originationExpireDateTime = v.dateTime
                            Tag.USAGE_EXPIRE_DATETIME -> usageExpireDateTime = v.dateTime
                            Tag.ATTESTATION_CHALLENGE -> attestationChallenge = v.blob
                            Tag.ATTESTATION_ID_BRAND -> brand = v.blob
                            Tag.ATTESTATION_ID_DEVICE -> device = v.blob
                            Tag.ATTESTATION_ID_PRODUCT -> product = v.blob
                            Tag.ATTESTATION_ID_MANUFACTURER -> manufacturer = v.blob
                            Tag.ATTESTATION_ID_MODEL -> model = v.blob
                            Tag.ATTESTATION_ID_IMEI -> imei1 = v.blob
                            Tag.ATTESTATION_ID_SECOND_IMEI -> imei2 = v.blob
                            Tag.ATTESTATION_ID_MEID -> meid = v.blob
                            Tag.ATTESTATION_ID_SERIAL -> serialno = v.blob
                            Tag.INCLUDE_UNIQUE_ID -> includeUniqueId = v.boolValue
                            Tag.NO_AUTH_REQUIRED -> noAuthRequired = v.boolValue
                            Tag.ORIGIN -> origin = v.origin
                        }
                    }
                    .onFailure {
                        if (
                            p.tag == Tag.USER_SECURE_ID || p.tag == Tag.USER_AUTH_TYPE || p.tag == Tag.AUTH_TIMEOUT ||
                                p.tag == Tag.ALLOW_WHILE_ON_BODY || p.tag == Tag.TRUSTED_USER_PRESENCE_REQUIRED ||
                                p.tag == Tag.TRUSTED_CONFIRMATION_REQUIRED || p.tag == Tag.UNLOCKED_DEVICE_REQUIRED ||
                                p.tag == Tag.NO_AUTH_REQUIRED
                        )
                            authPolicyParsed = false
                        Logger.d("Skipping key parameter tag=${p.tag}: ${it.message}")
                    }
            }
            authPolicyProvenance =
                if (authPolicyParsed) AuthPolicyProvenance.RAW_REQUEST else AuthPolicyProvenance.UNKNOWN
            if (ecCurveName == null && keySize != 0) ecCurveName = resolveEcCurveName(0, keySize)
        }

        val noAuthRequiredIsValid: Boolean
            get() =
                authPolicyProvenance == AuthPolicyProvenance.RAW_REQUEST &&
                    noAuthRequired == true &&
                    userSecureIds.isEmpty() &&
                    userAuthType == null &&
                    authTimeout == null &&
                    allowWhileOnBody != true &&
                    trustedUserPresenceRequired != true &&
                    trustedConfirmationRequired != true &&
                    unlockedDeviceRequired != true
    }

    private data class EcCurveInfo(val curve: Int, val name: String, val size: Int)

    // Only the sizes the Rust keygen crate accepts; anything else uses the platform provider.
    private val RSA_NATIVE_KEY_SIZES = setOf(2048, 3072, 4096)

    // P_256 before CURVE_25519 so that fallback maps 256 -> secp256r1
    private val EC_CURVES =
        listOf(
            EcCurveInfo(EcCurve.P_224, "secp224r1", 224),
            EcCurveInfo(EcCurve.P_256, "secp256r1", 256),
            EcCurveInfo(EcCurve.P_384, "secp384r1", 384),
            EcCurveInfo(EcCurve.P_521, "secp521r1", 521),
            EcCurveInfo(EcCurve.CURVE_25519, "CURVE_25519", 256),
        )

    fun effectiveKeySize(params: KeyGenParameters): Int {
        if (params.keySize > 0) return params.keySize
        if (params.algorithm != Algorithm.EC) return 0
        return EC_CURVES.firstOrNull { it.name == params.ecCurveName }?.size ?: 256
    }

    fun generateKeyPair(params: KeyGenParameters): KeyPair? {
        generateNativeKeyPair(params)?.let { return it }

        val raw = runCatching {
            when (params.algorithm) {
                Algorithm.EC -> {
                    Logger.d("Generating EC keypair of size ${params.keySize}")
                    KeyPairGenerator.getInstance("EC")
                        .apply { initialize(ECGenParameterSpec(params.ecCurveName ?: "secp256r1")) }
                        .generateKeyPair()
                }

                Algorithm.RSA -> {
                    Logger.d("Generating RSA keypair of size ${params.keySize}")
                    KeyPairGenerator.getInstance("RSA")
                        .apply {
                            initialize(
                                RSAKeyGenParameterSpec(
                                    params.keySize,
                                    params.rsaPublicExponent ?: RSAKeyGenParameterSpec.F4,
                                )
                            )
                        }
                        .generateKeyPair()
                }

                else -> {
                    Logger.i("Skipping non-EC/non-RSA algorithm: ${params.algorithm}")
                    null
                }
            }
        }
        return raw.onFailure { Logger.e("Failed to generate key pair", it) }.getOrNull()
    }

    /**
     * Runs key generation in Rust. Returns null — so the caller falls back to the platform
     * provider — whenever the native library is unavailable, the requested algorithm/curve is
     * unsupported natively, or the native call fails.
     */
    private fun generateNativeKeyPair(params: KeyGenParameters): KeyPair? {
        if (!NativeCertGen.isAvailable) return null

        val (factoryAlgorithm, ecCurve) =
            when (params.algorithm) {
                Algorithm.EC ->
                    when (params.ecCurveName) {
                        null, "secp256r1" -> KeyProperties.KEY_ALGORITHM_EC to EcCurve.P_256
                        "secp384r1" -> KeyProperties.KEY_ALGORITHM_EC to EcCurve.P_384
                        else -> return null
                    }

                Algorithm.RSA ->
                    if (params.keySize in RSA_NATIVE_KEY_SIZES) {
                        KeyProperties.KEY_ALGORITHM_RSA to 0
                    } else {
                        return null
                    }

                else -> return null
            }

        val blob =
            runCatching {
                    NativeCertGen.nativeGenerateKeyPair(
                        params.algorithm,
                        params.keySize,
                        ecCurve,
                        (params.rsaPublicExponent ?: RSAKeyGenParameterSpec.F4).toLong(),
                    )
                }
                .onFailure { Logger.d("Native keygen unavailable for this request: ${it.message}") }
                .getOrNull() ?: return null

        return runCatching {
                val buffer = ByteBuffer.wrap(blob)
                val privateKey = buffer.readLengthPrefixed()
                val publicKey = buffer.readLengthPrefixed()
                val factory = KeyFactory.getInstance(factoryAlgorithm)
                KeyPair(
                    factory.generatePublic(X509EncodedKeySpec(publicKey)),
                    factory.generatePrivate(PKCS8EncodedKeySpec(privateKey)),
                )
            }
            .onFailure { Logger.e("Failed to rebuild KeyPair from native keygen output", it) }
            .getOrNull()
    }

    private fun ByteBuffer.readLengthPrefixed(): ByteArray {
        val length = int
        require(length in 0..remaining()) { "Malformed native keygen blob" }
        val bytes = ByteArray(length)
        get(bytes)
        return bytes
    }

    fun generateKeyPair(
        uid: Int,
        descriptor: KeyDescriptor,
        attestKeyDescriptor: KeyDescriptor?,
        params: KeyGenParameters,
        securityLevel: Int = 1,
    ): Pair<KeyPair, List<Certificate>>? {
        val raw = runCatching {
            Logger.i("Requested KeyPair with alias: ${descriptor.alias}")
            attestKeyDescriptor?.let { Logger.i("Requested KeyPair with attestKey: ${it.alias}") }

            params.createdAtMs = params.createdAtMs ?: System.currentTimeMillis()
            val keyPair = generateKeyPair(params) ?: return null
            val keybox = getKeyboxForAlgorithm(params.algorithm) ?: return null
            if (keybox.certificates.isEmpty()) {
                Logger.e("Keybox has no certificates")
                return null
            }

            val signing =
                if (attestKeyDescriptor != null) {
                    getAttestationKeyInfo(uid, attestKeyDescriptor, securityLevel)
                } else {
                    keyboxSigningMaterial(keybox)
                }

            // A designated attestation key signs a standalone leaf; the keybox case appends the
            // whole keybox chain after it.
            val appendSigningChain = attestKeyDescriptor == null
            val chain =
                buildChain(keyPair, params, signing, uid, securityLevel, appendSigningChain)
            keyPair to chain
        }
        raw.exceptionOrNull()?.let { if (it is ServiceSpecificException) throw it }
        return raw.onFailure { Logger.e("Failed to generate key pair with certificates", it) }.getOrNull()
    }

    private fun getKeyboxForAlgorithm(algorithm: Int): KeyBox? {
        val name =
            when (algorithm) {
                Algorithm.EC -> KeyProperties.KEY_ALGORITHM_EC

                Algorithm.RSA -> KeyProperties.KEY_ALGORITHM_RSA

                else -> {
                    Logger.e("Unsupported algorithm: $algorithm")
                    null
                }
            } ?: return null
        return KeyBoxUtils.keyboxes[name] ?: KeyBoxUtils.keyboxes.values.firstOrNull()
    }

    private fun getAttestationKeyInfo(
        uid: Int,
        descriptor: KeyDescriptor,
        securityLevel: Int,
    ): SigningMaterial {
        val resolved = SecurityLevelInterceptor.resolveDesignatedAttestationKey(uid, descriptor)
            ?: throw ServiceSpecificException(
                KeymasterDefs.KM_ERROR_INVALID_ARGUMENT,
                "Designated attestation key not found",
            )
        if (!resolved.allowed) {
            throw ServiceSpecificException(
                android.system.keystore2.ResponseCode.PERMISSION_DENIED,
                "Designated attestation key access denied",
            )
        }
        val info = resolved.info
            ?: throw ServiceSpecificException(
                KeymasterDefs.KM_ERROR_INVALID_ARGUMENT,
                "Designated attestation key is unresolved",
            )
        val keyPair = info.keyPair
        val certificates =
            info.response.metadata?.certificate?.let { leaf ->
                CertificateUtils.run { leaf.toCertificates() }
            }
        val storedPurposes =
            info.response.metadata?.authorizations
                ?.filter { it.securityLevel == securityLevel && it.keyParameter.tag == Tag.PURPOSE }
                ?.map { it.keyParameter.value.keyPurpose }
        val attestPurpose = storedPurposes == listOf(KeyPurpose.ATTEST_KEY)
        val supportedAlgorithm = keyPair?.private is java.security.interfaces.ECPrivateKey ||
            keyPair?.private is java.security.interfaces.RSAPrivateKey
        if (
            !attestPurpose ||
                info.params.purpose != listOf(KeyPurpose.ATTEST_KEY) ||
                !supportedAlgorithm ||
                certificates.isNullOrEmpty() ||
                !certificates.first().publicKey.encoded.contentEquals(keyPair!!.public.encoded)
        ) {
            throw ServiceSpecificException(
                KeymasterDefs.KM_ERROR_INVALID_ARGUMENT,
                "Designated attest key is invalid for security level $securityLevel",
            )
        }
        val signingKey = keyPair!!
        return SigningMaterial(
            keyPair = signingKey,
            certChainDer = CertificateUtils.run { certificates.toByteArray() },
        )
    }

    /** Wraps a keybox as the signing material for the freshly minted leaf. */
    private fun keyboxSigningMaterial(keybox: KeyBox): SigningMaterial =
        SigningMaterial(
            keyPair = keybox.keyPair,
            certChainDer = CertificateUtils.run { keybox.certificates.toByteArray() },
        )

    private fun resolveEcCurveName(curve: Int, keySize: Int): String =
        EC_CURVES.firstOrNull { it.curve == curve }?.name
            ?: EC_CURVES.firstOrNull { it.size == keySize }?.name
            ?: "secp256r1"

    /**
     * Builds the leaf certificate and its chain for [keyPair] with the native Rust builder
     * (keybox parsing, leaf signing and chain assembly all run there).
     *
     * [appendSigningChain] appends the signing certificate chain after the leaf — true for the
     * keybox case, false when a designated attestation key signs a standalone leaf.
     */
    private fun buildChain(
        keyPair: KeyPair,
        params: KeyGenParameters,
        signing: SigningMaterial,
        uid: Int,
        securityLevel: Int,
        appendSigningChain: Boolean,
    ): List<Certificate> {
        params.createdAtMs = params.createdAtMs ?: System.currentTimeMillis()
        val creationTimeMs = params.createdAtMs!!
        val attestationDer = buildAttestationDer(params, uid, securityLevel, creationTimeMs)

        return buildNativeChain(keyPair, attestationDer, signing, params, appendSigningChain)
            ?: throw IllegalStateException("Native certificate chain builder unavailable")
    }

    /** Runs the native chain builder, throwing when the library is unavailable or rejects the request. */
    private fun buildNativeChain(
        keyPair: KeyPair,
        attestationDer: ByteArray,
        signing: SigningMaterial,
        params: KeyGenParameters,
        appendSigningChain: Boolean,
    ): List<Certificate>? {
        if (!NativeCertGen.isAvailable) return null
        val signingChain = signing.certChainDer ?: return null
        if (signingChain.isEmpty()) return null

        val request =
            runCatching { encodeChainBuildRequest(keyPair, attestationDer, signing, params, appendSigningChain) }
                .onFailure { Logger.e("Failed to encode native chain request", it) }
                .getOrNull() ?: return null

        val blob =
            runCatching { NativeCertGen.nativeBuildCertificateChain(request) }
                .onFailure { Logger.d("Native chain build unavailable for this request: ${it.message}") }
                .getOrNull() ?: return null

        return runCatching { CertificateUtils.run { blob.toCertificates().toList() } }
            .onFailure { Logger.e("Failed to parse native certificate chain", it) }
            .getOrNull()
            ?.takeIf { it.isNotEmpty() }
    }

    /**
     * Packs the chain-build request for the native builder: leaf key, pre-encoded attestation
     * extension and signing material (see the Rust `chaingen` module for the layout). Absent
     * optional values are encoded as zero-length fields so the native side applies its defaults,
     * and the validity dates are pre-resolved to the defaults the native builder expects.
     */
    private fun encodeChainBuildRequest(
        keyPair: KeyPair,
        attestationDer: ByteArray,
        signing: SigningMaterial,
        params: KeyGenParameters,
        appendSigningChain: Boolean,
    ): ByteArray {
        val out = ByteArrayOutputStream()
        DataOutputStream(out).use { data ->
            data.writeInt(params.algorithm)
            data.writeLong((params.certificateNotBefore ?: Date(0)).time)
            data.writeLong((params.certificateNotAfter ?: Date(253402300799000L)).time)
            data.writeByte(if (appendSigningChain) 1 else 0)
            data.writeLengthPrefixed(keyPair.private.encoded)
            data.writeLengthPrefixed(attestationDer)
            data.writeLengthPrefixed(signing.keyPair.private.encoded)
            data.writeLengthPrefixed(signing.certChainDer ?: ByteArray(0))
            data.writeInt(params.purpose.size)
            params.purpose.forEach { data.writeInt(it) }
            data.writeLengthPrefixed(params.certificateSerial?.toByteArray() ?: ByteArray(0))
            data.writeLengthPrefixed(params.certificateSubject ?: ByteArray(0))
        }
        return out.toByteArray()
    }

    private fun DataOutputStream.writeLengthPrefixed(bytes: ByteArray) {
        writeInt(bytes.size)
        write(bytes)
    }

    private fun DataOutputStream.writeIntVector(values: List<Int>) {
        writeInt(values.size)
        values.forEach { writeInt(it) }
    }

    private fun DataOutputStream.writeLongVector(values: List<Long>) {
        writeInt(values.size)
        values.forEach { writeLong(it) }
    }

    private fun DataOutputStream.writeOptionalInt(value: Int?) {
        writeBoolean(value != null)
        value?.let { writeInt(it) }
    }

    fun generateChain(uid: Int, params: KeyGenParameters, keyPair: KeyPair, securityLevel: Int = 1): List<ByteArray>? {
        val raw = runCatching {
            params.createdAtMs = params.createdAtMs ?: System.currentTimeMillis()
            val keybox = getKeyboxForAlgorithm(params.algorithm) ?: return null
            buildChain(keyPair, params, keyboxSigningMaterial(keybox), uid, securityLevel, true)
                .map { it.encoded }
        }
        return raw.onFailure { Logger.e("Failed to generate certificate chain", it) }.getOrNull()
    }

    /**
     * Encodes the KeyMint `KeyDescription` as DER with the native Rust builder; the caller wraps it
     * in the certificate's attestation extension, or hands the same bytes to the native chain
     * builder.
     */
    private fun buildAttestationDer(
        params: KeyGenParameters,
        uid: Int,
        securityLevel: Int = 1,
        creationTimeMs: Long,
    ): ByteArray =
        buildNativeAttestationDer(params, uid, securityLevel, creationTimeMs)
            ?: throw IllegalStateException("Native attestation builder unavailable")

    /** Runs the native attestation builder, throwing when the library is unavailable or rejects the request. */
    private fun buildNativeAttestationDer(
        params: KeyGenParameters,
        uid: Int,
        securityLevel: Int,
        creationTimeMs: Long,
    ): ByteArray? {
        if (!NativeCertGen.isAvailable) return null

        val request =
            runCatching { encodeAttestationRequest(params, uid, securityLevel, creationTimeMs) }
                .onFailure { Logger.e("Failed to encode native attestation request", it) }
                .getOrNull() ?: return null

        return runCatching { NativeCertGen.nativeBuildAttestationExtension(request) }
            .onFailure {
                Logger.d("Native attestation build unavailable for this request: ${it.message}")
            }
            .getOrNull()
            ?.takeIf { it.isNotEmpty() }
    }

    /**
     * Packs the attestation request for the native builder (see the Rust `attreq` module for the
     * layout). The attestation application id and the unique id come from the native `aaid` module;
     * only the PackageManager walk stays on this side, because the Android API is the only way to
     * read package names, version codes and signing history. Nullable optionals are written as
     * zero-length fields so the native side applies the same "omit this tag" default.
     */
    private fun encodeAttestationRequest(
        params: KeyGenParameters,
        uid: Int,
        securityLevel: Int,
        creationTimeMs: Long,
    ): ByteArray {
        val versions = AndroidUtils.attestationVersions(securityLevel)
        val patchLevels = AndroidUtils.resolvePatchLevels(uid)
        val applicationId = if (params.attestationChallenge != null) createApplicationId(uid) else null
        val uniqueId =
            if (params.includeUniqueId == true && applicationId != null) {
                computeUniqueId(creationTimeMs, applicationId)
            } else {
                ByteArray(0)
            }

        val out = ByteArrayOutputStream()
        DataOutputStream(out).use { data ->
            data.writeInt(params.algorithm)
            data.writeInt(effectiveKeySize(params))
            data.writeInt(params.ecCurve)
            data.writeLong(params.rsaPublicExponent?.toLong() ?: 0L)
            data.writeInt(securityLevel)
            data.writeInt(versions.attestation)
            data.writeInt(versions.keymaster)
            data.writeInt(AndroidUtils.osVersion)
            data.writeInt(patchLevels.os)
            data.writeInt(patchLevels.vendor)
            data.writeInt(patchLevels.boot)
            data.writeLong(creationTimeMs)
            data.writeInt(params.origin ?: 0)
            data.writeLengthPrefixed(params.attestationChallenge ?: ByteArray(0))
            data.writeLengthPrefixed(uniqueId)
            data.writeLengthPrefixed(applicationId ?: ByteArray(0))
            data.writeLengthPrefixed(AndroidUtils.moduleHash)
            data.writeLengthPrefixed(AndroidUtils.bootKey)
            data.writeLengthPrefixed(AndroidUtils.getBootHashFromProp() ?: ByteArray(0))
            data.writeIntVector(params.purpose)
            data.writeIntVector(params.digest)
            data.writeIntVector(params.blockMode)
            data.writeIntVector(params.padding)
            data.writeIntVector(params.mgfDigest)
            data.writeLongVector(params.userSecureIds)
            data.writeOptionalInt(params.userAuthType)
            data.writeOptionalInt(params.authTimeout)
            data.writeBoolean(params.allowWhileOnBody == true)
            data.writeBoolean(params.trustedUserPresenceRequired == true)
            data.writeBoolean(params.trustedConfirmationRequired == true)
            data.writeBoolean(params.unlockedDeviceRequired == true)
            data.writeBoolean(params.noAuthRequiredIsValid)
            data.writeBoolean(params.callerNonce == true)
            data.writeLong(params.activeDateTime ?: -1L)
            data.writeLong(params.originationExpireDateTime ?: -1L)
            data.writeLong(params.usageExpireDateTime ?: -1L)
            data.writeInt(params.maxUsesPerBoot)
            data.writeInt(params.usageCountLimit)
            data.writeLengthPrefixed(params.brand ?: ByteArray(0))
            data.writeLengthPrefixed(params.device ?: ByteArray(0))
            data.writeLengthPrefixed(params.product ?: ByteArray(0))
            data.writeLengthPrefixed(params.serialno ?: ByteArray(0))
            data.writeLengthPrefixed(params.imei1 ?: ByteArray(0))
            data.writeLengthPrefixed(params.meid ?: ByteArray(0))
            data.writeLengthPrefixed(params.manufacturer ?: ByteArray(0))
            data.writeLengthPrefixed(params.model ?: ByteArray(0))
            data.writeLengthPrefixed(params.imei2 ?: ByteArray(0))
        }
        return out.toByteArray()
    }

    // persisted so the unique_id stays stable across reboots; ephemeral fallback if unwritable
    private val hbk: ByteArray by lazy {
        val file = File("/data/adb/tricky_store/hbk")
        if (file.exists() && file.length() == 32L) {
            file.readBytes()
        } else {
            val k = ByteArray(32).also { SecureRandom().nextBytes(it) }
            file.parentFile?.mkdirs()
            file.writeBytes(k)
            k
        }
    }

    // counter advances every ~30 days, so later keys get a different unique_id like real hardware
    private fun computeUniqueId(creationTimeMs: Long, aaidDer: ByteArray): ByteArray {
        if (!NativeCertGen.isAvailable) throw IllegalStateException("Native unique id builder unavailable")
        return NativeCertGen.nativeUniqueId(creationTimeMs, aaidDer, hbk)
            ?: throw IllegalStateException("Native unique id builder returned no result")
    }

    /** One package's contribution to the attestation application id request. */
    private class PackageEntry(
        val name: String,
        val versionCode: Long,
        val digests: List<ByteArray>,
    )

    /**
     * Collects the packages sharing [uid] and hands them to the native builder, which assembles the
     * DER container (see the Rust `aaid` module). The PackageManager walk stays here: package names,
     * version codes and signing history are only reachable through the Android API.
     */
    @Throws(Throwable::class)
    private fun createApplicationId(uid: Int): ByteArray {
        val pm = PkgConfig.getPm() ?: throw IllegalStateException("PackageManager not found!")
        val packages = pm.getPackagesForUid(uid) ?: throw IllegalStateException("No packages for UID $uid")
        val md = MessageDigest.getInstance("SHA-256")

        val entries =
            packages.map { pkg ->
                val info =
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES.toLong(), uid / 100000)
                    } else {
                        pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES, uid / 100000)
                    }
                val signingHistory = info.signingInfo?.signingCertificateHistory
                    ?: throw IllegalStateException("No signing history for package ${info.packageName}")
                if (signingHistory.isEmpty()) {
                    throw IllegalStateException("Empty signing history for package ${info.packageName}")
                }
                PackageEntry(
                    name = info.packageName,
                    versionCode = info.longVersionCode,
                    digests = signingHistory.map { md.digest(it.toByteArray()) },
                )
            }

        val out = ByteArrayOutputStream()
        DataOutputStream(out).use { data ->
            data.writeInt(entries.size)
            for (entry in entries) {
                data.writeLengthPrefixed(entry.name.toByteArray(StandardCharsets.UTF_8))
                data.writeLong(entry.versionCode)
                data.writeInt(entry.digests.size)
                entry.digests.forEach { data.writeLengthPrefixed(it) }
            }
        }

        if (!NativeCertGen.isAvailable) throw IllegalStateException("Native application id builder unavailable")
        return NativeCertGen.nativeApplicationId(out.toByteArray())
            ?: throw IllegalStateException("Native application id builder returned no result")
    }
}
