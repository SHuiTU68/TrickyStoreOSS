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
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import javax.security.auth.x500.X500Principal
import org.bouncycastle.asn1.ASN1Boolean
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERSet
import org.bouncycastle.asn1.DERTaggedObject
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder

object CertificateGen {
    enum class AuthPolicyProvenance { UNKNOWN, RAW_REQUEST }

    data class KeyBox(val keyPair: KeyPair, val certificates: List<Certificate>)

    /**
     * The material used to sign a freshly generated leaf: the signing key, the issuer DN taken from
     * its leaf certificate, and that certificate chain as DER (leaf first). The native builder only
     * needs the DER form, while the BouncyCastle path uses the key and issuer directly.
     */
    private class SigningMaterial(
        val keyPair: KeyPair,
        val issuer: X500Name,
        val certChainDer: ByteArray?,
    )

    data class KeyGenParameters(
        var keySize: Int = 0,
        var algorithm: Int = 0,
        var certificateSerial: BigInteger? = null,
        var certificateNotBefore: Date? = null,
        var certificateNotAfter: Date? = null,
        var certificateSubject: X500Name? = null,
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
                            Tag.CERTIFICATE_SUBJECT -> certificateSubject = X500Name(X500Principal(v.blob).name)
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

    // Only the sizes the Rust keygen crate accepts; anything else stays on BouncyCastle.
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
                    KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME)
                        .apply { initialize(ECGenParameterSpec(params.ecCurveName ?: "secp256r1")) }
                        .generateKeyPair()
                }

                Algorithm.RSA -> {
                    Logger.d("Generating RSA keypair of size ${params.keySize}")
                    KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME)
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
     * Runs key generation in Rust. Returns null — so the caller falls back to BouncyCastle —
     * whenever the native library is unavailable, the requested algorithm/curve is unsupported
     * natively, or the native call fails.
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
                val factory = KeyFactory.getInstance(factoryAlgorithm, BouncyCastleProvider.PROVIDER_NAME)
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
                buildChain(keyPair, keybox, params, signing, uid, securityLevel, appendSigningChain)
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
            issuer = X509CertificateHolder(certificates.first().encoded).subject,
            certChainDer = CertificateUtils.run { certificates.toByteArray() },
        )
    }

    /** Wraps a keybox as the signing material for the freshly minted leaf. */
    private fun keyboxSigningMaterial(keybox: KeyBox): SigningMaterial =
        SigningMaterial(
            keyPair = keybox.keyPair,
            issuer = X509CertificateHolder(keybox.certificates[0].encoded).subject,
            certChainDer = CertificateUtils.run { keybox.certificates.toByteArray() },
        )

    private fun buildCertificate(
        keyPair: KeyPair,
        params: KeyGenParameters,
        issuer: X500Name,
        attestationDer: ByteArray,
        signingKeyPair: KeyPair,
    ): Certificate {
        val builder =
            JcaX509v3CertificateBuilder(
                issuer,
                params.certificateSerial ?: BigInteger.ONE,
                params.certificateNotBefore ?: Date(0),
                params.certificateNotAfter ?: Date(253402300799000L),
                params.certificateSubject ?: X500Name("CN=Android Keystore Key"),
                keyPair.public,
            )
        val keyUsageBits =
            params.purpose.fold(0) { acc, p ->
                acc or
                    when (p) {
                        KeyPurpose.SIGN -> KeyUsage.digitalSignature
                        KeyPurpose.DECRYPT -> KeyUsage.dataEncipherment
                        KeyPurpose.WRAP_KEY -> KeyUsage.keyEncipherment
                        KeyPurpose.AGREE_KEY -> KeyUsage.keyAgreement
                        KeyPurpose.ATTEST_KEY -> KeyUsage.keyCertSign
                        else -> 0
                    }
            }
        if (keyUsageBits != 0) builder.addExtension(Extension.keyUsage, true, KeyUsage(keyUsageBits))
        builder.addExtension(Extension(ATTESTATION_OID, false, DEROctetString(attestationDer)))
        val signerAlgorithm =
            when (signingKeyPair.private) {
                is java.security.interfaces.ECPrivateKey -> "ECDSA"
                is java.security.interfaces.RSAPrivateKey -> "RSA"
                else ->
                    throw UnsupportedOperationException(
                        "Unsupported attestation signing key algorithm: ${signingKeyPair.private.algorithm}"
                    )
            }
        val digestName = CertificateUtils.digestName(params.digest.firstOrNull { it != 0 } ?: 0, false)
        val signer =
            JcaContentSignerBuilder("${digestName}with$signerAlgorithm")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(signingKeyPair.private)
        return JcaX509CertificateConverter()
            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .getCertificate(builder.build(signer))
    }

    private fun resolveEcCurveName(curve: Int, keySize: Int): String =
        EC_CURVES.firstOrNull { it.curve == curve }?.name
            ?: EC_CURVES.firstOrNull { it.size == keySize }?.name
            ?: "secp256r1"

    /**
     * Builds the leaf certificate and its chain for [keyPair], preferring the native Rust builder
     * (keybox parsing, leaf signing and chain assembly all run there) and falling back to
     * BouncyCastle whenever the native library is unavailable or rejects the request.
     *
     * [appendSigningChain] appends the signing certificate chain after the leaf — true for the
     * keybox case, false when a designated attestation key signs a standalone leaf.
     */
    private fun buildChain(
        keyPair: KeyPair,
        keybox: KeyBox,
        params: KeyGenParameters,
        signing: SigningMaterial,
        uid: Int,
        securityLevel: Int,
        appendSigningChain: Boolean,
    ): List<Certificate> {
        params.createdAtMs = params.createdAtMs ?: System.currentTimeMillis()
        val creationTimeMs = params.createdAtMs!!
        val attestationDer = buildAttestationDer(params, uid, securityLevel, creationTimeMs)

        buildNativeChain(keyPair, attestationDer, signing, params, appendSigningChain)?.let { return it }

        val leaf = buildCertificate(keyPair, params, signing.issuer, attestationDer, signing.keyPair)
        return buildList {
            add(leaf)
            if (appendSigningChain) addAll(keybox.certificates)
        }
    }

    /** Runs the native chain builder, returning null so the caller falls back to BouncyCastle. */
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
     * and the validity dates are pre-resolved to match the BouncyCastle defaults exactly.
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
            data.writeLengthPrefixed(params.certificateSubject?.encoded ?: ByteArray(0))
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
            buildChain(keyPair, keybox, params, keyboxSigningMaterial(keybox), uid, securityLevel, true)
                .map { it.encoded }
        }
        return raw.onFailure { Logger.e("Failed to generate certificate chain", it) }.getOrNull()
    }

    /**
     * Encodes the KeyMint `KeyDescription` as DER; the caller wraps it in the certificate's
     * attestation extension, or hands the same bytes to the native chain builder. Prefers the
     * native Rust builder (byte-identical to the BouncyCastle path) and falls back to BouncyCastle
     * whenever the native library is unavailable or rejects the request.
     */
    private fun buildAttestationDer(
        params: KeyGenParameters,
        uid: Int,
        securityLevel: Int = 1,
        creationTimeMs: Long,
    ): ByteArray {
        buildNativeAttestationDer(params, uid, securityLevel, creationTimeMs)?.let { return it }

        val versions = AndroidUtils.attestationVersions(securityLevel)
        val attestationVersion = versions.attestation
        val keymasterVersion = versions.keymaster
        val key = AndroidUtils.bootKey
        val hash = AndroidUtils.getBootHashFromProp()
        val rootOfTrust =
            DERSequence(arrayOf(DEROctetString(key), ASN1Boolean.TRUE, ASN1Enumerated(0), DEROctetString(hash)))
        val osVersion = ASN1Integer(AndroidUtils.osVersion.toLong())
        val creationDateTime = ASN1Integer(creationTimeMs)
        val origin = ASN1Integer((params.origin ?: 0).toLong())
        val moduleHash = DEROctetString(AndroidUtils.moduleHash)
        val applicationId = if (params.attestationChallenge != null) createApplicationId(uid) else null
        val uniqueId =
            if (params.includeUniqueId == true && applicationId != null) {
                computeUniqueId(creationTimeMs, applicationId.octets)
            } else {
                ByteArray(0)
            }

        val tee = mutableListOf<ASN1Encodable>()

        fun teeTag(tag: Int, v: ASN1Encodable) = tee.add(DERTaggedObject(true, tag, v))

        fun teeSet(tag: Int, vs: List<Int>) =
            vs.takeIf { it.isNotEmpty() }
                ?.let { teeTag(tag, DERSet(it.map { ASN1Integer(it.toLong()) }.toTypedArray())) }

        teeSet(1, params.purpose)
        teeTag(2, ASN1Integer(params.algorithm.toLong()))
        val effectiveKey = effectiveKeySize(params)
        if (effectiveKey > 0) teeTag(3, ASN1Integer(effectiveKey.toLong()))
        teeSet(5, params.digest)
        params.userSecureIds.takeIf { it.isNotEmpty() }?.let { ids ->
            teeTag(502, DERSet(ids.map { ASN1Integer(it) }.toTypedArray()))
        }
        params.userAuthType?.let { teeTag(504, ASN1Integer(it.toLong())) }
        params.authTimeout?.let { teeTag(505, ASN1Integer(it.toLong())) }
        if (params.allowWhileOnBody == true) teeTag(506, DERNull.INSTANCE)
        if (params.trustedUserPresenceRequired == true) teeTag(507, DERNull.INSTANCE)
        if (params.trustedConfirmationRequired == true) teeTag(508, DERNull.INSTANCE)
        if (params.noAuthRequiredIsValid) teeTag(503, DERNull.INSTANCE)
        if (params.callerNonce == true) teeTag(1005, DERNull.INSTANCE)
        teeTag(702, origin)
        teeTag(704, rootOfTrust)
        teeTag(705, osVersion)
        val patchLevels = AndroidUtils.resolvePatchLevels(uid)
        if (patchLevels.os != AndroidUtils.DO_NOT_REPORT)
            teeTag(706, ASN1Integer(patchLevels.os.toLong()))
        if (patchLevels.vendor != AndroidUtils.DO_NOT_REPORT) {
            teeTag(718, ASN1Integer(patchLevels.vendor.toLong()))
        }
        if (patchLevels.boot != AndroidUtils.DO_NOT_REPORT) {
            teeTag(719, ASN1Integer(patchLevels.boot.toLong()))
        }
        teeSet(4, params.blockMode)
        teeSet(6, params.padding)
        if (attestationVersion >= 100) teeSet(203, params.mgfDigest)
        if (params.algorithm == Algorithm.EC && params.ecCurve != 0) teeTag(10, ASN1Integer(params.ecCurve.toLong()))
        if (params.algorithm == Algorithm.RSA && params.rsaPublicExponent != null)
            teeTag(200, ASN1Integer(params.rsaPublicExponent))
        params.brand?.let { teeTag(710, DEROctetString(it)) }
        params.device?.let { teeTag(711, DEROctetString(it)) }
        params.product?.let { teeTag(712, DEROctetString(it)) }
        params.manufacturer?.let { teeTag(716, DEROctetString(it)) }
        params.model?.let { teeTag(717, DEROctetString(it)) }
        params.serialno?.let { teeTag(713, DEROctetString(it)) }
        params.imei1?.let { teeTag(714, DEROctetString(it)) }
        params.meid?.let { teeTag(715, DEROctetString(it)) }
        if (attestationVersion >= 300) params.imei2?.let { teeTag(723, DEROctetString(it)) }
        tee.sortBy { (it as DERTaggedObject).tagNo }

        val sw = mutableListOf<ASN1Encodable>(DERTaggedObject(true, 701, creationDateTime))
        params.activeDateTime?.let { sw.add(DERTaggedObject(true, 400, ASN1Integer(it))) }
        params.originationExpireDateTime?.let { sw.add(DERTaggedObject(true, 401, ASN1Integer(it))) }
        params.usageExpireDateTime?.let { sw.add(DERTaggedObject(true, 402, ASN1Integer(it))) }
        if (params.maxUsesPerBoot > 0) sw.add(DERTaggedObject(true, 404, ASN1Integer(params.maxUsesPerBoot.toLong())))
        if (params.usageCountLimit > 0) sw.add(DERTaggedObject(true, 405, ASN1Integer(params.usageCountLimit.toLong())))
        if (params.unlockedDeviceRequired == true) sw.add(DERTaggedObject(true, 509, DERNull.INSTANCE))
        if (applicationId != null) sw.add(DERTaggedObject(true, 709, applicationId))
        if (attestationVersion >= 400) sw.add(DERTaggedObject(true, 724, moduleHash))
        sw.sortBy { (it as DERTaggedObject).tagNo }

        val keyDesc =
            arrayOf(
                ASN1Integer(attestationVersion.toLong()),
                ASN1Enumerated(securityLevel),
                ASN1Integer(keymasterVersion.toLong()),
                ASN1Enumerated(securityLevel),
                DEROctetString(params.attestationChallenge ?: ByteArray(0)),
                DEROctetString(uniqueId),
                DERSequence(sw.toTypedArray()),
                DERSequence(tee.toTypedArray()),
            )
        return DERSequence(keyDesc).encoded
    }

    /** Runs the native attestation builder, returning null so the caller falls back to BouncyCastle. */
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
     * layout). Every value mirrors what the BouncyCastle path below reads, so the two encoders
     * stay byte-identical: the native side only re-serialises the same fields. The attestation
     * application id and unique id are still computed here (they need the PackageManager and the
     * persisted HMAC key) and handed over already encoded. Nullable optionals are written as
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
                computeUniqueId(creationTimeMs, applicationId.octets)
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
            data.writeLengthPrefixed(applicationId?.octets ?: ByteArray(0))
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
        val temporalCounter = creationTimeMs / 2592000000L
        val message = ByteBuffer.allocate(8 + aaidDer.size + 1).putLong(temporalCounter).put(aaidDer).put(0x00).array()
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(hbk, "HmacSHA256"))
        return mac.doFinal(message).copyOf(16)
    }

    @Throws(Throwable::class)
    private fun createApplicationId(uid: Int): DEROctetString {
        val pm = PkgConfig.getPm() ?: throw IllegalStateException("PackageManager not found!")
        val packages = pm.getPackagesForUid(uid) ?: throw IllegalStateException("No packages for UID $uid")
        val md = MessageDigest.getInstance("SHA-256")
        val signatures = LinkedHashMap<String, ByteArray>()

        val packageInfoArray =
            packages
                .map { pkg ->
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
                    signingHistory.forEach { sig ->
                        val digest = md.digest(sig.toByteArray())
                        val key = digest.joinToString("") { "%02x".format(it) }
                        signatures.putIfAbsent(key, digest)
                    }
                    info
                }
                .map { info ->
                    DERSequence(
                        arrayOf(
                            DEROctetString(info.packageName.toByteArray(StandardCharsets.UTF_8)),
                            ASN1Integer(info.longVersionCode),
                        )
                    )
                }
                .toTypedArray()

        val sigArray = signatures.values.map { DEROctetString(it) }.toTypedArray()
        return DEROctetString(DERSequence(arrayOf(DERSet(packageInfoArray), DERSet(sigArray))).encoded)
    }
}
