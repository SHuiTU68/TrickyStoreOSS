/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS

import android.hardware.security.keymint.Algorithm
import android.hardware.security.keymint.EcCurve
import android.hardware.security.keymint.KeyPurpose
import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyParameterValue
import android.hardware.security.keymint.SecurityLevel
import android.hardware.security.keymint.Tag
import android.os.Build
import android.os.ServiceManager
import android.os.ServiceSpecificException
import android.os.SystemClock
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.system.keystore2.IKeystoreService
import android.system.keystore2.KeyDescriptor
import android.system.keystore2.ResponseCode
import io.github.beakthoven.TrickyStoreOSS.logging.Logger
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec

object AttestUtils {
    data class AttestationData(
        val verifiedBootKey: ByteArray?,
        val verifiedBootHash: ByteArray?,
        val attestVersion: Int?,
        val keymasterVersion: Int?,
        val osVersion: Int?,
        val moduleHash: ByteArray?,
    )

    enum class ProbeStatus { AVAILABLE, FAILED, UNAVAILABLE }

    data class ProbeResult(
        val status: ProbeStatus,
        val attestationData: AttestationData? = null,
        val failureCategory: String? = null,
        val serviceErrorCode: Int? = null,
    )

    @Volatile private var cachedProbeResult: ProbeResult? = null

    val probeResult: ProbeResult
        get() = cachedProbeResult ?: probe()

    val TEEStatus: Boolean
        get() = probeResult.status == ProbeStatus.AVAILABLE

    val CachedAttestData: AttestationData?
        get() = probeResult.attestationData

    private const val AAID_PROVIDER = "sec_key_att_app_id_provider"
    private const val AAID_PROVIDER_TIMEOUT_MS = 120_000L
    private const val AAID_POLL_INTERVAL_MS = 500L
    private const val PROBE_MAX_ATTEMPTS = 3
    private const val PROBE_RETRY_DELAY_MS = 1_000L
    private const val KEYSTORE_SERVICE = "android.system.keystore2.IKeystoreService/default"
    private const val PROBE_ALIAS_PREFIX = "TrickyStoreOSS_probe_"

    @Synchronized
    fun probe(): ProbeResult {
        cachedProbeResult?.let { return it }
        var result = ProbeResult(ProbeStatus.UNAVAILABLE, failureCategory = "not_run")
        var attempt = 0
        while (attempt < PROBE_MAX_ATTEMPTS) {
            result = probeOnce()
            attempt++
            if (result.status != ProbeStatus.UNAVAILABLE || attempt == PROBE_MAX_ATTEMPTS) break
            Logger.w("Attestation probe unavailable; retrying ($attempt/$PROBE_MAX_ATTEMPTS)")
            try {
                Thread.sleep(PROBE_RETRY_DELAY_MS)
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
                result = ProbeResult(ProbeStatus.UNAVAILABLE, failureCategory = "interrupted")
                break
            }
        }
        cachedProbeResult = result
        Logger.i(
            "Attestation probe status=${result.status} category=${result.failureCategory ?: "none"}" +
                " code=${result.serviceErrorCode ?: "none"}",
        )
        return result
    }

    private fun probeOnce(): ProbeResult = try {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) probeKeystore2() else probeLegacyKeystore()
    } catch (e: InterruptedException) {
        Thread.currentThread().interrupt()
        ProbeResult(ProbeStatus.UNAVAILABLE, failureCategory = "interrupted")
    } catch (e: ServiceSpecificException) {
        serviceFailure(e)
    } catch (e: Exception) {
        Logger.w("Attestation probe failed (${e.javaClass.simpleName})")
        ProbeResult(ProbeStatus.FAILED, failureCategory = e.javaClass.simpleName)
    }

    private fun serviceFailure(error: ServiceSpecificException): ProbeResult {
        val category = when (error.errorCode) {
            ResponseCode.SYSTEM_ERROR -> "system_error"
            ResponseCode.OUT_OF_KEYS_PENDING_INTERNET_CONNECTIVITY -> "pending_connectivity"
            ResponseCode.OUT_OF_KEYS_TRANSIENT_ERROR -> "transient_error"
            ResponseCode.OUT_OF_KEYS -> "out_of_keys"
            ResponseCode.OUT_OF_KEYS_REQUIRES_SYSTEM_UPGRADE -> "upgrade_required"
            ResponseCode.OUT_OF_KEYS_PERMANENT_ERROR -> "permanent_error"
            else -> "service_error"
        }
        val status = when (error.errorCode) {
            ResponseCode.SYSTEM_ERROR,
            ResponseCode.OUT_OF_KEYS_PENDING_INTERNET_CONNECTIVITY,
            ResponseCode.OUT_OF_KEYS_TRANSIENT_ERROR,
            -> ProbeStatus.UNAVAILABLE
            else -> ProbeStatus.FAILED
        }
        Logger.w("Attestation probe service error category=$category code=${error.errorCode}")
        return ProbeResult(status, failureCategory = category, serviceErrorCode = error.errorCode)
    }

    private fun probeKeystore2(): ProbeResult = Keystore2Probe.run()

    private object Keystore2Probe {
        private fun waitForAaidProvider(): Boolean {
            val deadline = SystemClock.elapsedRealtime() + AAID_PROVIDER_TIMEOUT_MS
            while (ServiceManager.checkService(AAID_PROVIDER) == null) {
                val remaining = deadline - SystemClock.elapsedRealtime()
                if (remaining <= 0) return false
                Thread.sleep(minOf(AAID_POLL_INTERVAL_MS, remaining))
            }
            return true
        }

        fun run(): ProbeResult {
            if (!waitForAaidProvider()) {
                Logger.w("Attestation probe unavailable: AAID provider readiness timeout")
                return ProbeResult(ProbeStatus.UNAVAILABLE, failureCategory = "aaid_timeout")
            }

            val binder = ServiceManager.checkService(KEYSTORE_SERVICE)
                ?: return ProbeResult(ProbeStatus.UNAVAILABLE, failureCategory = "keystore2_unavailable")
            val service = IKeystoreService.Stub.asInterface(binder)
            val securityLevel = service.getSecurityLevel(SecurityLevel.TRUSTED_ENVIRONMENT)
            val challenge = ByteArray(16).also { SecureRandom().nextBytes(it) }
            val alias = PROBE_ALIAS_PREFIX + java.util.UUID.randomUUID().toString()
            val descriptor = KeyDescriptor().apply {
                domain = 0
                nspace = -1
                this.alias = alias
                blob = null
            }
            return try {
                val metadata = securityLevel.generateKey(descriptor, null, probeParameters(challenge), 0, ByteArray(0))
                val certificate = metadata.certificate
                    ?: return ProbeResult(ProbeStatus.FAILED, failureCategory = "missing_certificate")
                val parsed = parseAttestationData(certificate, challenge)
                    ?: return ProbeResult(ProbeStatus.FAILED, failureCategory = "invalid_attestation")
                ProbeResult(ProbeStatus.AVAILABLE, parsed)
            } catch (e: ServiceSpecificException) {
                serviceFailure(e)
            } catch (e: Exception) {
                Logger.w("Keystore2 attestation probe failed (${e.javaClass.simpleName})")
                ProbeResult(ProbeStatus.FAILED, failureCategory = e.javaClass.simpleName)
            } finally {
                runCatching { service.deleteKey(descriptor) }
                    .onFailure { error ->
                        if (error !is ServiceSpecificException || error.errorCode != ResponseCode.KEY_NOT_FOUND) {
                            Logger.w("Failed to delete attestation probe key (${error.javaClass.simpleName})")
                        }
                    }
            }
        }

        private fun probeParameters(challenge: ByteArray): Array<KeyParameter> = arrayOf(
            keyParameter(Tag.ALGORITHM, KeyParameterValue.algorithm(Algorithm.EC)),
            keyParameter(Tag.KEY_SIZE, KeyParameterValue.integer(256)),
            keyParameter(Tag.EC_CURVE, KeyParameterValue.ecCurve(EcCurve.P_256)),
            keyParameter(Tag.PURPOSE, KeyParameterValue.keyPurpose(KeyPurpose.SIGN)),
            keyParameter(Tag.DIGEST, KeyParameterValue.digest(4)),
            keyParameter(Tag.NO_AUTH_REQUIRED, KeyParameterValue.boolValue(true)),
            keyParameter(Tag.ATTESTATION_CHALLENGE, KeyParameterValue.blob(challenge)),
            keyParameter(Tag.CERTIFICATE_NOT_BEFORE, KeyParameterValue.dateTime(0L)),
            keyParameter(Tag.CERTIFICATE_NOT_AFTER, KeyParameterValue.dateTime(253402300799000L)),
        )

        private fun keyParameter(tag: Int, value: KeyParameterValue) = KeyParameter().apply {
            this.tag = tag
            this.value = value
        }
    }

    private fun probeLegacyKeystore(): ProbeResult {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                android.app.ActivityThread.initializeMainlineModules()
            }
            android.security.keystore.AndroidKeyStoreProvider.install()
            val challenge = ByteArray(16).also { SecureRandom().nextBytes(it) }
            val alias = PROBE_ALIAS_PREFIX + java.util.UUID.randomUUID().toString()
            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            try {
                val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
                val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge(challenge)
                    .setIsStrongBoxBacked(false)
                    .build()
                generator.initialize(spec)
                generator.generateKeyPair()
                val certificate = keyStore.getCertificate(alias) as? X509Certificate
                    ?: return ProbeResult(ProbeStatus.FAILED, failureCategory = "missing_certificate")
                val parsed = parseAttestationData(certificate.encoded, challenge)
                    ?: return ProbeResult(ProbeStatus.FAILED, failureCategory = "invalid_attestation")
                ProbeResult(ProbeStatus.AVAILABLE, parsed)
            } finally {
                runCatching { keyStore.deleteEntry(alias) }
                    .onFailure {
                        Logger.w("Failed to delete legacy attestation probe key (${it.javaClass.simpleName})")
                    }
            }
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            ProbeResult(ProbeStatus.UNAVAILABLE, failureCategory = "interrupted")
        } catch (e: ServiceSpecificException) {
            serviceFailure(e)
        } catch (e: Exception) {
            Logger.w("Legacy attestation probe failed (${e.javaClass.simpleName})")
            ProbeResult(ProbeStatus.FAILED, failureCategory = e.javaClass.simpleName)
        }
    }

    private fun parseAttestationData(encodedCertificate: ByteArray, expectedChallenge: ByteArray): AttestationData? =
        parseAttestationDataNative(encodedCertificate, expectedChallenge)

    /**
     * Parses the attestation extension with the native Rust reader, returning null when the library
     * is unavailable or the certificate is rejected, so the probe reports the failure.
     */
    private fun parseAttestationDataNative(
        encodedCertificate: ByteArray,
        expectedChallenge: ByteArray,
    ): AttestationData? {
        if (!NativeCertGen.isAvailable) return null
        return try {
            val request = ByteArrayOutputStream().also { out ->
                DataOutputStream(out).also { data ->
                    data.writeInt(encodedCertificate.size)
                    data.write(encodedCertificate)
                    data.writeInt(expectedChallenge.size)
                    data.write(expectedChallenge)
                }
            }.toByteArray()
            decodeAttestationData(NativeCertGen.nativeParseAttestation(request))
        } catch (t: Throwable) {
            Logger.w("Native attestation parse failed", t)
            null
        }
    }

    /** Rebuilds [AttestationData] from the Rust presence-tagged response blob. */
    private fun decodeAttestationData(blob: ByteArray): AttestationData {
        val data = DataInputStream(ByteArrayInputStream(blob))
        val attestVersion = data.readInt()
        val keymasterVersion = data.readInt()
        val verifiedBootKey = readNativeOptionalBlob(data)
        val verifiedBootHash = readNativeOptionalBlob(data)
        val osVersion = if (data.readUnsignedByte() != 0) data.readInt() else null
        val moduleHash = readNativeOptionalBlob(data)
        if (data.available() != 0) {
            throw IllegalStateException("Trailing bytes in native attestation response")
        }
        return AttestationData(verifiedBootKey, verifiedBootHash, attestVersion, keymasterVersion, osVersion, moduleHash)
    }

    private fun readNativeOptionalBlob(data: DataInputStream): ByteArray? =
        if (data.readUnsignedByte() != 0) readNativeBlob(data) else null

    private fun readNativeBlob(data: DataInputStream): ByteArray {
        val length = data.readInt()
        if (length < 0 || length > data.available()) {
            throw IllegalStateException("Invalid native attestation field length: $length")
        }
        val bytes = ByteArray(length)
        data.readFully(bytes)
        return bytes
    }
}
