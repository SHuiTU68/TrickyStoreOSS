/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS

import android.hardware.security.keymint.Algorithm
import android.hardware.security.keymint.EcCurve
import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyParameterValue
import android.hardware.security.keymint.KeyPurpose
import android.hardware.security.keymint.Tag
import android.security.keymaster.KeymasterDefs
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.mockito.BDDMockito.given
import org.mockito.Mockito.mock
import java.math.BigInteger
import java.security.interfaces.ECPrivateKey
import java.util.Date

/**
 * JVM unit tests for the KeyMint request → [CertificateGen.KeyGenParameters] mapping: it feeds the
 * GENERATE / LEAF_HACK decision and every native encode call, so a mis-parsed tag silently poisons
 * the whole attestation path.
 *
 * `KeyParameterValue` comes from `project(":stub")`, whose statics all throw — every union value is
 * therefore a Mockito mock (created without calling the constructor) with only the getter this tag
 * reads stubbed; unstubbed getters return the union defaults.
 */
class CertificateGenKeyGenParametersTest {
    private fun param(tag: Int, value: KeyParameterValue): KeyParameter =
        KeyParameter().also { it.tag = tag; it.value = value }

    private fun intParam(tag: Int, value: Int): KeyParameter =
        param(tag, mock(KeyParameterValue::class.java).also { given(it.integer).willReturn(value) })

    private fun longParam(tag: Int, value: Long): KeyParameter =
        param(tag, mock(KeyParameterValue::class.java).also { given(it.longInteger).willReturn(value) })

    private fun blobParam(tag: Int, value: ByteArray): KeyParameter =
        param(tag, mock(KeyParameterValue::class.java).also { given(it.blob).willReturn(value) })

    private fun boolParam(tag: Int, value: Boolean): KeyParameter =
        param(tag, mock(KeyParameterValue::class.java).also { given(it.boolValue).willReturn(value) })

    private fun dateTimeParam(tag: Int, value: Long): KeyParameter =
        param(tag, mock(KeyParameterValue::class.java).also { given(it.dateTime).willReturn(value) })

    private fun algParam(tag: Int, value: Int): KeyParameter =
        param(tag, mock(KeyParameterValue::class.java).also { given(it.algorithm).willReturn(value) })

    private fun purposeParam(value: Int): KeyParameter =
        param(Tag.PURPOSE, mock(KeyParameterValue::class.java).also { given(it.keyPurpose).willReturn(value) })

    private fun digestParam(value: Int): KeyParameter =
        param(Tag.DIGEST, mock(KeyParameterValue::class.java).also { given(it.digest).willReturn(value) })

    private fun curveParam(value: Int): KeyParameter =
        param(Tag.EC_CURVE, mock(KeyParameterValue::class.java).also { given(it.ecCurve).willReturn(value) })

    @Test
    fun coreAttestationTagsParseIntoKeyGenParameters() {
        val challenge = ByteArray(32) { it.toByte() }
        val subject = byteArrayOf(0x30, 0x03, 0x02, 0x01, 0x01)
        val serial = BigInteger("12345678901234567890")
        val notBefore = Date(1_700_000_000_000)
        val notAfter = Date(1_800_000_000_000)

        val params =
            CertificateGen.KeyGenParameters(
                arrayOf(
                    algParam(Tag.ALGORITHM, Algorithm.EC),
                    intParam(Tag.KEY_SIZE, 256),
                    curveParam(EcCurve.P_256),
                    purposeParam(KeyPurpose.SIGN),
                    purposeParam(KeyPurpose.VERIFY),
                    digestParam(KeymasterDefs.KM_DIGEST_SHA_2_256),
                    blobParam(Tag.ATTESTATION_CHALLENGE, challenge),
                    blobParam(Tag.CERTIFICATE_SERIAL, serial.toByteArray()),
                    blobParam(Tag.CERTIFICATE_SUBJECT, subject),
                    dateTimeParam(Tag.CERTIFICATE_NOT_BEFORE, notBefore.time),
                    dateTimeParam(Tag.CERTIFICATE_NOT_AFTER, notAfter.time),
                    boolParam(Tag.NO_AUTH_REQUIRED, true),
                ),
            )

        assertEquals(Algorithm.EC, params.algorithm)
        assertEquals(256, params.keySize)
        assertEquals("secp256r1", params.ecCurveName)
        assertEquals(listOf(KeyPurpose.SIGN, KeyPurpose.VERIFY), params.purpose)
        assertEquals(listOf(KeymasterDefs.KM_DIGEST_SHA_2_256), params.digest)
        assertArrayEquals(challenge, params.attestationChallenge)
        assertEquals(serial, params.certificateSerial)
        assertArrayEquals(subject, params.certificateSubject)
        assertEquals(notBefore, params.certificateNotBefore)
        assertEquals(notAfter, params.certificateNotAfter)
        assertEquals(CertificateGen.AuthPolicyProvenance.RAW_REQUEST, params.authPolicyProvenance)
        assertTrue(params.noAuthRequiredIsValid)
    }

    @Test
    fun unknownTagIsIgnoredWithoutTouchingProvenance() {
        val params =
            CertificateGen.KeyGenParameters(
                arrayOf(param(0x7ead_beef, mock(KeyParameterValue::class.java))),
            )
        assertEquals(CertificateGen.AuthPolicyProvenance.RAW_REQUEST, params.authPolicyProvenance)
        assertEquals(0, params.keySize)
    }

    @Test
    fun curveNameFallsBackToKeySizeWhenEcCurveTagAbsent() {
        for ((keySize, expected) in listOf(256 to "secp256r1", 384 to "secp384r1", 224 to "secp224r1")) {
            val params =
                CertificateGen.KeyGenParameters(
                    arrayOf(algParam(Tag.ALGORITHM, Algorithm.EC), intParam(Tag.KEY_SIZE, keySize)),
                )
            assertEquals(expected, params.ecCurveName)
        }

        // An explicit P_224 tag is 0 on the wire and must still resolve to P_224.
        val p224 = CertificateGen.KeyGenParameters(arrayOf(algParam(Tag.ALGORITHM, Algorithm.EC), curveParam(EcCurve.P_224)))
        assertEquals("secp224r1", p224.ecCurveName)
    }

    @Test
    fun malformedAuthTagDowngradesProvenanceToUnknown() {
        val broken = mock(KeyParameterValue::class.java)
        given(broken.hardwareAuthenticatorType).willThrow(IllegalStateException("wrong union arm"))

        val params =
            CertificateGen.KeyGenParameters(
                arrayOf(
                    boolParam(Tag.NO_AUTH_REQUIRED, true),
                    param(Tag.USER_AUTH_TYPE, broken),
                ),
            )

        assertEquals(CertificateGen.AuthPolicyProvenance.UNKNOWN, params.authPolicyProvenance)
        assertFalse(params.noAuthRequiredIsValid)
    }

    @Test
    fun noAuthRequiredIsValidRequiresRawProvenanceAndNoOtherAuthTags() {
        fun base() =
            CertificateGen.KeyGenParameters().apply {
                authPolicyProvenance = CertificateGen.AuthPolicyProvenance.RAW_REQUEST
                noAuthRequired = true
            }

        assertTrue(base().noAuthRequiredIsValid)
        // Provenance unknown: the auth tags could not be fully read, so the flag is not trusted.
        assertFalse(
            base().apply { authPolicyProvenance = CertificateGen.AuthPolicyProvenance.UNKNOWN }.noAuthRequiredIsValid,
        )
        assertFalse(base().apply { noAuthRequired = null }.noAuthRequiredIsValid)
        assertFalse(base().apply { userSecureIds.add(1L) }.noAuthRequiredIsValid)
        assertFalse(base().apply { authTimeout = 30 }.noAuthRequiredIsValid)
        assertFalse(base().apply { userAuthType = 2 }.noAuthRequiredIsValid)
        assertFalse(base().apply { allowWhileOnBody = true }.noAuthRequiredIsValid)
        assertFalse(base().apply { trustedUserPresenceRequired = true }.noAuthRequiredIsValid)
        assertFalse(base().apply { trustedConfirmationRequired = true }.noAuthRequiredIsValid)
        assertFalse(base().apply { unlockedDeviceRequired = true }.noAuthRequiredIsValid)
    }

    @Test
    fun effectiveKeySizePrefersExplicitSizeAndResolvesCurvesByName() {
        assertEquals(
            2048,
            CertificateGen.effectiveKeySize(
                CertificateGen.KeyGenParameters().apply { algorithm = Algorithm.RSA; keySize = 2048 },
            ),
        )
        assertEquals(
            384,
            CertificateGen.effectiveKeySize(
                CertificateGen.KeyGenParameters().apply { algorithm = Algorithm.EC; ecCurveName = "secp384r1" },
            ),
        )
        // No size and no name at all: the EC default is 256.
        assertEquals(
            256,
            CertificateGen.effectiveKeySize(
                CertificateGen.KeyGenParameters().apply { algorithm = Algorithm.EC },
            ),
        )
        // RSA without a size has no EC curve to fall back to.
        assertEquals(
            0,
            CertificateGen.effectiveKeySize(
                CertificateGen.KeyGenParameters().apply { algorithm = Algorithm.RSA },
            ),
        )
    }

    @Test
    fun generateKeyPairFallsBackToPlatformProviderWhenNativeIsUnavailable() {
        val params =
            CertificateGen.KeyGenParameters().apply {
                algorithm = Algorithm.EC
                ecCurveName = "secp256r1"
                keySize = 256
            }

        val pair = CertificateGen.generateKeyPair(params)

        assertNotNull(pair)
        assertTrue(pair!!.private is ECPrivateKey)
        assertNotNull(pair.public)
    }

    @Test
    fun generateKeyPairRejectsNonEcAndRsaAlgorithms() {
        assertNull(
            CertificateGen.generateKeyPair(
                CertificateGen.KeyGenParameters().apply { algorithm = 0 /* Algorithm.UNSPECIFIED */ },
            ),
        )
    }
}
