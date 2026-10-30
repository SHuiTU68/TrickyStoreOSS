/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS

import io.github.beakthoven.TrickyStoreOSS.forge.ChainBuildRequest
import io.github.beakthoven.TrickyStoreOSS.forge.ForgeProtocol
import io.github.beakthoven.TrickyStoreOSS.forge.ForgeResult
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream

/**
 * Round-trip tests for the forge daemon wire protocol. LocalSocket is unavailable on the JVM,
 * so only the pure encode/decode layer is exercised here.
 */
class ForgeProtocolTest {

    private fun chainRequest(
        purposes: IntArray = intArrayOf(2, 3, 4),
        leafKey: ByteArray = byteArrayOf(0x30, 0x82.toByte(), 0x01, 0x01),
        attestation: ByteArray = byteArrayOf(0x30, 0x1F, 0x02),
    ) = ChainBuildRequest(
        algorithm = 3, // EC
        leafPrivateKey = leafKey,
        attestationDer = attestation,
        notBeforeMs = 1_700_000_000_000L,
        notAfterMs = 4_102_444_800_000L,
        appendSigningChain = true,
        purposes = purposes,
        serialDer = byteArrayOf(0x02, 0x01, 0x2A),
        subjectDer = byteArrayOf(0x30, 0x0F, 0x31),
    )

    @Test
    fun `chain request round trip preserves every field`() {
        val original = chainRequest()
        assertChainRequestEquals(original, ForgeProtocol.decodeChainRequest(ForgeProtocol.encodeChainRequest(original)))
    }

    @Test
    fun `chain request with empty vectors and blobs round trips`() {
        val original = chainRequest(purposes = IntArray(0), leafKey = ByteArray(0), attestation = ByteArray(0))
        assertChainRequestEquals(original, ForgeProtocol.decodeChainRequest(ForgeProtocol.encodeChainRequest(original)))
    }

    /** Data classes compare ByteArray members by reference, so equality is asserted field-wise. */
    private fun assertChainRequestEquals(expected: ChainBuildRequest, actual: ChainBuildRequest) {
        assertEquals(expected.algorithm, actual.algorithm)
        assertArrayEquals(expected.leafPrivateKey, actual.leafPrivateKey)
        assertArrayEquals(expected.attestationDer, actual.attestationDer)
        assertEquals(expected.notBeforeMs, actual.notBeforeMs)
        assertEquals(expected.notAfterMs, actual.notAfterMs)
        assertEquals(expected.appendSigningChain, actual.appendSigningChain)
        assertArrayEquals(expected.purposes, actual.purposes)
        assertArrayEquals(expected.serialDer, actual.serialDer)
        assertArrayEquals(expected.subjectDer, actual.subjectDer)
    }

    @Test
    fun `chain request survives a full purpose vector`() {
        val purposes = IntArray(256) { it }
        val decoded = ForgeProtocol.decodeChainRequest(ForgeProtocol.encodeChainRequest(chainRequest(purposes)))
        assertArrayEquals(purposes, decoded.purposes)
    }

    @Test
    fun `chain request rejects an oversized purpose vector`() {
        // algorithm, empty leaf blob, empty attestation blob, two timestamps, append flag, then a
        // purpose count far above MAX_PURPOSES — decode must reject it before reading the vector.
        val malformed =
            ByteArrayOutputStream().let { out ->
                DataOutputStream(out).use { data ->
                    data.writeInt(3)
                    data.writeInt(0)
                    data.writeInt(0)
                    data.writeLong(0)
                    data.writeLong(0)
                    data.writeByte(1)
                    data.writeInt(100_000)
                }
                out.toByteArray()
            }
        try {
            ForgeProtocol.decodeChainRequest(malformed)
            throw AssertionError("expected malformed purpose vector to be rejected")
        } catch (expected: IllegalArgumentException) {
            assertTrue(expected.message!!.contains("purpose"))
        }
    }

    @Test
    fun `leaf hack round trip keeps der and uid`() {
        val leaf = ByteArray(512) { (it % 251).toByte() }
        val (der, uid) = ForgeProtocol.decodeLeafHack(ForgeProtocol.encodeLeafHack(leaf, 1017))
        assertArrayEquals(leaf, der)
        assertEquals(1017, uid)
    }

    @Test
    fun `keybox certs request round trips utf-8 algorithm names`() {
        val decoded = ForgeProtocol.decodeKeyboxCerts(ForgeProtocol.encodeKeyboxCerts("EC"))
        assertEquals("EC", decoded)
        val rsa = ForgeProtocol.decodeKeyboxCerts(ForgeProtocol.encodeKeyboxCerts("RSA"))
        assertEquals("RSA", rsa)
    }

    @Test
    fun `success response round trip preserves payload`() {
        val payload = byteArrayOf(1, 2, 3, 4)
        val result = ForgeProtocol.decodeResponse(ForgeProtocol.encodeSuccess(payload))
        assertTrue(result is ForgeResult.Success)
        assertArrayEquals(payload, (result as ForgeResult.Success).payload)
    }

    @Test
    fun `failure response round trip preserves message`() {
        val result = ForgeProtocol.decodeResponse(ForgeProtocol.encodeFailure("keybox unavailable"))
        assertTrue(result is ForgeResult.Failure)
        assertEquals("keybox unavailable", (result as ForgeResult.Failure).message)
    }

    @Test
    fun `certificate chain round trip keeps order and blobs`() {
        val chain = listOf(byteArrayOf(0x30, 0x01), byteArrayOf(0x30, 0x02, 0x03), byteArrayOf())
        val decoded = ForgeProtocol.decodeCertificateChain(ForgeProtocol.encodeCertificateChain(chain))
        assertEquals(chain.size, decoded.size)
        chain.zip(decoded).forEach { (a, b) -> assertArrayEquals(a, b) }
    }

    @Test
    fun `empty certificate chain round trips`() {
        assertEquals(0, ForgeProtocol.decodeCertificateChain(ForgeProtocol.encodeCertificateChain(emptyList())).size)
    }

    @Test
    fun `request framing is op length payload`() {
        val payload = byteArrayOf(0x0A, 0x0B, 0x0C)
        val frame = ForgeProtocol.encodeRequest(ForgeProtocol.OP_FORGE_CHAIN, payload)
        assertEquals(4 + 4 + 3, frame.size)
        // big-endian op
        assertEquals(ForgeProtocol.OP_FORGE_CHAIN, ((frame[0].toInt() and 0xFF) shl 24) or ((frame[1].toInt() and 0xFF) shl 16) or ((frame[2].toInt() and 0xFF) shl 8) or (frame[3].toInt() and 0xFF))
        // big-endian length
        assertEquals(3, ((frame[4].toInt() and 0xFF) shl 24) or ((frame[5].toInt() and 0xFF) shl 16) or ((frame[6].toInt() and 0xFF) shl 8) or (frame[7].toInt() and 0xFF))
        assertArrayEquals(payload, frame.copyOfRange(8, frame.size))
    }
}
