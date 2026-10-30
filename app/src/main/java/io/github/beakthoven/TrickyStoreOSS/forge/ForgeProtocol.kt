/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS.forge

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream

/**
 * Wire format between the keystore-side [ForgeClient] and the daemon-side [ForgeServer].
 *
 * Every exchange is one request and one response, big-endian, length-prefixed:
 *
 * ```
 * request  = [u32 op][u32 payloadLen][payload]
 * response = [u8 ok][u32 payloadLen][payload]      ok=1: payload is op-specific
 *          | [u8 ok=0][u32 len][utf-8 message]    ok=0: the op failed on the daemon
 * ```
 *
 * An absent daemon surfaces as `null` from [ForgeClient], which callers already treat exactly
 * like any other forge failure — the error semantics are unchanged from the in-process era.
 */
object ForgeProtocol {
    const val OP_FORGE_CHAIN: Int = 1
    const val OP_HACK_LEAF: Int = 2
    const val OP_KEYBOX_CERTS: Int = 3
    const val OP_KEYBOX_STATUS: Int = 4

    /** Name of the abstract-namespace unix socket the daemon listens on. */
    const val SOCKET_NAME: String = "TrickyStoreOSSForgeV1"

    /** AUID boundary: only the keystore uid and root may talk to the forge socket. */
    const val KEYSTORE_UID: Int = 1017

    // --- request builders (keystore side) ---

    /** [ChainBuildRequest] packed for [OP_FORGE_CHAIN]. */
    fun encodeChainRequest(request: ChainBuildRequest): ByteArray {
        val out = ByteArrayOutputStream()
        DataOutputStream(out).use { data ->
            data.writeInt(request.algorithm)
            data.writeBlob(request.leafPrivateKey)
            data.writeBlob(request.attestationDer)
            data.writeLong(request.notBeforeMs)
            data.writeLong(request.notAfterMs)
            data.writeByte(if (request.appendSigningChain) 1 else 0)
            data.writeInt(request.purposes.size)
            request.purposes.forEach { data.writeInt(it) }
            data.writeBlob(request.serialDer)
            data.writeBlob(request.subjectDer)
        }
        return out.toByteArray()
    }

    fun decodeChainRequest(payload: ByteArray): ChainBuildRequest {
        DataInputStream(ByteArrayInputStream(payload)).use { data ->
            val algorithm = data.readInt()
            val leafPrivateKey = data.readBlob()
            val attestationDer = data.readBlob()
            val notBeforeMs = data.readLong()
            val notAfterMs = data.readLong()
            val appendSigningChain = data.readByte().toInt() == 1
            val purposeCount = data.readInt()
            require(purposeCount in 0..MAX_PURPOSES) { "malformed purpose vector" }
            val purposes = IntArray(purposeCount) { data.readInt() }
            val serialDer = data.readBlob()
            val subjectDer = data.readBlob()
            return ChainBuildRequest(
                algorithm = algorithm,
                leafPrivateKey = leafPrivateKey,
                attestationDer = attestationDer,
                notBeforeMs = notBeforeMs,
                notAfterMs = notAfterMs,
                appendSigningChain = appendSigningChain,
                purposes = purposes,
                serialDer = serialDer,
                subjectDer = subjectDer,
            )
        }
    }

    fun encodeLeafHack(leafDer: ByteArray, uid: Int): ByteArray {
        val out = ByteArrayOutputStream()
        DataOutputStream(out).use { data ->
            data.writeBlob(leafDer)
            data.writeInt(uid)
        }
        return out.toByteArray()
    }

    fun decodeLeafHack(payload: ByteArray): Pair<ByteArray, Int> {
        DataInputStream(ByteArrayInputStream(payload)).use { data ->
            val leafDer = data.readBlob()
            val uid = data.readInt()
            return leafDer to uid
        }
    }

    fun encodeKeyboxCerts(algorithm: String): ByteArray {
        val out = ByteArrayOutputStream()
        DataOutputStream(out).use { data ->
            data.writeBlob(algorithm.toByteArray(Charsets.UTF_8))
        }
        return out.toByteArray()
    }

    fun decodeKeyboxCerts(payload: ByteArray): String {
        DataInputStream(ByteArrayInputStream(payload)).use { data ->
            return String(data.readBlob(), Charsets.UTF_8)
        }
    }

    // --- response builders (daemon side) / parsers (keystore side) ---

    fun encodeSuccess(payload: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        DataOutputStream(out).use { data ->
            data.writeByte(1)
            data.writeBlob(payload)
        }
        return out.toByteArray()
    }

    fun encodeFailure(message: String): ByteArray {
        val out = ByteArrayOutputStream()
        DataOutputStream(out).use { data ->
            data.writeByte(0)
            data.writeBlob(message.toByteArray(Charsets.UTF_8))
        }
        return out.toByteArray()
    }

    /** Returns the payload of a successful response, or the failure message as [ForgeError]. */
    fun decodeResponse(blob: ByteArray): ForgeResult {
        DataInputStream(ByteArrayInputStream(blob)).use { data ->
            val ok = data.readByte().toInt() == 1
            val payload = data.readBlob()
            return if (ok) {
                ForgeResult.Success(payload)
            } else {
                ForgeResult.Failure(String(payload, Charsets.UTF_8))
            }
        }
    }

    /** Leaf-first certificate chain, each DER blob length-prefixed (the daemon's chain reply). */
    fun encodeCertificateChain(chains: List<ByteArray>): ByteArray {
        val out = ByteArrayOutputStream()
        DataOutputStream(out).use { data ->
            data.writeInt(chains.size)
            chains.forEach { data.writeBlob(it) }
        }
        return out.toByteArray()
    }

    fun decodeCertificateChain(payload: ByteArray): List<ByteArray> {
        DataInputStream(ByteArrayInputStream(payload)).use { data ->
            val count = data.readInt()
            require(count in 0..MAX_CHAIN_LENGTH) { "malformed chain" }
            return List(count) { data.readBlob() }
        }
    }

    fun encodeRequest(op: Int, payload: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        DataOutputStream(out).use { data ->
            data.writeInt(op)
            data.writeInt(payload.size)
            data.write(payload)
        }
        return out.toByteArray()
    }

    private const val MAX_PURPOSES = 256
    private const val MAX_CHAIN_LENGTH = 32
    private const val MAX_BLOB = 1 shl 22

    private fun DataOutputStream.writeBlob(bytes: ByteArray) {
        writeInt(bytes.size)
        write(bytes)
    }

    private fun DataInputStream.readBlob(): ByteArray {
        val length = readInt()
        require(length in 0..MAX_BLOB) { "malformed blob length $length" }
        val bytes = ByteArray(length)
        readFully(bytes)
        return bytes
    }
}

/**
 * Everything the native chain builder needs about the fresh key, minus the signing material —
 * the daemon injects that from the keybox so the private Google attestation key never crosses
 * back into the keystore process.
 */
data class ChainBuildRequest(
    val algorithm: Int,
    val leafPrivateKey: ByteArray,
    val attestationDer: ByteArray,
    val notBeforeMs: Long,
    val notAfterMs: Long,
    val appendSigningChain: Boolean,
    val purposes: IntArray,
    val serialDer: ByteArray,
    val subjectDer: ByteArray,
)

sealed class ForgeResult {
    class Success(val payload: ByteArray) : ForgeResult()
    class Failure(val message: String) : ForgeResult()
}
