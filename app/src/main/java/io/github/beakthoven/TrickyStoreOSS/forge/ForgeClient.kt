/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS.forge

import android.net.LocalSocket
import android.net.LocalSocketAddress
import io.github.beakthoven.TrickyStoreOSS.logging.Logger
import java.io.DataInputStream
import java.io.DataOutputStream

/**
 * Keystore-process side of the forge channel. One short-lived connection per request: the
 * operations are rare (key generation, attestation reads), the daemon may restart at any time,
 * and a fresh socket needs no invalidation logic. Every failure returns `null`, which the
 * callers already treat as "forging unavailable" — the same semantics the in-process native
 * path had.
 */
object ForgeClient {
    private const val IO_TIMEOUT_MS = 15_000
    private const val MAX_RESPONSE = 1 shl 22

    fun forgeChain(request: ChainBuildRequest): List<ByteArray>? =
        request(
            ForgeProtocol.OP_FORGE_CHAIN,
            ForgeProtocol.encodeChainRequest(request),
        )?.let { ForgeProtocol.decodeCertificateChain(it) }

    fun hackLeaf(leafDer: ByteArray, uid: Int): List<ByteArray>? =
        request(
            ForgeProtocol.OP_HACK_LEAF,
            ForgeProtocol.encodeLeafHack(leafDer, uid),
        )?.let { ForgeProtocol.decodeCertificateChain(it) }

    fun keyboxCertificates(algorithm: String): ByteArray? =
        request(
            ForgeProtocol.OP_KEYBOX_CERTS,
            ForgeProtocol.encodeKeyboxCerts(algorithm),
        )

    /** Whether the daemon currently holds a parsed keybox (drives the legacy-chain gate). */
    fun keyboxAvailable(): Boolean =
        request(ForgeProtocol.OP_KEYBOX_STATUS, ByteArray(0))?.let { it.isNotEmpty() && it[0].toInt() == 1 }
            ?: false

    private fun request(op: Int, payload: ByteArray): ByteArray? {
        val response =
            runCatching { exchange(op, payload) }
                .onFailure {
                    // A null `message` (bare EOFException, e.g. the daemon closed the connection
                    // without replying) is the most common failure shape here — the class name is
                    // what makes the log line actionable.
                    Logger.d(
                        "Forge daemon unreachable (op=$op): ${it.javaClass.simpleName}: ${it.message}",
                    )
                }
                .getOrNull() ?: return null
        return when (val result = ForgeProtocol.decodeResponse(response)) {
            is ForgeResult.Success -> result.payload
            is ForgeResult.Failure -> {
                Logger.i("Forge daemon rejected op=$op: ${result.message}")
                null
            }
        }
    }

    private fun exchange(op: Int, payload: ByteArray): ByteArray {
        LocalSocket().use { socket ->
            // android.net.LocalSocket#connect(LocalSocketAddress, int) is a stub on every
            // AOSP branch we ship to (13 / 14 / 15 / 16 / master): it throws
            // UnsupportedOperationException() with a null message, so this overload can
            // never connect. The single-argument form calls LocalSocketImpl.connect()
            // directly (fully implemented, and it ignores the timeout anyway), the
            // abstract-namespace connect to a local daemon returns immediately, and the
            // read side stays bounded by soTimeout below.
            socket.connect(
                LocalSocketAddress(ForgeProtocol.SOCKET_NAME, LocalSocketAddress.Namespace.ABSTRACT),
            )
            socket.soTimeout = IO_TIMEOUT_MS
            DataOutputStream(socket.outputStream).use { out ->
                val request = ForgeProtocol.encodeRequest(op, payload)
                out.writeInt(request.size)
                out.write(request)
                out.flush()
            }
            DataInputStream(socket.inputStream).use { input ->
                val length = input.readInt()
                require(length in 1..MAX_RESPONSE) { "malformed response length $length" }
                val response = ByteArray(length)
                input.readFully(response)
                return response
            }
        }
    }
}
