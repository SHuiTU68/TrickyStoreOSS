/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS.forge

import android.net.Credentials
import android.net.LocalServerSocket
import android.net.LocalSocket
import io.github.beakthoven.TrickyStoreOSS.AndroidUtils
import io.github.beakthoven.TrickyStoreOSS.CertificateGen
import io.github.beakthoven.TrickyStoreOSS.CertificateGen.KeyBox
import io.github.beakthoven.TrickyStoreOSS.CertificateUtils
import io.github.beakthoven.TrickyStoreOSS.KeyBoxUtils
import io.github.beakthoven.TrickyStoreOSS.NativeCertGen
import io.github.beakthoven.TrickyStoreOSS.logging.Logger
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.security.KeyFactory
import java.security.KeyPair
import java.security.spec.PKCS8EncodedKeySpec

/**
 * Daemon-side forge service. The keystore process asks this socket for the three operations that
 * need the keybox — signing a fresh leaf, re-signing a hacked leaf and serving keybox CA
 * certificates — so the keybox private key is parsed and held here, in the root daemon, and
 * never mapped into `keystore2`'s address space.
 *
 * The native calls are the exact ones the in-process path used ([NativeCertGen]); only their
 * execution moved. Connection handling is one thread per connection — requests are rare — and
 * the gate admits only the keystore uid and root: the abstract namespace is global, so without
 * the peer check any app could ask for keybox-signed material.
 */
object ForgeServer {
    private const val MAX_REQUEST = 1 shl 22

    @Volatile
    private var serverThread: Thread? = null

    fun start() {
        check(ProcessRole.isForgeHost) { "ForgeServer must run in the daemon process" }
        if (!NativeCertGen.isAvailable) {
            Logger.e("ForgeServer not started: native certgen unavailable")
            return
        }
        if (serverThread?.isAlive == true) return
        val thread = Thread({ serveLoop() }, "tsoss-forge-server")
        thread.isDaemon = true
        thread.start()
        serverThread = thread
        Logger.i("ForgeServer listening on abstract socket ${ForgeProtocol.SOCKET_NAME}")
    }

    private fun serveLoop() {
        while (!Thread.currentThread().isInterrupted) {
            val server =
                runCatching { LocalServerSocket(ForgeProtocol.SOCKET_NAME) }
                    .onFailure { Logger.e("ForgeServer: cannot bind ${ForgeProtocol.SOCKET_NAME}", it) }
                    .getOrNull() ?: return
            try {
                while (true) {
                    val client = server.accept() ?: break
                    if (!admits(client)) {
                        Logger.w("ForgeServer: rejected peer uid=${peerUid(client)}")
                        runCatching { client.close() }
                        continue
                    }
                    // One thread per connection; generateKey traffic is orders of magnitude below
                    // where pooling starts to matter.
                    Thread({ handle(client) }, "tsoss-forge-conn").run { start(); Unit }
                }
            } catch (e: Exception) {
                Logger.w("ForgeServer: accept loop restarting: ${e.message}")
            } finally {
                runCatching { server.close() }
            }
        }
    }

    private fun peerUid(client: LocalSocket): Int =
        runCatching { client.peerCredentials.uid }.getOrDefault(-1)

    private fun admits(client: LocalSocket): Boolean =
        peerUid(client) in intArrayOf(ForgeProtocol.KEYSTORE_UID, 0)

    private fun handle(client: LocalSocket) {
        try {
            client.soTimeout = 15_000
            DataInputStream(client.inputStream).use { input ->
                DataOutputStream(client.outputStream).use { out ->
                    while (true) {
                        val length = input.readInt()
                        if (length !in 1..MAX_REQUEST) break
                        val request = ByteArray(length).also { input.readFully(it) }
                        val stream = DataInputStream(request.inputStream())
                        val op = stream.readInt()
                        val payload = ByteArray(request.size - 4).also { stream.readFully(it) }
                        val response = dispatch(op, payload)
                        out.writeInt(response.size)
                        out.write(response)
                        out.flush()
                    }
                }
            }
        } catch (e: Exception) {
            Logger.d("ForgeServer: connection ended: ${e.message}")
        } finally {
            runCatching { client.close() }
        }
    }

    private fun dispatch(op: Int, payload: ByteArray): ByteArray =
        runCatching { when (op) {
                ForgeProtocol.OP_FORGE_CHAIN -> handleForgeChain(payload)
                ForgeProtocol.OP_HACK_LEAF -> handleHackLeaf(payload)
                ForgeProtocol.OP_KEYBOX_CERTS -> handleKeyboxCerts(payload)
                ForgeProtocol.OP_KEYBOX_STATUS ->
                    ForgeProtocol.encodeSuccess(byteArrayOf(if (KeyBoxUtils.hasKeyboxes()) 1 else 0))
                else -> ForgeProtocol.encodeFailure("unknown op $op")
            }
        }.getOrElse { ForgeProtocol.encodeFailure("${it.javaClass.simpleName}: ${it.message}") }

    // --- op handlers ---

    private fun handleForgeChain(payload: ByteArray): ByteArray {
        val request = ForgeProtocol.decodeChainRequest(payload)
        val keybox =
            keyboxForAlgorithm(request.algorithm)
                ?: return ForgeProtocol.encodeFailure("no keybox for algorithm ${request.algorithm}")
        if (keybox.certificates.isEmpty()) return ForgeProtocol.encodeFailure("keybox has no certificates")

        val signing = io.github.beakthoven.TrickyStoreOSS.CertificateGen.keyboxSigningMaterial(keybox)
        val chain =
            NativeCertGen.nativeBuildCertificateChain(
                io.github.beakthoven.TrickyStoreOSS.CertificateGen.encodeChainBuildRequest(
                    algorithm = request.algorithm,
                    leafPrivateKey = request.leafPrivateKey,
                    attestationDer = request.attestationDer,
                    signing = signing,
                    notBeforeMs = request.notBeforeMs,
                    notAfterMs = request.notAfterMs,
                    appendSigningChain = request.appendSigningChain,
                    purposes = request.purposes,
                    serialDer = request.serialDer,
                    subjectDer = request.subjectDer,
                ),
            )
        return ForgeProtocol.encodeSuccess(
            ForgeProtocol.encodeCertificateChain(splitCertificates(chain)),
        )
    }

    private fun handleHackLeaf(payload: ByteArray): ByteArray {
        val (leafDer, uid) = ForgeProtocol.decodeLeafHack(payload)
        val leaf =
            CertificateUtils.certificateFactory.generateCertificate(leafDer.inputStream())
                as java.security.cert.X509Certificate
        val keybox =
            keyboxForName(leaf.publicKey.algorithm)
                ?: return ForgeProtocol.encodeFailure("no keybox for algorithm ${leaf.publicKey.algorithm}")
        val hacked =
            NativeCertGen.nativeHackCertificateChain(encodeNativeHackRequest(leaf, keybox, uid))
        return ForgeProtocol.encodeSuccess(
            ForgeProtocol.encodeCertificateChain(splitCertificates(hacked)),
        )
    }

    private fun handleKeyboxCerts(payload: ByteArray): ByteArray {
        val algorithm = ForgeProtocol.decodeKeyboxCerts(payload)
        val keybox =
            keyboxForName(algorithm)
                ?: return ForgeProtocol.encodeFailure("no keybox for algorithm $algorithm")
        val der = CertificateUtils.run { keybox.certificates.toByteArray() }
            ?: return ForgeProtocol.encodeFailure("keybox certificates unreadable")
        return ForgeProtocol.encodeSuccess(der)
    }

    // --- keybox lookup (daemon-local; KeyBoxUtils is never loaded in the keystore process) ---

    private fun keyboxForAlgorithm(algorithm: Int): KeyBox? {
        val name =
            when (algorithm) {
                android.hardware.security.keymint.Algorithm.EC ->
                    android.security.keystore.KeyProperties.KEY_ALGORITHM_EC
                android.hardware.security.keymint.Algorithm.RSA ->
                    android.security.keystore.KeyProperties.KEY_ALGORITHM_RSA
                else -> return null
            }
        return keyboxForName(name)
    }

    private fun keyboxForName(name: String): KeyBox? =
        KeyBoxUtils.keyboxes[name] ?: KeyBoxUtils.keyboxes.values.firstOrNull()

    // --- native request packing (moved from the keystore-side classes, byte-for-byte) ---

    /** The Rust `hack_leaf` request, rebuilt from the daemon-held keybox. */
    private fun encodeNativeHackRequest(
        leaf: java.security.cert.X509Certificate,
        keybox: KeyBox,
        uid: Int,
    ): ByteArray {
        val patch = AndroidUtils.resolvePatchLevels(uid)
        val out = ByteArrayOutputStream()
        DataOutputStream(out).use { data ->
            data.writeBlob(leaf.encoded)
            data.writeBlob(keybox.keyPair.private.encoded)
            data.writeBlob(CertificateUtils.run { keybox.certificates.toByteArray() } ?: ByteArray(0))
            data.writeBlob(AndroidUtils.bootKey)
            data.writeBlob(AndroidUtils.getBootHashFromProp() ?: ByteArray(0))
            data.writeInt(AndroidUtils.osVersion)
            data.writeOptionalInt(patch.osOverride)
            data.writeOptionalInt(patch.vendorOverride)
            data.writeOptionalInt(patch.bootOverride)
        }
        return out.toByteArray()
    }

    private fun DataOutputStream.writeBlob(bytes: ByteArray) {
        writeInt(bytes.size)
        write(bytes)
    }

    private fun DataOutputStream.writeLengthPrefixed(bytes: ByteArray) {
        writeInt(bytes.size)
        write(bytes)
    }

    private fun DataOutputStream.writeOptionalInt(value: Int?) {
        writeBoolean(value != null)
        value?.let { writeInt(it) }
    }

    /** Rebuilds a `java.security.KeyPair` from a native keygen blob (private then public). */
    fun keyPairFromNativeBlob(blob: ByteArray): KeyPair {
        val buffer = java.nio.ByteBuffer.wrap(blob)
        fun readBlob(): ByteArray {
            val length = buffer.int
            require(length in 0..buffer.remaining()) { "malformed native keygen blob" }
            return ByteArray(length).also { buffer.get(it) }
        }
        val privateKey = readBlob()
        val publicKey = readBlob()
        val factory = KeyFactory.getInstance("EC")
        return KeyPair(
            factory.generatePublic(java.security.spec.X509EncodedKeySpec(publicKey)),
            factory.generatePrivate(java.security.spec.PKCS8EncodedKeySpec(privateKey)),
        )
    }

    /** Splits the back-to-back leaf-first DER certificates the native builders return. */
    fun splitCertificates(blob: ByteArray): List<ByteArray> =
        CertificateUtils.run { blob.toCertificates().map { it.encoded } }
}
