/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS

import android.hardware.security.keymint.IKeyMintDevice
import android.os.Build
import android.os.IBinder
import android.os.Parcel
import android.os.ServiceManager
import androidx.annotation.RequiresApi
import io.github.beakthoven.TrickyStoreOSS.logging.Logger
import java.nio.ByteBuffer

/**
 * Resolves versions from Android 12+ native KeyMint and legacy Keymaster backends.
 *
 * Only the binder plumbing lives here: the service lookup, the AIDL `interfaceVersion` read and the
 * hand-rolled compat `Parcel` transaction all need a live `IBinder`, so they cannot move. Everything
 * that turns a number into an attestation/keymaster pair — the KeyMint instance names, the
 * `interfaceVersion * 100` scaling and the legacy `20`/`30`/`40`/`41` table — is owned by the native
 * `version` module and returned as an eight-byte big-endian pair.
 */
@RequiresApi(Build.VERSION_CODES.S)
internal object KeyMintVersionResolver {
    fun resolve(securityLevel: Int): AndroidUtils.AttestationVersions? =
        nativeKeyMintVersions(securityLevel) ?: compatKeymasterVersions(securityLevel)

    private fun keyMintInstance(securityLevel: Int): String? =
        NativeCertGen.nativeVersionKeyMintInstance(securityLevel)

    private fun nativeKeyMintVersions(securityLevel: Int): AndroidUtils.AttestationVersions? {
        val instance = keyMintInstance(securityLevel) ?: return null
        val serviceName = "${IKeyMintDevice.DESCRIPTOR}/$instance"
        val binder = ServiceManager.checkService(serviceName) ?: return null

        return runCatching {
                val keyMint = IKeyMintDevice.Stub.asInterface(binder)
                decodeVersions(NativeCertGen.nativeVersionFromInterfaceVersion(keyMint.interfaceVersion))
            }
            .onSuccess { versions -> if (versions != null) Logger.i("Resolved $serviceName versions: $versions") }
            .onFailure { Logger.w("Failed to query $serviceName interface version", it) }
            .getOrNull()
    }

    private fun legacyKeymasterVersions(versionNumber: Int): AndroidUtils.AttestationVersions? =
        decodeVersions(NativeCertGen.nativeVersionLegacyKeymaster(versionNumber))

    private const val COMPAT_DESCRIPTOR = "android.security.compat.IKeystoreCompatService"
    private const val TRANSACTION_GET_KEYMINT_DEVICE = IBinder.FIRST_CALL_TRANSACTION

    private fun compatKeyMintDevice(binder: IBinder, securityLevel: Int): IKeyMintDevice? {
        val data = Parcel.obtain()
        val reply = Parcel.obtain()
        return try {
            data.writeInterfaceToken(COMPAT_DESCRIPTOR)
            data.writeInt(securityLevel)
            if (!binder.transact(TRANSACTION_GET_KEYMINT_DEVICE, data, reply, 0)) return null
            reply.readException()
            reply.readStrongBinder()?.let { IKeyMintDevice.Stub.asInterface(it) }
        } finally {
            reply.recycle()
            data.recycle()
        }
    }

    private fun compatKeymasterVersions(securityLevel: Int): AndroidUtils.AttestationVersions? {
        val serviceName = "android.security.compat"
        val binder = ServiceManager.checkService(serviceName) ?: return null

        return runCatching {
                val keyMint = compatKeyMintDevice(binder, securityLevel)
                    ?: error("No compat KeyMint device for level $securityLevel")
                val hardwareInfo = keyMint.hardwareInfo
                require(hardwareInfo.securityLevel == securityLevel) {
                    "Compat KeyMint security level ${hardwareInfo.securityLevel}, requested $securityLevel"
                }
                legacyKeymasterVersions(hardwareInfo.versionNumber)
                    ?: error("Unsupported legacy Keymaster version: ${hardwareInfo.versionNumber}")
            }
            .onSuccess { versions -> Logger.i("Resolved $serviceName level=$securityLevel versions: $versions") }
            .onFailure { Logger.w("Failed to query $serviceName level=$securityLevel", it) }
            .getOrNull()
    }

    /** Number of bytes in the native `[i32 attestation][i32 keymaster]` wire form. */
    private const val VERSIONS_BYTES = 8

    /**
     * Decodes the native pair. A null blob means the native side had no answer for the input, which
     * is not an error: the caller falls through to the next resolution strategy. A non-null blob of
     * the wrong width would be a programming error, so it throws instead of being silently ignored.
     */
    private fun decodeVersions(blob: ByteArray?): AndroidUtils.AttestationVersions? {
        if (blob == null) return null
        require(blob.size == VERSIONS_BYTES) {
            "Expected $VERSIONS_BYTES version bytes, got ${blob.size}"
        }
        val buffer = ByteBuffer.wrap(blob)
        return AndroidUtils.AttestationVersions(attestation = buffer.int, keymaster = buffer.int)
    }
}