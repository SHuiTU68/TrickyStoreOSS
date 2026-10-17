/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS

import io.github.beakthoven.TrickyStoreOSS.logging.Logger

/**
 * JNI bridge to the native `libcertgen.so` (Rust `native-certgen` crate).
 *
 * The crate is currently a pipeline skeleton exposing only smoke-test entry points; the real
 * keygen / certificate / attestation port will add its JNI functions here. Until then [isAvailable]
 * gates nothing and callers keep using the BouncyCastle path.
 */
object NativeCertGen {
    // Magisk/KernelSU/APatch all mount modules at this fixed path, and the daemon starts from here.
    private const val LIBRARY_PATH = "/data/adb/modules/tricky_store/libcertgen.so"

    @Volatile var isAvailable: Boolean = false
        private set

    fun initialize() {
        try {
            System.load(LIBRARY_PATH)
            isAvailable = true
            Logger.i("NativeCertGen: loaded $LIBRARY_PATH (version=${nativeVersion()}, selfTest=${selfTest()})")
        } catch (e: UnsatisfiedLinkError) {
            Logger.e("NativeCertGen: failed to load $LIBRARY_PATH, falling back to BouncyCastle", e)
        }
    }

    external fun nativeVersion(): String

    external fun selfTest(): Boolean
}
