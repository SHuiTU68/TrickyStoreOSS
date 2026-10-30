/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS

import android.os.Build
import io.github.beakthoven.TrickyStoreOSS.config.PkgConfig
import io.github.beakthoven.TrickyStoreOSS.forge.ForgeServer
import io.github.beakthoven.TrickyStoreOSS.forge.ProcessRole
import io.github.beakthoven.TrickyStoreOSS.interceptors.Keystore2Interceptor
import io.github.beakthoven.TrickyStoreOSS.interceptors.KeystoreInterceptor
import io.github.beakthoven.TrickyStoreOSS.logging.Logger

private const val RETRY_DELAY_MS = 1000L

fun main(args: Array<String>) {
    Logger.i("Welcome to TrickyStoreOSS!")

    try {
        // This process is the forge host: the keybox is parsed and held here only, and the
        // injected keystore-side copy of this dex asks for keybox-signed material over the forge
        // socket (see ForgeServer/ForgeClient). Marked before anything can touch a keybox.
        ProcessRole.markAsForgeHost()

        // Load the native certificate generator before anything can call into it. The startup probe
        // below parses attestation extensions exclusively through the Rust reader, so probing first
        // reports UNAVAILABLE on every boot even when libcertgen.so would have loaded fine.
        NativeCertGen.initialize()
        val probe = AttestUtils.probe()
        Logger.i("Startup attestation probe: ${probe.status} (${probe.failureCategory ?: "none"})")
        AndroidUtils.setupBootHash()
        HideProps.apply()
        initializeInterceptors()
        ForgeServer.start()
        maintainService()
    } catch (e: Exception) {
        Logger.e("Fatal error in main", e)
        throw e
    }
}

private fun initializeInterceptors() {
    val interceptor = selectKeystoreInterceptor()

    while (!interceptor.tryRunKeystoreInterceptor()) {
        Logger.d("Retrying interceptor initialization...")
        Thread.sleep(RETRY_DELAY_MS)
    }

    PkgConfig.initialize()
    Logger.i("Interceptors initialized successfully")
}

private fun selectKeystoreInterceptor() =
    when {
        Build.VERSION.SDK_INT in Build.VERSION_CODES.Q..Build.VERSION_CODES.R -> {
            Logger.i("Using KeystoreInterceptor for Android Q/R (SDK ${Build.VERSION.SDK_INT})")
            KeystoreInterceptor
        }
        else -> {
            Logger.i("Using Keystore2Interceptor for Android S+ (SDK ${Build.VERSION.SDK_INT})")
            Keystore2Interceptor
        }
    }

private fun maintainService() {
    Logger.i("Service started, entering maintenance mode")
    Thread.currentThread().join()
}
