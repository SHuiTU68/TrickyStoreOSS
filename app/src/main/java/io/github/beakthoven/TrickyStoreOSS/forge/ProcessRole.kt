/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS.forge

/**
 * Which copy of this dex is running. The same `payload.bin` is loaded twice: once as the daemon
 * (`app_process`, root) and once inside the keystore process (injected). The keybox — the only
 * long-lived private root of trust — must ever be parsed and held by the daemon, so everything
 * below [KeyBoxUtils] gates on this flag and the keystore-side copy routes through
 * [ForgeClient] instead.
 */
object ProcessRole {
    /** Set by [Main] before any keybox code can run; never set inside the keystore process. */
    @Volatile
    var isForgeHost: Boolean = false
        private set

    fun markAsForgeHost() {
        isForgeHost = true
    }
}
