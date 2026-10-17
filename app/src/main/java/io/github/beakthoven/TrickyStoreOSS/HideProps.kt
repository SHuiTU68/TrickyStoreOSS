/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS

import android.os.SystemProperties
import io.github.beakthoven.TrickyStoreOSS.logging.Logger
import java.io.File

/**
 * Boot-time, global system-property spoofing.
 *
 * `ro.*` properties are read-only once init has set them, so a plain [SystemProperties.set] silently
 * fails. Every write here therefore goes through `resetprop`, which edits the shared property area
 * directly and leaves no observable "property changed" trace.
 *
 * The whole config is resolved once at startup and applied in a single shell invocation: properties
 * whose value already matches are skipped outright, so the cost is a couple of fork/execs per boot
 * and the keystore hot path stays untouched.
 */
object HideProps {
    private const val CONFIG_FILE = "/data/adb/tricky_store/hide_props.txt"

    // Keys without a dot are behaviour switches, not properties.
    private const val ADB_KEY = "adb"
    private const val USB_KEY = "usb"

    private const val SHELL = "/system/bin/sh"
    private const val SETPROP = "/system/bin/setprop"
    private const val SETTINGS = "/system/bin/settings"

    private val RESETPROP_CANDIDATES =
        listOf(
            "resetprop",
            "/data/adb/magisk/resetprop",
            "/data/adb/ksu/bin/resetprop",
            "/data/adb/ap/bin/resetprop",
        )

    private val resetprop: String? by lazy { locateBinary(RESETPROP_CANDIDATES) }

    /** Applies the configured spoofing once at boot; a missing [CONFIG_FILE] is a no-op. */
    fun apply() {
        val entries = readConfig(File(CONFIG_FILE))
        if (entries.isEmpty()) return

        val resetpropPath = resetprop
        val script = StringBuilder()
        var properties = 0
        for ((name, value) in entries) {
            when {
                name.equals(ADB_KEY, ignoreCase = true) -> appendAdb(script, value)
                name.equals(USB_KEY, ignoreCase = true) -> appendUsb(script, value)
                name.contains('.') -> {
                    if (resetpropPath == null) {
                        Logger.e("resetprop not found; cannot spoof '$name'")
                    } else if (SystemProperties.get(name, null) != value) {
                        script
                            .append(shellQuote(resetpropPath))
                            .append(' ')
                            .append(shellQuote(name))
                            .append(' ')
                            .append(shellQuote(value))
                            .append('\n')
                        properties++
                    }
                }
                else -> Logger.w("ignoring unknown hide_props key: '$name'")
            }
        }
        if (script.isNotEmpty()) {
            Logger.i("Applying boot property spoofing ($properties properties changed)")
            runShell(script.toString())
        }
    }

    /** Sets a single property through resetprop; returns false when it could not be applied. */
    fun setProperty(name: String, value: String): Boolean {
        if (SystemProperties.get(name, null) == value) return true
        val resetpropPath = resetprop ?: return false
        return runShell(shellQuote(resetpropPath) + " " + shellQuote(name) + " " + shellQuote(value)) != null
    }

    private fun appendAdb(script: StringBuilder, value: String) {
        if (!value.equals("off", ignoreCase = true) && !value.equals("disable", ignoreCase = true) && value != "0") {
            Logger.w("hide_props: unsupported adb value '$value' (expected 'off')")
            return
        }
        script.append(SETTINGS).append(" put global adb_enabled 0\n")
    }

    private fun appendUsb(script: StringBuilder, value: String) {
        if (value.isEmpty()) return
        script.append(SETPROP).append(" sys.usb.config ").append(shellQuote(value)).append('\n')
        script.append(SETPROP).append(" persist.sys.usb.config ").append(shellQuote(value)).append('\n')
    }

    private fun readConfig(file: File): List<Pair<String, String>> {
        if (!file.exists()) return emptyList()
        return runCatching {
                file.readLines().mapNotNull { line ->
                    val entry = line.substringBefore('#').trim()
                    if (entry.isEmpty()) return@mapNotNull null
                    val separator = entry.indexOf('=')
                    if (separator <= 0) {
                        Logger.w("ignoring malformed hide_props line: $line")
                        return@mapNotNull null
                    }
                    val name = entry.substring(0, separator).trim()
                    val value = entry.substring(separator + 1).trim()
                    if (name.isEmpty()) null else name to value
                }
            }
            .onFailure { Logger.e("failed to read $CONFIG_FILE", it) }
            .getOrDefault(emptyList())
    }

    private fun locateBinary(candidates: List<String>): String? {
        val commands = candidates.joinToString(" ") { shellQuote(it) }
        val output =
            runShell(
                "for c in $commands; do " +
                    "if command -v \"\$c\" >/dev/null 2>&1; then printf '%s' \"\$c\"; exit 0; fi; " +
                    "done; exit 1",
            )
        return output?.trim()?.takeIf { it.isNotEmpty() }
    }

    private fun runShell(script: String): String? =
        runCatching {
            val process = ProcessBuilder(SHELL, "-c", script).redirectErrorStream(true).start()
            val output = process.inputStream.bufferedReader().use { it.readText() }
            if (process.waitFor() == 0) output else null
        }.getOrElse { null }

    private fun shellQuote(value: String): String = "'" + value.replace("'", "'\\''") + "'"
}
