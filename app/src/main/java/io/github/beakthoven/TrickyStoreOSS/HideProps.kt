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
 * fails. Every write here therefore goes through `resetprop -n`, which edits the shared property area
 * in place and bypasses `property_service` (so no `on property:` events fire).
 *
 * Two rules keep the write invisible to property-area tamper checks:
 *   - Only properties that already exist on this build are rewritten. Inserting a brand-new entry
 *     takes a write fault on a fresh property-area page, which moves the area's mtime and leaves a
 *     property the build never defined (e.g. `sys.oem_unlock_allowed` on Android 16+). Both are
 *     recorded as tamper evidence, so a missing property is skipped instead of created.
 *   - In-place rewrites of existing entries normally leave the area mtime untouched.
 *
 * A line with no `=` is a removal directive instead of an assignment: the property is deleted from
 * the area altogether. Some keys cannot be spoofed at all because the only safe state is "absent" —
 * `sys.oem_unlock_allowed` is one of them. `frameworks/base` stopped writing it in Android 16, so
 * a build that still exposes it was written by something outside the platform, and detectors treat
 * any non-empty value as evidence of tampering rather than checking the value itself.
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
    private const val FINGERPRINT_KEY = "fp"
    private const val SHELL = "/system/bin/sh"
    private const val SETTINGS = "/system/bin/settings"
    private val USB_PROPERTIES = listOf("sys.usb.config", "persist.sys.usb.config", "sys.usb.state")

    /**
     * Every build fingerprint a device can expose, paired with the property prefix that holds that
     * partition's own product identity. `ro.build.fingerprint` belongs to the system partition.
     */
    private val FINGERPRINT_PROPERTIES =
        listOf(
            "ro.build.fingerprint" to "ro.product",
            "ro.system.build.fingerprint" to "ro.product.system",
            "ro.system_ext.build.fingerprint" to "ro.product.system_ext",
            "ro.vendor.build.fingerprint" to "ro.product.vendor",
            "ro.odm.build.fingerprint" to "ro.product.odm",
            "ro.product.build.fingerprint" to "ro.product.product",
            "ro.bootimage.build.fingerprint" to "ro.product.bootimage",
        )

    /** One `hide_props.txt` line: a non-null [value] assigns, a null [value] removes the key. */
    private data class HideEntry(val name: String, val value: String?)

    private val RESETPROP_CANDIDATES =
        listOf(
            "resetprop",
            "/data/adb/magisk/resetprop",
            "/data/adb/ksu/bin/resetprop",
            "/data/adb/ap/bin/resetprop",
        )

    private val resetprop: String? by lazy { locateBinary(RESETPROP_CANDIDATES) }

    /** Applies the global spoofing once at boot; a missing [CONFIG_FILE] is a no-op. */
    fun apply() {
        val entries = parseConfig(File(CONFIG_FILE))
        if (entries.isEmpty()) return

        val resetpropPath = resetprop
        val script = StringBuilder()
        // The assignments the config is about to make, so the fingerprint chain can be composed from
        // the values the device will report *after* this run rather than the ones it reports now.
        val configured = HashMap<String, String>()
        var spoofFingerprint = false
        var properties = 0
        var removals = 0
        for (entry in entries) {
            val name = entry.name
            val value = entry.value
            if (value == null) {
                removals += appendRemove(script, name, resetpropPath)
                continue
            }
            when {
                name.equals(ADB_KEY, ignoreCase = true) -> appendAdb(script, value)
                name.equals(USB_KEY, ignoreCase = true) -> appendUsb(script, value, resetpropPath)
                name.equals(FINGERPRINT_KEY, ignoreCase = true) -> {
                    spoofFingerprint = parseSwitch(value, FINGERPRINT_KEY)
                }
                name.contains('.') -> {
                    val current = SystemProperties.get(name, null)
                    when {
                        resetpropPath == null -> Logger.e("resetprop not found; cannot spoof '$name'")
                        // Skip a property this build never defined: creating it inserts a new entry
                        // (fresh-page write fault -> mtime moves) and leaves a non-AOSP property that
                        // tamper checks flag. Rewriting an existing entry is the only safe edit.
                        current == null -> Logger.d("skipping '$name': not defined on this device")
                        else -> {
                            // Record only what this build can actually report: a skipped assignment
                            // must not leak into the fingerprint chain, or the composed fingerprint
                            // would advertise an identity the device never had.
                            configured[name] = value
                            if (current != value) {
                                script.append(resetpropCommand(resetpropPath, name, value))
                                properties++
                            }
                        }
                    }
                }
                else -> Logger.w("ignoring unknown hide_props key: '$name'")
            }
        }
        // Composed last: every fingerprint is derived from the product identity this run is about to
        // install, so the chain describes the device the rest of the config just built.
        if (spoofFingerprint && resetpropPath != null) {
            properties += appendFingerprints(script, configured, resetpropPath)
        }
        if (script.isNotEmpty()) {
            Logger.i("Applying boot property spoofing ($properties properties changed, $removals removed)")
            runShell(script.toString())
        }
    }

    /** Sets a single property through resetprop; returns false when it could not be applied. */
    fun setProperty(name: String, value: String): Boolean {
        if (SystemProperties.get(name, null) == value) return true
        val resetpropPath = resetprop ?: return false
        return runShell(resetpropCommand(resetpropPath, name, value)) != null
    }

    private fun resetpropCommand(resetpropPath: String, name: String, value: String): String =
        shellQuote(resetpropPath) + " -n " + shellQuote(name) + " " + shellQuote(value) + '\n'

    private fun appendAdb(script: StringBuilder, value: String) {
        if (!value.equals("off", ignoreCase = true) && !value.equals("disable", ignoreCase = true) && value != "0") {
            Logger.w("hide_props: unsupported adb value '$value' (expected 'off')")
            return
        }
        script.append(SETTINGS).append(" put global adb_enabled 0\n")
    }

    private fun appendUsb(
        script: StringBuilder,
        value: String,
        resetpropPath: String?,
    ) {
        if (value.isEmpty()) return
        val resetprop = resetpropPath ?: return Logger.e("resetprop not found; cannot spoof usb config")
        // `setprop` is unusable here: `sys.usb.config` is owned by init's `on property:` triggers, so
        // writing it notifies property_service, fires those triggers and reconfigures the gadget —
        // exactly the transition a detector watches for. `resetprop -n` edits the property area in
        // place without notifying property_service, which is how every other key in this file is
        // spoofed. Entries this build never defined are skipped for the mtime/fresh-page reason
        // documented above; `sys.usb.state` only exists once a gadget function is bound.
        for (name in USB_PROPERTIES) {
            when {
                SystemProperties.get(name, null) == null ->
                    Logger.d("skipping '$name': not defined on this device")
                else -> script.append(resetpropCommand(resetprop, name, value))
            }
        }
    }

    /**
     * Deletes a property from the area entirely (`hide_props.txt` line without `=`).
     *
     * Used for keys whose only safe state is non-existence: rewriting the value cannot help because
     * the check is "does this property exist", not "what does it hold". An absent key is skipped, so
     * a second boot on an already-clean device is a no-op and cannot move the area mtime.
     *
     * @return 1 when a delete command was emitted, 0 when the key was already absent.
     */
    private fun appendRemove(
        script: StringBuilder,
        name: String,
        resetpropPath: String?,
    ): Int {
        if (!name.contains('.')) {
            Logger.w("hide_props: '$name' has no value and is not a property name; ignoring")
            return 0
        }
        val resetprop = resetpropPath ?: return 0.also {
            Logger.e("resetprop not found; cannot remove '$name'")
        }
        if (SystemProperties.get(name, null) == null) return 0
        script.append(shellQuote(resetprop)).append(" --delete ").append(shellQuote(name)).append('\n')
        return 1
    }

    /**
     * Rebuilds every `ro.*.build.fingerprint` from the device's own product identity.
     *
     * A fingerprint is not a free-form string: it is
     * `brand/product/device:release/id/incremental:type/tags`, and a detector can cross-check each
     * segment against the `ro.product.*` properties it claims to describe. Hard-coding some other
     * device's fingerprint therefore *creates* the inconsistency it was meant to hide, so the value
     * is composed here instead — from the very properties this run just installed. The result is by
     * construction self-consistent, and it only differs from what the build shipped when the config
     * actually changed the product identity.
     *
     * @return the number of fingerprint properties rewritten.
     */
    private fun appendFingerprints(
        script: StringBuilder,
        configured: Map<String, String>,
        resetpropPath: String,
    ): Int {
        // The build identity half of the fingerprint is shared by every partition.
        val release = effective(configured, "ro.build.version.release")
        val id = effective(configured, "ro.build.id")
        val incremental = effective(configured, "ro.build.version.incremental")
        val type = effective(configured, "ro.build.type")
        val tags = effective(configured, "ro.build.tags")
        if (release == null || id == null || incremental == null || type == null || tags == null) {
            Logger.w("skipping fingerprint chain: the build identity properties are incomplete")
            return 0
        }

        var rewritten = 0
        for ((fingerprintProperty, productPrefix) in FINGERPRINT_PROPERTIES) {
            val brand = effective(configured, "$productPrefix.brand")
            val product = effective(configured, "$productPrefix.name")
            val device = effective(configured, "$productPrefix.device")
            if (brand == null || product == null || device == null) {
                Logger.d("skipping '$fingerprintProperty': '$productPrefix.*' is incomplete")
                continue
            }
            val current = SystemProperties.get(fingerprintProperty, null)
            val composed = "$brand/$product/$device:$release/$id/$incremental:$type/$tags"
            when {
                // Same rule as every other key in this file: never create an entry the build did not
                // define, and never rewrite one that already holds the right value.
                current == null ->
                    Logger.d("skipping '$fingerprintProperty': not defined on this device")
                current == composed -> Unit
                else -> {
                    script.append(resetpropCommand(resetpropPath, fingerprintProperty, composed))
                    rewritten++
                }
            }
        }
        return rewritten
    }

    /**
     * Reads the value a property will hold after this run: a pending assignment from the config
     * wins over the live value, because the live one is what is being replaced.
     */
    private fun effective(
        configured: Map<String, String>,
        name: String,
    ): String? = configured[name] ?: SystemProperties.get(name, null)?.takeIf { it.isNotEmpty() }

    /** Parses the on/off style behaviour switches (`adb`, `usb`, `fp`). */
    private fun parseSwitch(
        value: String,
        key: String,
    ): Boolean =
        when (value.lowercase()) {
            "on", "true", "1", "yes", "enable", "enabled" -> true
            "off", "false", "0", "no", "disable", "disabled" -> false
            else -> {
                Logger.w("hide_props: unsupported $key value '$value' (expected 'on' or 'off')")
                false
            }
        }

    private fun parseConfig(file: File): List<HideEntry> {
        if (!file.exists()) return emptyList()
        return runCatching {
                file.readLines().mapNotNull { line ->
                    val entry = line.substringBefore('#').trim()
                    if (entry.isEmpty()) return@mapNotNull null
                    val separator = entry.indexOf('=')
                    // A name with no `=` is a removal directive: delete the property, do not set it.
                    if (separator < 0) {
                        val name = entry.trim()
                        return@mapNotNull name.ifEmpty { null }?.let { HideEntry(it, null) }
                    }
                    if (separator == 0) {
                        Logger.w("ignoring malformed hide_props line: $line")
                        return@mapNotNull null
                    }
                    val name = entry.substring(0, separator).trim()
                    val value = entry.substring(separator + 1).trim()
                    name.ifEmpty { null }?.let { HideEntry(it, value) }
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
