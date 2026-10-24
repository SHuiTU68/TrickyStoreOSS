/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS

import io.github.beakthoven.TrickyStoreOSS.logging.Logger
import java.io.File
import java.nio.ByteBuffer

/**
 * Boot-time, global system-property spoofing.
 *
 * `ro.*` properties are read-only once init has set them, so a plain [android.os.SystemProperties.set]
 * silently fails. Every write here therefore goes through `resetprop -n`, which edits the shared
 * property area in place and bypasses `property_service` (so no `on property:` events fire).
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
 *
 * The planner itself lives in the native crate (`native-certgen`'s `hide_props` module): it is pure
 * logic over a property-reader and a shell-runner trait, so it is unit-tested on the host without a
 * device. This object is the wrapper — it reads the config file, hands the text over, replays the
 * log lines the planner returned through [Logger] and finally runs the script. Splitting it this way
 * keeps every "which properties exist / which resetprop is installed" decision in one tested place
 * while the Kotlin side stays a thin, obvious adapter.
 */
object HideProps {
    private const val CONFIG_FILE = "/data/adb/tricky_store/hide_props.txt"
    private const val SHELL = "/system/bin/sh"

    // Must match `report::Level` in the native crate, which is the wire contract for the notes.
    private const val LEVEL_DEBUG = 1
    private const val LEVEL_WARN = 2
    private const val LEVEL_ERROR = 3

    /** One log line the planner produced, replayed here so the daemon keeps a single log sink. */
    private class Note(val level: Int, val message: String)

    /** The planner's decision: what to log, what to run, and what the summary line should say. */
    private class Plan(val notes: List<Note>, val script: String, val changed: Int, val removed: Int)

    /** Applies the global spoofing once at boot; a missing [CONFIG_FILE] is a no-op. */
    fun apply() {
        if (!NativeCertGen.isAvailable) {
            Logger.e("hide_props: libcertgen.so unavailable; skipping global property spoofing")
            return
        }
        val config =
            runCatching { File(CONFIG_FILE).readText() }
                .onFailure { Logger.e("failed to read $CONFIG_FILE", it) }
                .getOrNull() ?: return
        val plan =
            runCatching { parsePlan(NativeCertGen.nativeHidePropsPlan(config)) }
                .onFailure { Logger.e("failed to plan global property spoofing", it) }
                .getOrNull() ?: return
        for (note in plan.notes) {
            when (note.level) {
                LEVEL_DEBUG -> Logger.d(note.message)
                LEVEL_WARN -> Logger.w(note.message)
                LEVEL_ERROR -> Logger.e(note.message)
                else -> Logger.i(note.message)
            }
        }
        // An empty script means there is nothing to apply at all: every assignment was already in
        // place, every key was skipped, or the config only held behaviour switches. Do not fork.
        if (plan.script.isEmpty()) return
        Logger.i("Applying boot property spoofing (${plan.changed} properties changed, ${plan.removed} removed)")
        runShell(plan.script)
    }

    /** Sets a single property through resetprop; returns false when it could not be applied. */
    fun setProperty(name: String, value: String): Boolean {
        if (!NativeCertGen.isAvailable) {
            Logger.e("hide_props: libcertgen.so unavailable; cannot set '$name'")
            return false
        }
        return runCatching { NativeCertGen.nativeHidePropsSetProperty(name, value) }
            .onFailure { Logger.e("failed to set '$name'", it) }
            .getOrDefault(false)
    }

    /**
     * Decodes the planner's response blob:
     * `[notes][u32 scriptLen][script][u32 changed][u32 removed]`, with the notes section itself
     * `[u32 count]{ [u8 level][u32 len][message] }`.
     *
     * The count is validated against the remaining bytes before it is used for an allocation: the
     * blob comes back from JNI and a truncated one must not be able to ask for a huge list.
     */
    private fun parsePlan(blob: ByteArray): Plan {
        val buffer = ByteBuffer.wrap(blob)
        require(buffer.remaining() >= 4) { "truncated native hide_props blob" }
        val count = buffer.int
        // Each note costs at least five bytes: one level plus a four-byte length prefix.
        require(count in 0..(buffer.remaining() / 5)) { "malformed native hide_props note count: $count" }
        val notes = ArrayList<Note>(count)
        repeat(count) {
            require(buffer.remaining() >= 5) { "truncated native hide_props note" }
            val level = buffer.get().toInt() and 0xFF
            notes += Note(level, buffer.readLengthPrefixed().toString(Charsets.UTF_8))
        }
        val script = buffer.readLengthPrefixed().toString(Charsets.UTF_8)
        require(buffer.remaining() >= 8) { "truncated native hide_props counters" }
        val changed = buffer.int
        val removed = buffer.int
        require(changed >= 0 && removed >= 0) { "negative native hide_props counter" }
        return Plan(notes, script, changed, removed)
    }

    private fun ByteBuffer.readLengthPrefixed(): ByteArray {
        require(remaining() >= 4) { "truncated native hide_props field" }
        val length = int
        require(length in 0..remaining()) { "malformed native hide_props blob" }
        val bytes = ByteArray(length)
        get(bytes)
        return bytes
    }

    private fun runShell(script: String): String? =
        runCatching {
            val process = ProcessBuilder(SHELL, "-c", script).redirectErrorStream(true).start()
            val output = process.inputStream.bufferedReader().use { it.readText() }
            if (process.waitFor() == 0) output else null
        }.getOrElse { null }
}