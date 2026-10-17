/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS

import android.os.SystemProperties
import io.github.beakthoven.TrickyStoreOSS.logging.Logger

/**
 * Applies per-package property overrides only while the package is in the foreground.
 *
 * Some detectors insist on a "normal" value for a property that this module deliberately spoofs —
 * e.g. `persist.sys.usb.config` must read `mtp`, while the device keeps USB data off with `none`.
 * Spoofing that globally would win the check at the cost of actually re-enabling USB, so the
 * override is instead gated to the foreground window of the package that performs the check. The
 * value is written globally (whole property area) because that is what detectors read through every
 * path (libc, reflection, `getprop`); it is simply reverted once the package leaves the foreground.
 *
 * Scopes are declared in `hide_props.txt` with `@<package>` lines (see [HideProps.scopedEntries]).
 * The previous value of every touched property is snapshotted before the override and restored
 * afterwards, so a scope never leaks a spoofed value into the rest of the system.
 */
object ForegroundPropGate {
    private const val POLL_INTERVAL_MS = 2000L

    private const val ACTIVITY_FILTER =
        "dumpsys activity activities 2>/dev/null | grep -m1 -E 'topResumedActivity=|mResumedActivity='"
    private const val WINDOW_FILTER = "dumpsys window 2>/dev/null | grep -m1 'mCurrentFocus='"

    // ActivityRecord{<hash> u0 com.example/.MainActivity ...} — the token before '/' is the package.
    private val ACTIVITY_PATTERN = Regex("ActivityRecord\\{[^}]*?\\s([A-Za-z0-9_.]+)/")
    private val WINDOW_PATTERN = Regex("mCurrentFocus=Window\\{[^}]*?\\s([A-Za-z0-9_.]+)/")

    /** Starts the (daemon) poller; a no-op when no `@package` scope is configured. */
    fun start() {
        val scopes = HideProps.scopedEntries()
        if (scopes.isEmpty()) return
        Logger.i("Foreground property gate watching: ${scopes.keys.joinToString()}")
        Thread({ poll(scopes) }, "ForegroundPropGate").apply { isDaemon = true }.start()
    }

    private fun poll(scopes: Map<String, List<Pair<String, String>>>) {
        var active: String? = null
        var snapshot: Map<String, String> = emptyMap()
        while (true) {
            try {
                val foreground = foregroundPackage()
                val next = foreground?.takeIf { scopes.containsKey(it) }
                if (next != active) {
                    if (active != null) restore(snapshot)
                    snapshot = emptyMap()
                    active = next
                    if (next != null) snapshot = override(scopes.getValue(next))
                }
            } catch (t: Throwable) {
                Logger.e("Foreground property gate iteration failed", t)
            }
            runCatching { Thread.sleep(POLL_INTERVAL_MS) }
        }
    }

    /** Applies [entries] and returns the pre-override value of every property that was touched. */
    private fun override(entries: List<Pair<String, String>>): Map<String, String> {
        val snapshot = LinkedHashMap<String, String>()
        for ((name, value) in entries) {
            if (!name.contains('.')) {
                Logger.w("ignoring non-property key in foreground scope: '$name'")
                continue
            }
            if (snapshot.containsKey(name)) continue
            val original = SystemProperties.get(name, null)
            // Only rewrite what the build defined: creating an entry is itself tamper evidence.
            if (original == null) {
                Logger.d("skipping foreground property '$name': not defined on this device")
                continue
            }
            snapshot[name] = original
            if (original != value) HideProps.setProperty(name, value)
        }
        return snapshot
    }

    private fun restore(snapshot: Map<String, String>) {
        for ((name, value) in snapshot) HideProps.setProperty(name, value)
    }

    private fun foregroundPackage(): String? {
        HideProps.runShell(ACTIVITY_FILTER)?.let { dump ->
            ACTIVITY_PATTERN.find(dump)?.groupValues?.get(1)?.let { return it }
        }
        HideProps.runShell(WINDOW_FILTER)?.let { dump ->
            WINDOW_PATTERN.find(dump)?.groupValues?.get(1)?.let { return it }
        }
        return null
    }
}
