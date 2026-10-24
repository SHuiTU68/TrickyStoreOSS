/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS.config

import android.content.pm.IPackageManager
import android.os.Build
import android.os.FileObserver
import android.os.IBinder
import android.os.IInterface
import android.os.ServiceManager
import io.github.beakthoven.TrickyStoreOSS.AttestUtils
import io.github.beakthoven.TrickyStoreOSS.AttestUtils.ProbeStatus
import io.github.beakthoven.TrickyStoreOSS.KeyBoxUtils
import io.github.beakthoven.TrickyStoreOSS.NativeCertGen
import io.github.beakthoven.TrickyStoreOSS.interceptors.SecurityLevelInterceptor
import io.github.beakthoven.TrickyStoreOSS.logging.Logger
import java.io.File
import java.nio.ByteBuffer
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * State that the keystore path reads on every request, rebuilt from the three config files in
 * [CONFIG_PATH].
 *
 * The files' *contents* are parsed in the native crate (`native-certgen`'s `config` module): the
 * `target.txt` line grammar, the `security_patch.txt` block grammar and the `tee_status` report are
 * pure functions over text, unit-tested on the host, and they are the only place that knows which
 * spellings are accepted. This object owns everything that is not text processing:
 *
 *  - the file system side: watching the directory, reading the files, debouncing `keybox.xml`;
 *  - the binder side: resolving `IPackageManager` for the calling UID so [Mode.AUTO] can be
 *    resolved against the live TEE probe, and answering the per-UID permission lookups;
 *  - the publication side: swapping the immutable tables through `@Volatile` fields so a binder
 *    thread never observes a half-built snapshot.
 *
 * Each table is decoded from a length-prefixed blob; every count is checked against the bytes that
 * are actually left before it is used to size a collection, because the blob crosses JNI and a
 * truncated one must not be able to ask for a huge allocation.
 */
object PkgConfig {
    // volatile immutable map; swapped on reload so binder threads read a consistent snapshot
    @Volatile private var packageModes: Map<String, Mode> = emptyMap()

    enum class Mode {
        AUTO,
        LEAF_HACK,
        GENERATE,
    }

    // Must match `report::Level` in the native crate, which is the wire contract for the notes.
    private const val LEVEL_DEBUG = 1
    private const val LEVEL_WARN = 2
    private const val LEVEL_ERROR = 3

    /** The probe never produced a service error code; the native formatter writes `none` for it. */
    private const val NO_SERVICE_ERROR_CODE = -1

    private const val CONFIG_PATH = "/data/adb/tricky_store"
    private const val TARGET_FILE = "target.txt"
    private const val KEYBOX_FILE = "keybox.xml"
    private const val TEE_STATUS_FILE = "tee_status"
    private const val PATCHLEVEL_FILE = "security_patch.txt"
    private val root = File(CONFIG_PATH)

    private fun updateTargetPackages(f: File?) {
        val raw = runCatching {
            // A missing file is an empty target list, not an error: the daemon then rewrites
            // certificates for nobody, which is the documented meaning of an absent target.txt.
            val modes = parseTargets(NativeCertGen.nativeConfigParseTargets(f?.readText() ?: ""))
            packageModes = modes
            SecurityLevelInterceptor.invalidatePatchedResponses()
            Logger.i("update target packages: $modes")
        }
        raw.onFailure { Logger.e("failed to update target files", it) }
    }

    private data class KeyboxFileState(val exists: Boolean, val length: Long, val modified: Long)

    private fun keyboxFileState(file: File): KeyboxFileState =
        KeyboxFileState(file.exists(), file.length(), file.lastModified())

    private fun updateKeyBox(generation: Long? = null) {
        val raw = runCatching {
            val file = File(root, KEYBOX_FILE)
            val before = keyboxFileState(file)
            val contents = if (before.exists) file.readText() else null
            val current = keyboxFileState(file)
            val isCurrent = {
                val unchanged = runCatching {
                    (generation == null || generation == keyboxReloadGeneration.get()) &&
                        keyboxFileState(file) == current &&
                        (!current.exists || file.readText() == contents)
                }.getOrDefault(false)
                if (!unchanged && generation != null) keyboxReloadPending.set(true)
                unchanged
            }
            if (!isCurrent()) {
                if (generation != null) keyboxReloadPending.set(true)
                return@runCatching
            }
            if (KeyBoxUtils.readFromXml(contents, isCurrent)) {
                SecurityLevelInterceptor.invalidatePatchedResponses()
            } else {
                Logger.e("failed to update keybox; previous snapshot retained")
            }
        }
        raw.onFailure { Logger.e("failed to read keybox file") }
    }

    private val keyboxReloadExecutor = Executors.newSingleThreadExecutor { r ->
        Thread(r, "ts-keybox-reload").apply { isDaemon = true }
    }
    private val keyboxReloadPending = AtomicBoolean(false)
    private val keyboxReloadScheduled = AtomicBoolean(false)
    private val keyboxReloadGeneration = AtomicLong(0)

    private fun scheduleKeyboxReload() {
        keyboxReloadGeneration.incrementAndGet()
        keyboxReloadPending.set(true)
        if (!keyboxReloadScheduled.compareAndSet(false, true)) return
        keyboxReloadExecutor.execute {
            try {
                while (keyboxReloadPending.getAndSet(false)) {
                    val generation = keyboxReloadGeneration.get()
                    updateKeyBox(generation)
                }
            } finally {
                keyboxReloadScheduled.set(false)
                if (keyboxReloadPending.get()) scheduleKeyboxReload()
            }
        }
    }

    @Volatile private var probe: AttestUtils.ProbeResult? = null

    private fun storeTEEStatus(root: File) {
        val result = AttestUtils.probeResult
        probe = result
        val statusFile = File(root, TEE_STATUS_FILE)
        try {
            statusFile.writeText(
                NativeCertGen.nativeConfigFormatTeeStatus(
                    result.status.name,
                    result.failureCategory,
                    result.serviceErrorCode ?: NO_SERVICE_ERROR_CODE,
                ),
            )
            Logger.i(
                "TEE status written to $statusFile: status=${result.status}, " +
                    "category=${result.failureCategory ?: "none"}, code=${result.serviceErrorCode ?: "none"}",
            )
        } catch (e: Exception) {
            Logger.e("Failed to write TEE status: ${e.message}")
        }
    }

    private fun currentProbe(): AttestUtils.ProbeResult {
        probe?.let { return it }
        storeTEEStatus(root)
        return probe ?: AttestUtils.probeResult.also { probe = it }
    }

    object ConfigObserver : FileObserver(root, CLOSE_WRITE or DELETE or MOVED_FROM or MOVED_TO) {
        override fun onEvent(event: Int, path: String?) {
            path ?: return
            when (event) {
                CLOSE_WRITE, MOVED_TO, DELETE, MOVED_FROM -> Unit
                else -> return
            }
            when (path) {
                TARGET_FILE -> updateTargetPackages(File(root, path).takeIf { it.exists() })
                KEYBOX_FILE -> scheduleKeyboxReload()
                PATCHLEVEL_FILE -> updatePatchLevel(File(root, path).takeIf { it.exists() })
            }
        }
    }

    fun initialize() {
        root.mkdirs()
        val scope = File(root, TARGET_FILE)
        if (scope.exists()) {
            updateTargetPackages(scope)
        } else {
            Logger.e("target.txt file not found, please put it to $scope !")
        }
        val keybox = File(root, KEYBOX_FILE)
        if (!keybox.exists()) Logger.e("keybox file not found, please put it to $keybox !")
        updateKeyBox()
        val patchFile = File(root, PATCHLEVEL_FILE)
        updatePatchLevel(if (patchFile.exists()) patchFile else null)
        ConfigObserver.startWatching()
    }

    private var iPm: IPackageManager? = null
    private val packageManagerDeathRecipient =
        object : IBinder.DeathRecipient {
            override fun binderDied() {
                (iPm as? IInterface)?.asBinder()?.unlinkToDeath(this, 0)
                iPm = null
            }
        }

    fun getPm(): IPackageManager? {
        if (iPm == null) {
            val binder = waitAndGetSystemService("package") ?: return null
            binder.linkToDeath(packageManagerDeathRecipient, 0)
            iPm = IPackageManager.Stub.asInterface(binder)
        }
        return iPm
    }

    private fun packagesForUid(uid: Int): Array<String>? =
        runCatching { getPm()?.getPackagesForUid(uid) }
            .onFailure { Logger.e("failed to get packages for uid=$uid", it) }
            .getOrNull()

    fun hasPermissionForUid(uid: Int, permission: String): Boolean {
        val userId = uid / 100000
        return packagesForUid(uid)?.any { pkg ->
            runCatching { getPm()?.checkPermission(permission, pkg, userId) == 0 }.getOrDefault(false)
        } ?: false
    }

    /** Both target-mode flags for a UID, resolved from a single PackageManager lookup. */
    data class TargetModes(val leafHack: Boolean, val generate: Boolean) {
        companion object {
            val NONE = TargetModes(false, false)
        }
    }

    fun targetModes(callingUid: Int): TargetModes {
        val raw = runCatching {
            val ps = packagesForUid(callingUid) ?: return@runCatching TargetModes.NONE
            val autoMode = when (currentProbe().status) {
                ProbeStatus.AVAILABLE -> Mode.LEAF_HACK
                ProbeStatus.FAILED -> Mode.GENERATE
                ProbeStatus.UNAVAILABLE -> null
            }
            var leafHack = false
            var generate = false
            for (pkg in ps) {
                when (val resolved = packageModes[pkg]?.let { if (it == Mode.AUTO) autoMode else it }) {
                    Mode.LEAF_HACK -> leafHack = true
                    Mode.GENERATE -> generate = true
                    else -> Unit
                }
            }
            TargetModes(leafHack, generate)
        }
        return raw.onFailure { Logger.e("failed to get packages", it) }.getOrDefault(TargetModes.NONE)
    }

    fun needHack(callingUid: Int): Boolean = targetModes(callingUid).leafHack

    @Volatile private var globalPatchLevel: CustomPatchLevel? = null

    @Volatile private var packagePatchLevels: Map<String, CustomPatchLevel> = emptyMap()

    val globalPatchLevelConfig: CustomPatchLevel?
        get() = globalPatchLevel

    fun packagePatchLevelForUid(uid: Int): CustomPatchLevel? {
        val packages = packagesForUid(uid) ?: return null
        return packages.firstNotNullOfOrNull { packagePatchLevels[it] }
    }

    fun updatePatchLevel(f: File?) {
        val raw = runCatching {
            if (f == null || !f.exists()) {
                globalPatchLevel = null
                packagePatchLevels = emptyMap()
                SecurityLevelInterceptor.invalidatePatchedResponses()
                return@runCatching
            }
            val parsed = parsePatchLevels(NativeCertGen.nativeConfigParsePatchLevels(f.readText()))
            globalPatchLevel = parsed[""]
            packagePatchLevels = parsed.filterKeys { it.isNotEmpty() }
            SecurityLevelInterceptor.invalidatePatchedResponses()
            Logger.i(
                "loaded patch levels: global=${globalPatchLevel != null}, ${packagePatchLevels.size} package overrides"
            )
        }
        raw.onFailure { Logger.e("failed to update patch level", it) }
    }

    /**
     * Decodes the `target.txt` blob: `[notes][u32 count]{ [text package][u8 mode] }`.
     *
     * The table is filled in file order, so a later line for the same package replaces an earlier
     * one — the last spelling wins, exactly as it did when the file was read line by line.
     */
    private fun parseTargets(blob: ByteArray): Map<String, Mode> {
        val buffer = ByteBuffer.wrap(blob)
        replayNotes(buffer)
        require(buffer.remaining() >= 4) { "truncated native target.txt blob" }
        val count = buffer.int
        // Each entry costs at least five bytes: a four-byte length prefix plus the mode byte.
        require(count in 0..(buffer.remaining() / 5)) {
            "malformed native target.txt entry count: $count"
        }
        val modes = LinkedHashMap<String, Mode>(count)
        repeat(count) {
            val packageName = buffer.readLengthPrefixed().toString(Charsets.UTF_8)
            require(buffer.remaining() >= 1) { "truncated native target.txt mode" }
            val mode = when (val code = buffer.get().toInt() and 0xFF) {
                0 -> Mode.AUTO
                1 -> Mode.LEAF_HACK
                2 -> Mode.GENERATE
                else -> throw IllegalArgumentException("unknown native target mode byte: $code")
            }
            modes[packageName] = mode
        }
        require(!buffer.hasRemaining()) { "trailing bytes in native target.txt blob" }
        return modes
    }

    /**
     * Decodes the `security_patch.txt` blob:
     * `[notes][u32 count]{ [text context][opt text system][opt text vendor][opt text boot][opt text all] }`.
     *
     * The empty context name is the global block; the caller splits it off the table.
     */
    private fun parsePatchLevels(blob: ByteArray): LinkedHashMap<String, CustomPatchLevel> {
        val buffer = ByteBuffer.wrap(blob)
        replayNotes(buffer)
        require(buffer.remaining() >= 4) { "truncated native patch level blob" }
        val count = buffer.int
        // Each block costs at least eight bytes: a four-byte context length plus four presence bytes.
        require(count in 0..(buffer.remaining() / 8)) {
            "malformed native patch level block count: $count"
        }
        val parsed = LinkedHashMap<String, CustomPatchLevel>(count)
        repeat(count) {
            val context = buffer.readLengthPrefixed().toString(Charsets.UTF_8)
            parsed[context] =
                CustomPatchLevel(
                    system = buffer.readOptionalText(),
                    vendor = buffer.readOptionalText(),
                    boot = buffer.readOptionalText(),
                    all = buffer.readOptionalText(),
                )
        }
        require(!buffer.hasRemaining()) { "trailing bytes in native patch level blob" }
        return parsed
    }

    /**
     * Replays the leading notes section — `[u32 count]{ [u8 level][u32 len][message] }` — through
     * [Logger], then leaves the buffer positioned at the payload. The parsers live on the native side
     * and have no log sink, so they hand their warnings back instead of printing them.
     */
    private fun replayNotes(buffer: ByteBuffer) {
        require(buffer.remaining() >= 4) { "truncated native notes section" }
        val count = buffer.int
        // Each note costs at least five bytes: one level plus a four-byte length prefix.
        require(count in 0..(buffer.remaining() / 5)) { "malformed native note count: $count" }
        repeat(count) {
            require(buffer.remaining() >= 5) { "truncated native note" }
            val level = buffer.get().toInt() and 0xFF
            val message = buffer.readLengthPrefixed().toString(Charsets.UTF_8)
            when (level) {
                LEVEL_DEBUG -> Logger.d(message)
                LEVEL_WARN -> Logger.w(message)
                LEVEL_ERROR -> Logger.e(message)
                else -> Logger.i(message)
            }
        }
    }

    private fun ByteBuffer.readLengthPrefixed(): ByteArray {
        require(remaining() >= 4) { "truncated native config field" }
        val length = int
        require(length in 0..remaining()) { "malformed native config blob" }
        val bytes = ByteArray(length)
        get(bytes)
        return bytes
    }

    private fun ByteBuffer.readOptionalText(): String? {
        require(remaining() >= 1) { "truncated native optional text presence" }
        return if (get().toInt() == 0) null else readLengthPrefixed().toString(Charsets.UTF_8)
    }

    private fun waitAndGetSystemService(name: String): IBinder? {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            return ServiceManager.waitForService(name)
        }

        var tryCount = 0
        while (tryCount++ < 70) {
            val service = ServiceManager.getService(name)
            if (service != null) {
                Logger.d("Got $name service after $tryCount tries")
                return service
            }
            Thread.sleep(500)
        }

        Logger.e("Failed to get $name service")
        return null
    }
}

data class CustomPatchLevel(
    val system: String? = null,
    val vendor: String? = null,
    val boot: String? = null,
    val all: String? = null,
)