/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import com.android.build.api.artifact.SingleArtifact
import com.android.build.api.variant.ApplicationVariant
import java.util.Properties
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

plugins { alias(libs.plugins.android.application) }

val gitCommitCount =
    providers
        .exec {
            commandLine("git", "rev-list", "HEAD", "--count")
            workingDir = rootDir
        }
        .standardOutput
        .asText
        .map { it.trim().toInt() }
        .get()

val gitCommitHash =
    providers
        .exec {
            commandLine("git", "rev-parse", "--verify", "--short", "HEAD")
            workingDir = rootDir
        }
        .standardOutput
        .asText
        .map { it.trim() }
        .get()

val verName = "v3.1.0"

val androidNdkVersion = "29.0.14206865"
val androidMinSdk = 29

android {
    namespace = "io.github.beakthoven.TrickyStoreOSS"
    compileSdk = 37
    ndkVersion = androidNdkVersion

    defaultConfig {
        applicationId = "io.github.beakthoven.TrickyStoreOSS"
        minSdk = androidMinSdk
        targetSdk = 37
        versionCode = gitCommitCount
        versionName = verName

        // The module ships a single ABI: arm64-v8a covers essentially all modern devices and keeps
        // the packaged native libraries (libcertgen/libinject/libTrickyStoreOSS) to one copy.
        ndk { abiFilters += "arm64-v8a" }

        externalNativeBuild {
            cmake {
                arguments += "-DANDROID_STL=none"
                arguments += "-DCMAKE_BUILD_TYPE=Release"
                arguments += "-DANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES=ON"
                arguments += "-DANDROID_ALLOW_UNDEFINED_SYMBOLS=ON"
                arguments += "-DCMAKE_CXX_STANDARD=23"
                arguments += "-DCMAKE_C_STANDARD=23"
                arguments += "-DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON"
                // Link-time dead stripping. LTO already removes what no caller in the same module
                // reaches, but the stub archives (`utils`, `binder`, `PLTI`) and the Rust
                // staticlib are only trimmed at link time. `--icf=safe` (not `all`) folds
                // identical functions whose address is never taken — this codebase compares
                // function pointers in its hook tables, so `all` would be a correctness gamble.
                // `--as-needed` drops the DT_NEEDED entries nothing calls, which also removes the
                // matching relocation blocks; `--exclude-libs,ALL` re-hides the archive symbols a
                // static link would otherwise promote into `.dynsym`.
                arguments +=
                    "-DCMAKE_SHARED_LINKER_FLAGS=" +
                        "-Wl,--gc-sections -Wl,--icf=safe -Wl,--as-needed -Wl,--exclude-libs,ALL"
                arguments +=
                    "-DCMAKE_EXE_LINKER_FLAGS=" +
                        "-Wl,--gc-sections -Wl,--icf=safe -Wl,--as-needed -Wl,--exclude-libs,ALL"

                cppFlags += "-std=c++23"
                // Pin the optimisation level instead of leaning on whatever `CMAKE_BUILD_TYPE=Release`
                // happens to expand to in the NDK in use. -O2 is what this code wants: the hot paths
                // are Binder transactions, ELF parsing and the ptrace scaffolding, none of which
                // benefit from -O3's extra inlining (it mostly costs I-cache here) and all of which
                // lose measurably under -Oz. A duplicate -O2 alongside the build type's own is
                // harmless, and the last one on the command line wins if they ever disagree.
                cppFlags += "-O2"
                cppFlags += "-fno-exceptions"
                cppFlags += "-fno-rtti"
                // Nothing on this side unwinds: exceptions are off, every failure path returns an
                // error code, and the injector talks to the target through ptrace. Without these
                // flags clang still emits a call-site table per function, which is what made
                // `.eh_frame` 34 KB of the 348 KB `inject` binary. `-ffunction-sections` /
                // `-fdata-sections` are what give `--gc-sections` something to drop.
                cppFlags += "-ffunction-sections"
                cppFlags += "-fdata-sections"
                cppFlags += "-fno-unwind-tables"
                cppFlags += "-fno-asynchronous-unwind-tables"
                cppFlags += "-fvisibility=hidden"
                cppFlags += "-fvisibility-inlines-hidden"
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_24
        targetCompatibility = JavaVersion.VERSION_24
    }
    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.28.0+"
        }
    }
    buildFeatures { prefab = true }
    packaging { resources { pickFirsts += setOf("META-INF/LICENSE.md", "META-INF/NOTICE.md", "META-INF/INDEX.LIST") } }

    testOptions {
        // Public framework APIs (android.util.Log, …) must return defaults under the mockable
        // android.jar instead of aborting tests with "not mocked". Hidden APIs come from
        // `project(":stub")`, whose statics throw — Logger guards those itself.
        unitTests.isReturnDefaultValues = true
    }
}

dependencies {
    compileOnly(project(":stub"))
    compileOnly(libs.annotation)
    implementation(libs.org.lsposed.libcxx.libcxx)

    // Unit tests run against the framework stubs (keymint Tag/Algorithm/KeyParameterValue, …)
    // rather than the mockable android.jar, which only carries the public SDK surface. The
    // stub's union statics all throw, so KeyParameterValue instances are Mockito mocks.
    testImplementation(project(":stub"))
    testImplementation(libs.junit)
    testImplementation(libs.mockito)
}

// --- Rust cross-compilation plumbing ---
//
// Three crates are cross-built for arm64-v8a:
//
//   * `native-certgen` — cdylib, lands in jniLibs and is merged into the APK;
//   * `native-inject`  — staticlib linked into `libinject.so`, plus the cdylib the injector
//                        dlopen()s into the target process;
//   * `native-daemon`  — the control-plane binary that replaced `Main.kt`.
//
// Two things used to break the build here, both only visible on a machine where the NDK toolchain
// is not already on `PATH`:
//
//   * `ndkForCargo` silently produced an empty toolchain prefix when the NDK failed to resolve
//     (`listOfNotNull` drops nulls), so `cargo` still ran and `ring`'s build script reported
//     `ToolNotFound: failed to find tool "aarch64-linux-android-clang"` from inside a dependency.
//     The compiler is now handed over by absolute path through `CC_*`/`CXX_*`/`AR_*`/`RANLIB_*`
//     and `CARGO_TARGET_*_LINKER` (which outranks `.cargo/config.toml`), and an unusable NDK fails
//     the task with a message that lists every path that was tried.
//   * `lsplt-rs` never guesses an NDK on `target_os = "android"`: its build script calls
//     `resolve_ndk_root()`, which reads `ANDROID_NDK`/`ANDROID_NDK_HOME`/`ANDROID_NDK_ROOT`/
//     `NDK_HOME` and panics when all four are absent. All four are exported now, together with
//     `LIBCLANG_PATH` for the bindgen step it runs before the C++ part.
//
// Resolution happens inside the tasks rather than at configuration time because on a fresh CI
// runner the NDK only exists after the workflow (or AGP) has installed it.
//
// The helpers live in a static nested object, not in the script itself: task actions are
// serialized by the configuration cache and must not capture the script instance, which calling
// script-level functions or reading script-level vals would do. Task bodies snapshot the values
// they need into locals (Files/Strings/Booleans — all serializable) and call into this object;
// `object` members resolve through a static reference, so nothing captures the script.
private object Toolchains {
    /** Locates the NDK every `cargo` invocation below must use. Called from task actions only. */
    fun resolveAndroidNdk(sdkDir: File?, ndkVersion: String, minSdk: Int): File {
        val sdkNdkRoot = sdkDir?.resolve("ndk")
        // AGP downloads the revision named by `ndkVersion`, but runner images also ship a few others
        // side by side. Any installed revision that carries the LLVM toolchain beats failing the build,
        // so they are appended newest-first after the exact match.
        val installedRevisions =
            sdkNdkRoot
                ?.listFiles()
                ?.filter { it.isDirectory }
                ?.sortedByDescending { it.name }
                .orEmpty()
        val candidates =
            (
                listOfNotNull(
                    System.getenv("ANDROID_NDK_HOME"),
                    System.getenv("ANDROID_NDK_ROOT"),
                    System.getenv("ANDROID_NDK"),
                    System.getenv("NDK_HOME"),
                    sdkNdkRoot?.resolve(ndkVersion)?.absolutePath,
                ).map { File(it) } + installedRevisions
            ).distinct()
        return candidates.firstOrNull { it.resolve("toolchains/llvm/prebuilt").isDirectory }
            ?: throw GradleException(
                "No usable Android NDK $ndkVersion found; the Rust cross-builds need " +
                    "aarch64-linux-android$minSdk-clang. Looked at: " +
                    candidates.joinToString { it.absolutePath } +
                    ". Set ANDROID_NDK_HOME or install it with " +
                    "`sdkmanager \"ndk;$ndkVersion\"`.",
            )
    }

    /**
     * Everything a cross-build needs, keyed by environment variable name.
     *
     * `PATH` is still extended because `native-inject/.cargo/config.toml` names the linker without a
     * directory, but nothing depends on it any more: the absolute paths below are what `cc-rs` and
     * `rustc` actually consume.
     */
    fun rustAndroidEnvironment(ndk: File, minSdk: Int): Map<String, String> {
        val prebuilt =
            ndk.resolve("toolchains/llvm/prebuilt").listFiles()?.firstOrNull { it.isDirectory }
                ?: throw GradleException(
                    "The NDK at ${ndk.absolutePath} has no toolchains/llvm/prebuilt/<host> directory.",
                )
        val bin = prebuilt.resolve("bin")
        // The API-versioned wrappers bake in `--target` and `--sysroot`, so the unversioned
        // `<triple>-clang` that `cc-rs` probes for is never needed.
        val clang = bin.resolve("aarch64-linux-android$minSdk-clang")
        val clangxx = bin.resolve("${clang.name}++")
        if (!clang.isFile || !clangxx.isFile) {
            val clangBinaries =
                bin.listFiles()
                    ?.filter { it.isFile && it.name.contains("clang") }
                    ?.map { it.name }
                    ?.sorted()
                    ?.take(12)
                    ?.joinToString()
                    ?.takeIf { it.isNotEmpty() }
                    ?: "none"
            throw GradleException(
                "Missing ${clang.absolutePath}. The NDK at ${ndk.absolutePath} is not usable " +
                    "(clang binaries present: $clangBinaries).",
            )
        }
        // bindgen (run by `lsplt-sys` before its C++ step) loads libclang from the NDK.
        val libclangDir =
            listOf(prebuilt.resolve("lib"), prebuilt.resolve("lib64"))
                .firstOrNull { it.resolve("libclang.so").isFile || it.resolve("libclang.dylib").isFile }
        val env =
            mutableMapOf(
                "ANDROID_NDK_HOME" to ndk.absolutePath,
                "ANDROID_NDK_ROOT" to ndk.absolutePath,
                "ANDROID_NDK" to ndk.absolutePath,
                "NDK_HOME" to ndk.absolutePath,
                "PATH" to
                    listOfNotNull(
                            bin.absolutePath,
                            "${System.getProperty("user.home")}/.cargo/bin",
                            System.getenv("PATH"),
                        )
                        .joinToString(":"),
                "CC_aarch64_linux_android" to clang.absolutePath,
                "CXX_aarch64_linux_android" to clangxx.absolutePath,
                "AR_aarch64_linux_android" to bin.resolve("llvm-ar").absolutePath,
                "RANLIB_aarch64_linux_android" to bin.resolve("llvm-ranlib").absolutePath,
                "CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER" to clang.absolutePath,
            )
        libclangDir?.let { env["LIBCLANG_PATH"] = it.absolutePath }
        return env
    }

    /**
     * Drops the DWARF unwind tables (`.eh_frame` / `.eh_frame_hdr`) from a shipped ELF.
     *
     * Every native artifact this module ships is built without exceptions and with `panic = "abort"`,
     * so no frame is ever unwound on purpose. The tables are still emitted for two reasons no flag set
     * in this file can reach: `libcertgen`/`inject` link the precompiled Rust std, which carries
     * `.eh_frame` for all of its own code, and clang keeps a call-site table per function wherever a
     * landing pad exists. Post-link removal is the only place that catches all of them at once.
     *
     * `.eh_frame_hdr` has to go with `.eh_frame` — it is a sorted binary index into it. The loader
     * reads neither: `dlopen` needs `.dynamic`, `.dynsym`/`.dynstr`, the relocation tables and the
     * program headers, all of which stay untouched. The only real loss is stack unwinding for these
     * files in a crash report (frames show up as `<unknown>`).
     */
    fun stripUnwindTables(ndk: File, artifact: File) {
        val objcopy =
            ndk.resolve("toolchains/llvm/prebuilt")
                .listFiles()
                ?.firstOrNull { it.isDirectory }
                ?.resolve("bin/llvm-objcopy")
        if (objcopy == null || !objcopy.isFile) {
            throw GradleException("No llvm-objcopy in the NDK at ${ndk.absolutePath}.")
        }
        val before = artifact.length()
        val process =
            ProcessBuilder(
                    objcopy.absolutePath,
                    "--remove-section=.eh_frame",
                    "--remove-section=.eh_frame_hdr",
                    // `.comment` is a plain compiler-version string ("clang version 19.x …"); it
                    // identifies the exact toolchain that produced the artifact and serves no
                    // runtime purpose. The GNU build-id stays: it is a content hash that helps
                    // symbolication and does not fingerprint the build environment.
                    "--remove-section=.comment",
                    artifact.absolutePath,
                )
                .redirectErrorStream(true)
                .start()
        val output = process.inputStream.bufferedReader().use { it.readText() }.trim()
        val exit = process.waitFor()
        if (exit != 0) {
            throw GradleException("llvm-objcopy failed on ${artifact.name} (exit $exit): $output")
        }
        val after = artifact.length()
        println(
            "shrink: ${artifact.name} $before -> $after bytes " +
                "(${before - after} bytes of unwind tables dropped)",
        )
    }

    // `llvm-objcopy --remove-section` leaves the removed bytes behind as a zero hole inside the
    // preceding PT_LOAD, so files hardly shrink on disk even though whole tables are gone.
    // elf_compact.py slides the following segments down over that hole (respecting each segment's
    // p_align) and rewrites the headers. It verifies its own output and is a no-op when the hole is
    // too small to be removed without breaking the loader's offset/vaddr congruence.
    fun resolvePython(): String? {
        for (candidate in listOf("python3", "python")) {
            try {
                val process =
                    ProcessBuilder(candidate, "-c", "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)")
                        .redirectErrorStream(true)
                        .start()
                val ok = process.waitFor() == 0
                process.inputStream.close()
                if (ok) return candidate
            } catch (e: Exception) {
                // Not installed under this name; try the next candidate.
            }
        }
        return null
    }

    fun compactElf(python: String, script: File, artifact: File) {
        val before = artifact.length()
        val process =
            ProcessBuilder(python, script.absolutePath, artifact.absolutePath)
                .directory(script.parentFile.parentFile)
                .redirectErrorStream(true)
                .start()
        val output = process.inputStream.bufferedReader().use { it.readText() }.trim()
        val exit = process.waitFor()
        if (exit != 0) {
            throw GradleException("elf_compact.py failed on ${artifact.name} (exit $exit): $output")
        }
        output.lineSequence().filter { it.isNotBlank() }.forEach { println("compact: $it") }
        val after = artifact.length()
        println("compact: ${artifact.name} $before -> $after bytes (${before - after} bytes reclaimed)")
    }
}

val androidSdkDir: File? =
    run {
        // CI exports ANDROID_SDK_ROOT/ANDROID_HOME, while a developer machine usually only has
        // `sdk.dir` in `local.properties` (git-ignored). Both have to be honoured here: the Rust
        // tasks run outside AGP and therefore cannot ask it where the SDK is.
        val fromEnv = System.getenv("ANDROID_SDK_ROOT") ?: System.getenv("ANDROID_HOME")
        val fromLocalProperties =
            rootProject.file("local.properties").takeIf { it.isFile }?.let { propsFile ->
                Properties()
                    .apply { propsFile.inputStream().use { load(it) } }
                    .getProperty("sdk.dir")
            }
        (fromEnv ?: fromLocalProperties)?.let { file(it) }
    }

// --- Native cert generation (Rust cdylib) ---
// Builds libcertgen.so for arm64-v8a straight into app/src/main/jniLibs, which AGP merges into
// the APK; the module packaging below then extracts it from the APK.
//
// `-Z build-std` rebuilds core and std from source, which is the only way to actually drop the
// formatting machinery behind `panic!` rather than just the unwinder: the CI probe measured
// 318 KB off libcertgen.so (.text 640 KB -> 419 KB) and zero `panicked at` strings left behind.
// It stays opt-in because it needs a nightly toolchain, i.e. `TSTORE_BUILD_STD=1 ./gradlew ...`.
//
// Three things have to line up for it, and the old invocation satisfies none of them:
//   * immediate abort is a real panic strategy in current nightlies, not a
//     `-Z build-std-features` switch; it is spelled `panic = "immediate-abort"` in the profile;
//   * selecting it requires `cargo-features = ["panic-immediate-abort"]` at the very top of the
//     manifest, and stable Cargo rejects that key outright, so the manifest is patched only for
//     the duration of the build and restored afterwards instead of being committed that way;
//   * native-certgen/rust-toolchain.toml pins stable and a toolchain file outranks the default
//     toolchain, so RUSTUP_TOOLCHAIN has to be forced for `-Z` to be accepted at all.
val certgenCrateDir = rootProject.projectDir.resolve("native-certgen")
val certgenManifest = certgenCrateDir.resolve("Cargo.toml")
val certgenManifestStash = certgenCrateDir.resolve("Cargo.toml.build-std-stash")

fun buildStdRequested() = System.getenv("TSTORE_BUILD_STD") == "1"

// Pinned nightly for the `-Z build-std` rebuild. `panic = "immediate-abort"` only resolves on
// recent nightlies, so an unpinned `nightly` drifting under us would silently change — or break —
// the shipped library. Keep in sync with the `rustup toolchain install` steps in
// .github/workflows/{build,release,build-std-probe}.yml; override with TSTORE_NIGHTLY to try a
// different toolchain locally.
val buildStdNightly = System.getenv("TSTORE_NIGHTLY") ?: "nightly-2026-10-23"

// The manifest rewrite inside buildRustCertgen is a doFirst/doLast pair, and Gradle skips doLast
// when the task fails — a failed build-std run would leave Cargo.toml carrying `cargo-features`
// and `panic = "immediate-abort"`, which the pinned stable toolchain then refuses to parse. The
// restore therefore lives in a *finalizer* task: finalizers run whether the build succeeds,
// fails, or is skipped. `onlyIf` keeps it a no-op whenever no stash exists.
val restoreCertgenManifest =
    tasks.register("restoreCertgenManifest") {
        // Locals only: task actions are serialized by the configuration cache and must not
        // capture the script instance through script-level vals.
        val stash = certgenManifestStash
        val manifest = certgenManifest
        group = "TrickyStoreOSS Native Build"
        description = "Restores native-certgen/Cargo.toml from the build-std stash, even after a failed build"
        onlyIf { stash.exists() }
        doLast {
            stash.copyTo(manifest, overwrite = true)
            stash.delete()
            println("Restored ${manifest.name} from build-std stash")
        }
    }

fun buildCertgenCommandLine(): List<String> {
    val args =
        mutableListOf(
            "cargo",
            "ndk",
            "-t",
            "arm64-v8a",
            "-o",
            rootProject.projectDir.resolve("app/src/main/jniLibs").absolutePath,
            "build",
        )
    if (buildStdRequested()) {
        args += listOf("-Z", "build-std=std,panic_abort")
    }
    args += "--release"
    return args
}

val buildRustCertgen =
    tasks.register<Exec>("buildRustCertgen") {
        group = "TrickyStoreOSS Native Build"
        description = "Builds libcertgen.so via cargo-ndk for arm64-v8a."

        // Run the restore after this task no matter how it ended; onlyIf inside keeps it free
        // when no stash exists (e.g. build-std not requested).
        finalizedBy(restoreCertgenManifest)

        workingDir = rootProject.projectDir.resolve("native-certgen")

        commandLine(buildCertgenCommandLine())

        inputs.dir(rootProject.projectDir.resolve("native-certgen/src"))
        inputs.file(rootProject.projectDir.resolve("native-certgen/Cargo.toml"))
        inputs.file(rootProject.projectDir.resolve("native-certgen/Cargo.lock"))
        outputs.dir(rootProject.projectDir.resolve("app/src/main/jniLibs"))

        // Snapshots for the action below: task actions are serialized by the configuration cache,
        // so they may only capture serializable locals — reading script members from inside the
        // action would capture the script instance. Snapshotting happens here, at configuration
        // time; the toolchain lookups still run through the static Toolchains object at execution.
        val sdkDir = androidSdkDir
        val ndkVersion = androidNdkVersion
        val minSdk = androidMinSdk
        val certgenStash = certgenManifestStash
        val certgenManifest = certgenManifest
        val buildStdRequested = buildStdRequested()
        val buildStdNightlyPinned = buildStdNightly

        doFirst {
            // The Kotlin DSL renders `doFirst`'s Action as a receiver lambda, so `this` is the
            // task at execution time — no configuration receiver is captured. A cast keeps the
            // Exec-only surface (environment) reachable from the plain Task receiver.
            val exec = this as Exec
            Toolchains.rustAndroidEnvironment(Toolchains.resolveAndroidNdk(sdkDir, ndkVersion, minSdk), minSdk)
                .forEach { (key, value) -> exec.environment(key, value) }
            // Self-heal first: a build-std run that died hard (killed daemon, dropped CI job)
            // can outlive its finalizer and leave a stale stash — start from a clean manifest
            // so a normal stable build never sees the patched file.
            if (certgenStash.exists()) {
                certgenStash.copyTo(certgenManifest, overwrite = true)
                certgenStash.delete()
            }
            if (buildStdRequested) {
                certgenManifest.copyTo(certgenStash, overwrite = true)
                certgenManifest.writeText(
                    "cargo-features = [\"panic-immediate-abort\"]\n\n" +
                        certgenStash.readText().replaceFirst(
                            Regex("(?m)^panic = \"abort\"$"),
                            "panic = \"immediate-abort\"",
                        ),
                )
                exec.environment("RUSTUP_TOOLCHAIN", buildStdNightlyPinned)
            }
        }
    }

// --- Native injection helpers (Rust staticlib + cdylib) ---
// `native-inject` owns the pure-logic half of the injector: /proc/<pid>/maps parsing, wait-status
// and PTRACE_EVENT rendering, magic-string generation and the SELinux knob writers. It produces
// `librustinject.a` (linked into `libinject.so` by CMake, so nothing extra lands in the APK) and
// `librustinject.so` (the payload the injector dlopen()s into keystore2/system_server).
val rustInjectCrateDir = rootProject.projectDir.resolve("native-inject")
// The staging directory CMake looks at. Resolved eagerly at configuration time so the task body
// only ever sees plain strings — build-script objects cannot be serialized by the configuration
// cache, so nothing here may be deferred into a task action.
val rustInjectAbiDir = layout.buildDirectory.dir("rust/inject/arm64-v8a").get().asFile
val rustInjectReleaseDir = rustInjectCrateDir.resolve("target/aarch64-linux-android/release")
// cargo-ndk only copies cdylib artifacts, so the archive is cross-built with plain cargo (linker
// from .cargo/config.toml) and staged with `cp` in the very same shell command instead of a doLast
// action. Both artifacts come out of that one `cargo build`: the crate is cdylib + staticlib.
val buildRustInject =
    tasks.register<Exec>("buildRustInject") {
        group = "TrickyStoreOSS Native Build"
        description = "Builds librustinject.a/.so for arm64-v8a (the archive is linked into libinject.so)."

        workingDir = rustInjectCrateDir
        commandLine(
            "sh",
            "-c",
            "cargo build --release --locked --target aarch64-linux-android" +
                " && mkdir -p '${rustInjectAbiDir.absolutePath}'" +
                " && cp '${rustInjectReleaseDir.resolve("librustinject.a").absolutePath}'" +
                " '${rustInjectAbiDir.absolutePath}/librustinject.a'" +
                " && cp '${rustInjectReleaseDir.resolve("librustinject.so").absolutePath}'" +
                " '${rustInjectAbiDir.absolutePath}/librustinject.so'",
        )
        inputs.dir(rustInjectCrateDir.resolve("src"))
        inputs.file(rustInjectCrateDir.resolve("Cargo.toml"))
        inputs.file(rustInjectCrateDir.resolve("Cargo.lock"))
        outputs.dir(rustInjectAbiDir)

        // Snapshots for the action below — see buildRustCertgen: actions may only capture
        // serializable locals, never script members.
        val sdkDir = androidSdkDir
        val ndkVersion = androidNdkVersion
        val minSdk = androidMinSdk

        doFirst {
            // Receiver form — see buildRustCertgen: `this` is the task at execution time.
            val exec = this as Exec
            Toolchains.rustAndroidEnvironment(Toolchains.resolveAndroidNdk(sdkDir, ndkVersion, minSdk), minSdk)
                .forEach { (key, value) -> exec.environment(key, value) }
        }
    }

// --- Native daemon (the JVM-free control plane) ---
// `tricky-daemon` replaces `app_process ... MainKt`: it resolves the boot inputs, applies the
// property spoofing and supervises the interceptor. It links `certgen` statically, so it drags in
// `ring` and therefore needs the same toolchain every other Rust task gets.
val rustDaemonCrateDir = rootProject.projectDir.resolve("native-daemon")
val rustDaemonAbiDir = layout.buildDirectory.dir("rust/daemon/arm64-v8a").get().asFile
val rustDaemonBinary = rustDaemonCrateDir.resolve("target/aarch64-linux-android/release/tricky-daemon")
val buildRustDaemon =
    tasks.register<Exec>("buildRustDaemon") {
        group = "TrickyStoreOSS Native Build"
        description = "Builds the tricky-daemon binary for arm64-v8a."

        workingDir = rustDaemonCrateDir
        commandLine(
            "sh",
            "-c",
            "cargo build --release --locked --target aarch64-linux-android" +
                " && mkdir -p '${rustDaemonAbiDir.absolutePath}'" +
                " && cp '${rustDaemonBinary.absolutePath}' '${rustDaemonAbiDir.absolutePath}/tricky-daemon'",
        )
        inputs.dir(rustDaemonCrateDir.resolve("src"))
        inputs.file(rustDaemonCrateDir.resolve("Cargo.toml"))
        inputs.file(rustDaemonCrateDir.resolve("Cargo.lock"))
        outputs.dir(rustDaemonAbiDir)

        // Snapshots for the action below — see buildRustCertgen: actions may only capture
        // serializable locals, never script members.
        val sdkDir = androidSdkDir
        val ndkVersion = androidNdkVersion
        val minSdk = androidMinSdk

        doFirst {
            // Receiver form — see buildRustCertgen: `this` is the task at execution time.
            val exec = this as Exec
            Toolchains.rustAndroidEnvironment(Toolchains.resolveAndroidNdk(sdkDir, ndkVersion, minSdk), minSdk)
                .forEach { (key, value) -> exec.environment(key, value) }
        }
    }

// CMakeLists.txt consumes the archive by path, so it has to exist before every configure step.
tasks.configureEach {
    if (name.startsWith("configureCMake") || name.startsWith("buildCMake")) {
        dependsOn(buildRustInject)
    }
}
// AGP auto-detects jniLibs/ as an input to mergeJniLibFolders — make it depend on the Rust build.
tasks.configureEach {
    if (name.startsWith("merge") && name.endsWith("JniLibFolders")) {
        dependsOn(buildRustCertgen)
    }
}

androidComponents {
    onVariants { variant: ApplicationVariant ->
        val variantName = variant.name
        val capitalized = variantName.replaceFirstChar { it.uppercase() }
        val sourceDir = project.rootDir.resolve("module")
        val tempModuleDir = project.layout.buildDirectory.dir("tmp/module-${variantName}")
        val apkFile = variant.artifacts.get(SingleArtifact.APK)

        tasks.register("prepareModuleFiles${capitalized}") {
            dependsOn(buildRustCertgen, buildRustInject, buildRustDaemon)
            // Locals only: the configuration cache serializes doLast, so it may not capture the
            // script instance through script-level vals or functions. Everything that must be
            // computed here is snapshotted up front; the toolchain helpers run through the static
            // Toolchains object and still resolve at execution time.
            val commitCount = gitCommitCount
            val commitHash = gitCommitHash
            val versionName = verName
            val sourceDir = project.rootDir.resolve("module")
            val toolsDir = project.rootDir.resolve("tools")
            val sdkDir = androidSdkDir
            val ndkVersion = androidNdkVersion
            val minSdk = androidMinSdk
            inputs.dir(sourceDir)
            inputs.dir(apkFile)
            inputs.file(rustDaemonBinary)
            inputs.file(rustInjectAbiDir.resolve("librustinject.so"))
            outputs.dir(tempModuleDir)

            doLast {
                val tempDir = tempModuleDir.get().asFile
                tempDir.deleteRecursively()
                tempDir.mkdirs()

                sourceDir.walkTopDown()
                    .filter { file ->
                        file.isFile &&
                            file.name !in setOf("module.prop", "service.apk", "payload.bin") &&
                            !file.relativeTo(sourceDir).invariantSeparatorsPath.startsWith("lib/")
                    }
                    .forEach { file ->
                        val destination = tempDir.resolve(file.relativeTo(sourceDir))
                        destination.parentFile.mkdirs()
                        file.copyTo(destination, overwrite = true)
                    }

                tempDir.resolve("module.prop").writeText(
                    sourceDir.resolve("module.prop")
                        .readText()
                        .replace("REPLACEMEVERCODE", commitCount.toString())
                        .replace("REPLACEMEVER", "$versionName ($commitCount-$commitHash-$variantName)"),
                )

                // The module needs the .so files unpacked, so they are pulled out of the APK and
                // installed loose. The JVM control plane itself ships as `payload.bin`, a zip whose
                // root holds `classes.dex`: `module/daemon` hands it to `app_process` as the
                // classpath and ART reads `classes*.dex` out of any zip whatever the file is named,
                // so the module carries neither a bare `classes.dex` nor a `service.apk`.
                val apks =
                    apkFile
                        .get()
                        .asFile
                        .walkTopDown()
                        .filter { it.isFile && it.extension == "apk" }
                        .sortedBy { it.invariantSeparatorsPath }
                        .toList()
                check(apks.size == 1) { "Expected exactly one APK output for $variantName, found ${apks.size}" }
                val apk = apks.single()

                ZipFile(apk).use { zip ->
                    val entries = zip.entries()
                    while (entries.hasMoreElements()) {
                        val entry = entries.nextElement()
                        if (!entry.isDirectory && entry.name.startsWith("lib/") &&
                            entry.name.substringAfterLast('/') in
                                setOf("libinject.so", "libTrickyStoreOSS.so", "libcertgen.so")
                        ) {
                            val destination = tempDir.resolve(entry.name)
                            destination.parentFile.mkdirs()
                            zip.getInputStream(entry).use { input ->
                                destination.outputStream().use(input::copyTo)
                            }
                        }
                    }
                }

                val dexEntry = Regex("""classes\d*\.dex""")
                var carried = 0
                // Entry timestamps default to "now", which stamps every payload.bin with the
                // moment of its build. A fixed value drops that fingerprint and makes the
                // artifact byte-reproducible for a given dex (ZipEntry.time is epoch millis;
                // 1980-01-01T00:00:00Z is the DOS epoch zip tooling standardizes on).
                val fixedZipTime = 315_532_800_000L
                ZipOutputStream(tempDir.resolve("payload.bin").outputStream()).use { out ->
                    ZipFile(apk).use { zip ->
                        for (entry in zip.entries()) {
                            if (entry.isDirectory || !dexEntry.matches(entry.name)) continue
                            out.putNextEntry(ZipEntry(entry.name).apply { time = fixedZipTime })
                            zip.getInputStream(entry).use { input -> input.copyTo(out) }
                            out.closeEntry()
                            carried++
                        }
                    }
                }
                check(carried > 0) { "the $variantName APK carries no classes.dex to publish" }
                // Last step before the zip is assembled: drop the unwind tables from the three
                // ELF files that actually get installed. Sizes are printed so the saving shows up
                // in the CI log instead of only in the zip.
                val ndk = Toolchains.resolveAndroidNdk(sdkDir, ndkVersion, minSdk)
                val compactScript = toolsDir.resolve("elf_compact.py")
                val python = if (compactScript.isFile) Toolchains.resolvePython() else null
                if (compactScript.isFile && python == null) {
                    println("compact: skipped, no python3 (>= 3.8) on PATH; zip will keep the zero holes")
                }
                for (name in listOf("libcertgen.so", "libinject.so", "libTrickyStoreOSS.so")) {
                    val artifact = tempDir.resolve("lib/arm64-v8a/$name")
                    if (!artifact.isFile) {
                        throw GradleException(
                            "expected $name in the staged module at ${artifact.absolutePath}",
                        )
                    }
                    Toolchains.stripUnwindTables(ndk, artifact)
                    if (python != null) Toolchains.compactElf(python, compactScript, artifact)
                }
            }
        }

        tasks.register<Zip>("zip${capitalized}") {
            dependsOn("prepareModuleFiles${capitalized}")
            archiveFileName.set("Tricky-Store-OSS-RS-$verName-$gitCommitCount-$gitCommitHash-${capitalized}.zip")
            destinationDirectory.set(project.rootDir.resolve("out"))
            from(tempModuleDir)
        }

        tasks.matching { it.name == "assemble${capitalized}" }.configureEach { finalizedBy("zip${capitalized}") }
    }
}
