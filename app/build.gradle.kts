/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import com.android.build.api.artifact.SingleArtifact
import com.android.build.api.variant.ApplicationVariant
import java.util.Properties
import java.util.zip.ZipFile

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

                cppFlags += "-std=c++23"
                cppFlags += "-fno-exceptions"
                cppFlags += "-fno-rtti"
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
}

dependencies {
    compileOnly(project(":stub"))
    compileOnly(libs.annotation)
    implementation(libs.org.lsposed.libcxx.libcxx)
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

/** Locates the NDK every `cargo` invocation below must use. Called from task actions only. */
fun resolveAndroidNdk(): File {
    val sdkNdkRoot = androidSdkDir?.resolve("ndk")
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
                sdkNdkRoot?.resolve(androidNdkVersion)?.absolutePath,
            ).map { file(it) } + installedRevisions
        ).distinct()
    return candidates.firstOrNull { it.resolve("toolchains/llvm/prebuilt").isDirectory }
        ?: throw GradleException(
            "No usable Android NDK $androidNdkVersion found; the Rust cross-builds need " +
                "aarch64-linux-android$androidMinSdk-clang. Looked at: " +
                candidates.joinToString { it.absolutePath } +
                ". Set ANDROID_NDK_HOME or install it with " +
                "`sdkmanager \"ndk;$androidNdkVersion\"`.",
        )
}

/**
 * Everything a cross-build needs, keyed by environment variable name.
 *
 * `PATH` is still extended because `native-inject/.cargo/config.toml` names the linker without a
 * directory, but nothing depends on it any more: the absolute paths below are what `cc-rs` and
 * `rustc` actually consume.
 */
fun rustAndroidEnvironment(ndk: File): Map<String, String> {
    val prebuilt =
        ndk.resolve("toolchains/llvm/prebuilt").listFiles()?.firstOrNull { it.isDirectory }
            ?: throw GradleException(
                "The NDK at ${ndk.absolutePath} has no toolchains/llvm/prebuilt/<host> directory.",
            )
    val bin = prebuilt.resolve("bin")
    // The API-versioned wrappers bake in `--target` and `--sysroot`, so the unversioned
    // `<triple>-clang` that `cc-rs` probes for is never needed.
    val clang = bin.resolve("aarch64-linux-android$androidMinSdk-clang")
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

// --- Native cert generation (Rust cdylib) ---
// Builds libcertgen.so for arm64-v8a straight into app/src/main/jniLibs, which AGP merges into
// the APK; the module packaging below then extracts it from the APK.
val buildRustCertgen =
    tasks.register<Exec>("buildRustCertgen") {
        group = "TrickyStoreOSS Native Build"
        description = "Builds libcertgen.so via cargo-ndk for arm64-v8a."

        notCompatibleWithConfigurationCache("resolves the NDK when the task runs")

        workingDir = rootProject.projectDir.resolve("native-certgen")

        commandLine(
            "cargo",
            "ndk",
            "-t",
            "arm64-v8a",
            "-o",
            rootProject.projectDir.resolve("app/src/main/jniLibs").absolutePath,
            "build",
            "--release",
        )

        inputs.dir(rootProject.projectDir.resolve("native-certgen/src"))
        inputs.file(rootProject.projectDir.resolve("native-certgen/Cargo.toml"))
        inputs.file(rootProject.projectDir.resolve("native-certgen/Cargo.lock"))
        outputs.dir(rootProject.projectDir.resolve("app/src/main/jniLibs"))

        doFirst {
            rustAndroidEnvironment(resolveAndroidNdk()).forEach { (key, value) -> environment(key, value) }
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

        notCompatibleWithConfigurationCache("resolves the NDK when the task runs")

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

        doFirst {
            rustAndroidEnvironment(resolveAndroidNdk()).forEach { (key, value) -> environment(key, value) }
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

        notCompatibleWithConfigurationCache("resolves the NDK when the task runs")

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

        doFirst {
            rustAndroidEnvironment(resolveAndroidNdk()).forEach { (key, value) -> environment(key, value) }
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
            notCompatibleWithConfigurationCache("stages APK contents into the variant module directory")
            dependsOn(buildRustCertgen, buildRustInject, buildRustDaemon)
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
                            file.name !in setOf("module.prop", "service.apk") &&
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
                        .replace("REPLACEMEVERCODE", gitCommitCount.toString())
                        .replace("REPLACEMEVER", "$verName ($gitCommitCount-$gitCommitHash-$variantName)"),
                )

                // The Rust control plane and the payload it dlopen()s go to the module root:
                // `module/daemon` execs `tricky-daemon`, and `interceptor.rs` looks for
                // `<module>/librustinject.so` next to `<module>/tricky-inject`.
                rustDaemonBinary.copyTo(tempDir.resolve("tricky-daemon"), overwrite = true)
                rustInjectAbiDir
                    .resolve("librustinject.so")
                    .copyTo(tempDir.resolve("librustinject.so"), overwrite = true)

                val apks = apkFile.get().asFile.walkTopDown()
                    .filter { it.isFile && it.extension == "apk" }
                    .sortedBy { it.invariantSeparatorsPath }
                    .toList()
                check(apks.size == 1) { "Expected exactly one APK output for $variantName, found ${apks.size}" }
                val apk = apks.single()

                // The APK is only a carrier for the native libraries now that the JVM control plane
                // is gone, so it is not shipped as service.apk: the module would otherwise carry
                // every .so twice.
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
