/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

// Top-level build file where you can add configuration options common to all sub-projects/modules.

/*
 * Every open Dependabot alert on this repository is a transitive dependency of the Android Gradle
 * Plugin's own classpath — BouncyCastle, jdom2, jose4j, httpclient, commons-lang3 and the Kotlin
 * Gradle Plugin that AGP pins — so none of them are declared by this project and none of them ship
 * in the APK. AGP 9.4.1 is the current stable release, so there is no plugin upgrade that would
 * pull fixed versions in; the versions are pinned here instead.
 *
 * This only affects the build machine: `cargo`-built native code, the app and the module all stay
 * free of these artifacts. Keep the list in sync with the Dependabot alerts and drop an entry once
 * AGP stops pulling the vulnerable version, so the pin does not outlive its reason.
 */
buildscript {
    configurations.all {
        resolutionStrategy {
            force(
                // CVE-2026-13506: Lazy ASN.1 sequence forcing resets the nesting-depth guard.
                "org.bouncycastle:bcprov-jdk18on:1.86",
                "org.bouncycastle:bcpkix-jdk18on:1.86",
                // CVE-2021-33813: XML parsing allows a denial of service via a crafted document.
                "org.jdom:jdom2:2.0.6.1",
                "org.bitbucket.b_c:jose4j:0.9.6",
                "org.apache.commons:commons-lang3:3.18.0",
                // CVE-2026-53914: unsafe deserialization in the Kotlin build cache.
                "org.jetbrains.kotlin:kotlin-gradle-plugin:2.4.21",
                "org.jetbrains.kotlin:kotlin-gradle-plugin-api:2.4.21",
                "org.jetbrains.kotlin:kotlin-gradle-plugin-model:2.4.21",
            )
        }
    }
}
plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.android.library) apply false
}