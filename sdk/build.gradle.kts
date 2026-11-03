/*
 * Copyright (c) 2026, Circle Internet Group, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import com.android.build.api.dsl.ManagedVirtualDevice
import org.cyclonedx.gradle.CyclonedxDirectTask

// DAA Android SDK library module.
//
// Android library containing the narrow Owner AuthKey surface and the SCA
// hosted-ceremony client. It does not implement the AuthKey enrollment,
// recovery, or rotation flows, Owner-grant handling, or network models.

plugins {
    id("com.android.library")
    kotlin("android")
    kotlin("plugin.serialization")
    id("org.jlleitschuh.gradle.ktlint")
    id("org.cyclonedx.bom")
    `maven-publish`
}

dependencies {
    // FragmentActivity is public API (the biometric prompt is shown over one),
    // so retain the modern consumer floor used by host apps.
    api("androidx.fragment:fragment:1.6.2")
    // The SCA contracts extend ActivityResultContract, so activity is public API.
    // Pinned to the version androidx.browser 1.9.0 resolves, so declaring it here
    // moves nothing beyond what the browser dependency already requires.
    api("androidx.activity:activity:1.9.0")
    // Auth Tab (AuthTabIntent, 1.9.0+) and Custom Tabs for the SCA ceremony. 1.9.0's
    // AAR metadata requires compileSdk 36 and AGP 8.9.1+ of every consumer; that is
    // why this module compiles against 36. See README.md "Requirements".
    implementation("androidx.browser:browser:1.9.0")
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("androidx.core:core:1.9.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.8.1")
    testImplementation(platform("org.junit:junit-bom:5.11.3"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    testImplementation("org.mockito:mockito-core:5.15.2")
    androidTestImplementation("androidx.test:core-ktx:1.6.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test.ext:junit-ktx:1.2.1")
    androidTestImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.10.2")
}

android {
    namespace = "com.circle.daa.sdk"
    compileSdk = 36
    defaultConfig {
        minSdk = 23
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }
    compileOptions {
        // No core library desugaring. Enabling it here would be recorded in the
        // published AAR's metadata, and AGP then refuses to build any consuming
        // app that has not enabled it too — a build-configuration change imposed
        // on every integrator. Main sources therefore stay within minSdk's own
        // API surface: see internal/EpochSeconds and internal/authkey/Base64Url,
        // which exist to avoid java.time and java.util.Base64 (both API 26).
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    testOptions {
        unitTests.all { it.useJUnitPlatform() }
        // This profile is for a disposable, hardware-virtualized host. A host
        // without hardware virtualization compiles these tests but cannot boot
        // the VM.
        managedDevices.devices {
            create<ManagedVirtualDevice>("nexusOneApi30") {
                device = "Nexus One"
                apiLevel = 30
                systemImageSource = "aosp-atd"
            }
        }
    }
    publishing { singleVariant("release") { withSourcesJar() } }
}

kotlin {
    // Enforce an explicit public API surface at compile time — the central
    // custody invariant is "no generic sign(bytes) on the public surface", so a
    // compiler-enforced boundary is cheap insurance (a leaked internal fails).
    explicitApi()
    jvmToolchain(17)
}

publishing {
    // The Maven publication consumers resolve as `com.circle.daa:daa-android-sdk`.
    publications {
        create<MavenPublication>("maven") {
            // Explicit coordinate, not the default, which would inherit the generic
            // project name `sdk`. Published coordinates are permanent.
            artifactId = "daa-android-sdk"
            afterEvaluate { from(components["release"]) }
            pom {
                name = "DAA Android SDK"
                description = "Digital Asset Accounts (DAA) SDK for Android."
                url = "https://github.com/circlefin/daa-android-sdk"
                licenses {
                    license {
                        name = "Apache-2.0"
                        url = "https://www.apache.org/licenses/LICENSE-2.0"
                    }
                }
                scm {
                    url = "https://github.com/circlefin/daa-android-sdk"
                    connection = "scm:git:https://github.com/circlefin/daa-android-sdk.git"
                    developerConnection = "scm:git:ssh://git@github.com/circlefin/daa-android-sdk.git"
                }
            }
        }
    }
    repositories {
        // A local Maven repository under build/staging-repo. Needs no credentials;
        // a consuming project can point a `maven {}` block at it, or use
        // `includeBuild` instead.
        maven {
            name = "staging"
            url = uri(rootProject.layout.buildDirectory.dir("staging-repo"))
        }
    }
}

tasks.named<CyclonedxDirectTask>("cyclonedxDirectBom") {
    // CycloneDX SBOM for the published artifact's resolved runtime
    // dependencies, scoped to what actually ships in the published AAR.
    //
    // The per-project "direct" task, not the plugin's default aggregate
    // `cyclonedxBom` task: plugin 3.0+ removed includeConfigs/skipConfigs from
    // the aggregate task, and AGP never creates a plain `runtimeClasspath`
    // configuration for the aggregate task to fall back to — only the
    // variant-scoped `releaseRuntimeClasspath` below exists here. `testConfigs`
    // already defaults to excluding `^test.*`; it does not need to be repeated.
    includeConfigs = listOf("releaseRuntimeClasspath")
}

tasks.withType<Test>().configureEach {
    // Drift guard: expose the Gradle coordinate version to the test so
    // it can assert it equals DaaSdk.VERSION. Bumping this build's `version`
    // without updating DaaSdk.VERSION (or vice versa) FAILS the build; see
    // DaaSdk.kt.
    systemProperty("daa.project.version", project.version.toString())
}
