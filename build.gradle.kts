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

// Root build script for daa-android-sdk.
//
// Android library build for the DAA SDK.

plugins {
    id("com.android.library") version "8.10.1" apply false
    kotlin("android") version "2.1.21" apply false
    // Compiler plugin for the kotlinx-serialization-json runtime the :sdk module
    // already depends on. Used for DECODING only — the SDK builds no request
    // bodies, so no encoder ships. Version is pinned to the Kotlin version by
    // definition.
    kotlin("plugin.serialization") version "2.1.21" apply false
    id("org.jlleitschuh.gradle.ktlint") version "12.1.1" apply false
    // Binary-compatibility-validator: `apiCheck` fails the build on any
    // unreviewed change to the public API snapshot (`sdk/api/sdk.api`). This
    // turns the guardrail "never expose a generic sign(bytes)" from a convention
    // into a build gate.
    id("org.jetbrains.kotlinx.binary-compatibility-validator") version "0.16.3"
    // Generates a CycloneDX SBOM for the published artifact's resolved runtime
    // dependencies. See `sdk/build.gradle.kts` for the `cyclonedxDirectBom` task
    // configuration.
    id("org.cyclonedx.bom") version "3.4.1" apply false
}

allprojects {
    group = "com.circle.daa"
    // SSOT NOTE: this version is duplicated at
    // sdk/src/main/kotlin/com/circle/daa/sdk/DaaSdk.kt (DaaSdk.VERSION), which is
    // what consumers read at runtime. Bump BOTH together — a unit test injects
    // this coordinate via the `daa.project.version` system property and fails the
    // build on drift (see sdk/build.gradle.kts, DaaSdkTest).
    version = "0.6.0" // x-release-please-version
}
