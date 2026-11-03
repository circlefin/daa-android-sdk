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

package com.circle.daa.sdk

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class DaaSdkTest {
    // Asserts VERSION is a well-formed semver (so it does not break on every
    // intended bump). The regex accepts an optional pre-release and build-metadata
    // suffix (e.g. `0.1.0-SNAPSHOT`, `0.1.0+sha.abc1234`).
    @Test
    fun `reports a semantic version`() {
        assertTrue(
            DaaSdk.VERSION.matches(Regex("""\d+\.\d+\.\d+(-[\w.]+)?(\+[\w.]+)?""")),
            "unexpected version: ${DaaSdk.VERSION}",
        )
    }

    // Drift guard: DaaSdk.VERSION and the Gradle coordinate `version`
    // are two hand-maintained copies of the same string. build.gradle.kts injects
    // the coordinate as the `daa.project.version` system property; this asserts
    // the two agree, so bumping one without the other fails the build.
    @Test
    fun `VERSION matches the gradle coordinate`() {
        val coordinate = System.getProperty("daa.project.version")
        // Distinguish a misconfigured harness (property unset — e.g. running this
        // class directly in an IDE rather than via `./gradlew test`) from real
        // drift, so the failure message points at the actual cause.
        assertNotNull(
            coordinate,
            "daa.project.version is not set — run via `./gradlew test` (injected in sdk/build.gradle.kts)",
        )
        assertEquals(
            coordinate,
            DaaSdk.VERSION,
            "DaaSdk.VERSION (${DaaSdk.VERSION}) drifted from the Gradle coordinate ($coordinate) — bump both",
        )
    }
}
