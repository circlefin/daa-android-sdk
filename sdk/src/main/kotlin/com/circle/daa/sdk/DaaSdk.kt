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

/**
 * Entry point for the DAA Android SDK.
 *
 * This is a standalone Android library, not a fork of the Programmable
 * Wallet Android SDK. `DaaSecureKey` owns the narrow installation-scoped
 * Owner AuthKey boundary. The SDK does not implement the AuthKey enrollment,
 * recovery, or rotation flows, Owner-grant handling, or network models.
 */
public object DaaSdk {
    /**
     * Semantic version of the SDK, as reported to consumers at runtime.
     *
     * Note: this literal is duplicated by the Gradle coordinate `version` in
     * `build.gradle.kts`. Bump BOTH together — a unit test
     * (`DaaSdkTest.VERSION matches the gradle coordinate`) fails the build if
     * they drift.
     */
    public const val VERSION: String = "0.6.0" // x-release-please-version
}
