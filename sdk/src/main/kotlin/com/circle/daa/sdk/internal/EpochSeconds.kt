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

package com.circle.daa.sdk.internal

/**
 * Seconds since the Unix epoch, the unit every signing input here is expressed
 * in.
 *
 * This exists so the reason is written down once instead of six bare divisions.
 * `java.time.Instant` is API 26 while this library's `minSdk` is 23, and using
 * it obliges every consuming app to enable core library desugaring — AGP records
 * the requirement in the published AAR's metadata and refuses to build an app
 * that has not. Every call site only ever wanted `Instant.now().epochSecond`, a
 * `Long`, so nothing about `java.time` was load-bearing.
 *
 * Test code is free to keep using `java.time`: unit tests run on a JVM, where
 * the API level does not apply.
 */
internal object EpochSeconds {
    internal fun now(): Long = System.currentTimeMillis() / 1000
}
