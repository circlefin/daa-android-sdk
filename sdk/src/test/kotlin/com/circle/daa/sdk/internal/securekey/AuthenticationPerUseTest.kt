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

package com.circle.daa.sdk.internal.securekey

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * The predicate is separated from `KeyInfo` so it can be tested on a JVM at all — `KeyInfo` is an Android class and is
 * a stub in unit tests, so without this seam the platform's two spellings of "per use" could only be checked on a
 * device.
 */
class AuthenticationPerUseTest {
    @Test
    fun `treats both platform spellings of per-use as per-use`() {
        // API 30+: created with setUserAuthenticationParameters(0, ...), an explicit per-use timeout of zero.
        // This is the value that every current device reports.
        assertTrue(isAuthenticationPerUse(0))
        // API 29 and earlier: what setUserAuthenticationValidityDurationSeconds(-1) produced.
        assertTrue(isAuthenticationPerUse(-1))
    }

    @Test
    fun `refuses a time window`() {
        // A positive duration keeps the key usable for that many seconds after a single unlock. That is a weaker
        // guarantee than an Owner AuthKey makes, so it must not pass as per-use. This is the case the check
        // exists to catch.
        assertFalse(isAuthenticationPerUse(1))
        assertFalse(isAuthenticationPerUse(30))
        assertFalse(isAuthenticationPerUse(Int.MAX_VALUE))
    }

    @Test
    fun `treats any other negative as per-use rather than a window`() {
        // No platform release is known to report these, but if one did, the safe reading is per-use: a negative
        // duration cannot describe a window, and failing closed here would reject a key that is in fact per-use.
        assertTrue(isAuthenticationPerUse(-2))
        assertTrue(isAuthenticationPerUse(Int.MIN_VALUE))
    }
}
