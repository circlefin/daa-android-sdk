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

import android.security.keystore.KeyProperties
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * The interpretation is separated from `KeyInfo` so it can be tested on a JVM at all — `KeyInfo` is an
 * Android class and a stub in unit tests, and `securityLevel` itself is only defined from API 31.
 */
class HardwareBackedSecurityLevelTest {
    @Test
    fun `accepts trusted environment and strongbox`() {
        assertTrue(isHardwareBackedSecurityLevel(KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT))
        assertTrue(isHardwareBackedSecurityLevel(KeyProperties.SECURITY_LEVEL_STRONGBOX))
    }

    @Test
    fun `accepts unknown-secure as a distinct guarantee from unknown`() {
        // The platform would not report SECURITY_LEVEL_UNKNOWN_SECURE unless the key is at least as
        // strong as SECURITY_LEVEL_TRUSTED_ENVIRONMENT — only the exact tier is withheld, not whether
        // hardware was involved.
        assertTrue(isHardwareBackedSecurityLevel(KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE))
    }

    @Test
    fun `rejects software`() {
        assertFalse(isHardwareBackedSecurityLevel(KeyProperties.SECURITY_LEVEL_SOFTWARE))
    }

    @Test
    fun `rejects plain unknown because the guarantee cannot be confirmed`() {
        // Unlike SECURITY_LEVEL_UNKNOWN_SECURE, this means the Keymaster implementation could not report
        // a level at all. Passing an unconfirmed key is exactly what this check exists to prevent.
        assertFalse(isHardwareBackedSecurityLevel(KeyProperties.SECURITY_LEVEL_UNKNOWN))
    }

    @Test
    fun `rejects a level it has never been taught about`() {
        // The platform has added security levels before and may again. A value this code does not
        // recognise is not evidence of hardware backing, so it has to fail closed and force a decision
        // here rather than pass simply by not appearing on a denylist.
        assertFalse(isHardwareBackedSecurityLevel(99))
        assertFalse(isHardwareBackedSecurityLevel(Int.MAX_VALUE))
    }
}
