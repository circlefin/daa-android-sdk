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

import com.circle.daa.sdk.DaaSecureKeyError
import com.circle.daa.sdk.DaaSecureKeyException
import org.junit.jupiter.api.Assertions.assertDoesNotThrow
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class BiometricAuthenticationStartTest {
    @Test
    fun `rejects an activity whose fragment state is saved without authenticating`() {
        var authenticated = false

        val error =
            assertThrows(DaaSecureKeyException::class.java) {
                startBiometricAuthentication(isActivityStateSaved = true) { authenticated = true }
            }

        assertFalse(authenticated)
        assertEquals(DaaSecureKeyError.AuthenticationFailed, error.error)
    }

    @Test
    fun `maps platform start failures to authentication failed`() {
        val cause = IllegalArgumentException("unsupported authenticators")

        val error =
            assertThrows(DaaSecureKeyException::class.java) {
                startBiometricAuthentication(isActivityStateSaved = false) { throw cause }
            }

        assertEquals(DaaSecureKeyError.AuthenticationFailed, error.error)
        assertSame(cause, error.cause)
    }

    @Test
    fun `starts authentication while activity state is ready`() {
        var authenticated = false

        assertDoesNotThrow {
            startBiometricAuthentication(isActivityStateSaved = false) { authenticated = true }
        }

        assertTrue(authenticated)
    }
}
