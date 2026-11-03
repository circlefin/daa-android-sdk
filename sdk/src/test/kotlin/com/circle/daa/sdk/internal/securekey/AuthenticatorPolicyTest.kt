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
import androidx.biometric.BiometricManager
import com.circle.daa.sdk.DaaSecureKeyError
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/** Pure-JVM coverage for the authenticator-policy predicate; `KeyInfo` is a stub in unit tests. */
class AuthenticatorPolicyTest {
    @Test
    fun `pins a strong biometric only`() {
        assertEquals(KeyProperties.AUTH_BIOMETRIC_STRONG, USER_PRESENCE_AUTHENTICATORS)
    }

    @Test
    fun `accepts a strong-biometric-only key, which is also what a pre-API-30 key reports after an OS upgrade`() {
        assertTrue(isAuthenticatorPolicyPinned(KeyProperties.AUTH_BIOMETRIC_STRONG))
    }

    @Test
    fun `refuses a key that admits the device credential`() {
        assertFalse(isAuthenticatorPolicyPinned(KeyProperties.AUTH_DEVICE_CREDENTIAL))
        assertFalse(
            isAuthenticatorPolicyPinned(KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL),
        )
    }

    @Test
    fun `refuses no authenticator and unknown extra bits`() {
        assertFalse(isAuthenticatorPolicyPinned(0))
        // 1 shl 4 is not any AUTH_* constant today (they are 1 and 2); revisit if the platform adds one.
        assertFalse(isAuthenticatorPolicyPinned(KeyProperties.AUTH_BIOMETRIC_STRONG or (1 shl 4)))
    }

    @Test
    fun `maps strong-biometric availability to the same errors at creation and signing`() {
        assertNull(strongBiometricUnavailableError(BiometricManager.BIOMETRIC_SUCCESS))
        assertEquals(
            DaaSecureKeyError.SecureHardwareUnavailable,
            strongBiometricUnavailableError(BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE),
        )
        assertEquals(
            DaaSecureKeyError.SecureHardwareUnavailable,
            strongBiometricUnavailableError(BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE),
        )
        assertEquals(
            DaaSecureKeyError.AuthenticationFailed,
            strongBiometricUnavailableError(BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED),
        )
    }
}
