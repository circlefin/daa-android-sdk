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

import com.circle.daa.sdk.DaaDeviceAuthorizationSigningInputValidator
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/**
 * The prompt text is separated from `BiometricPrompt.PromptInfo` so it can be tested on a JVM at
 * all — `PromptInfo` requires the real Android `BiometricPrompt` class, which is only available in
 * the instrumentation lane. See [AndroidAuthKeyBackendTest] (androidTest) for the assertion that
 * this text actually lands in a constructed `PromptInfo`.
 */
class OperationAuthorizationPromptTest {
    /**
     * The cross-platform wording table. Both SDKs must produce these exact strings; the iOS SDK
     * pins the same six. Keyed by the validated wire discriminator, never shown raw.
     */
    private val table =
        mapOf(
            DaaDeviceAuthorizationSigningInputValidator.TRANSFER to "Authorizing: transfer",
            DaaDeviceAuthorizationSigningInputValidator.WITHDRAWAL to "Authorizing: withdrawal",
            DaaDeviceAuthorizationSigningInputValidator.CREATE_ACCOUNT to "Authorizing: account creation",
            DaaDeviceAuthorizationSigningInputValidator.REGISTER_DEVICE_KEY to "Authorizing: device registration",
            DaaDeviceAuthorizationSigningInputValidator.COMPLETE_SOCIAL_LOGIN to "Authorizing: sign-in",
            DaaDeviceAuthorizationSigningInputValidator.GET_DEVICE_CONTEXT to "Authorizing: device verification",
        )

    @Test
    fun `maps every operation to its table prompt`() {
        table.forEach { (operation, expected) ->
            assertEquals(expected, operationAuthorizationPrompt(operation))
        }
    }

    @Test
    fun `negative button text is SDK-set`() {
        assertEquals("Cancel", PROMPT_NEGATIVE_BUTTON_TEXT)
    }

    @Test
    fun `never surfaces the raw discriminator for an unknown operation`() {
        assertEquals("Authorizing", operationAuthorizationPrompt("some_future_operation"))
    }
}
