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
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class ClearedForReplacementTest {
    @Test
    fun `stops key creation when durable state could not be cleared`() {
        val error =
            assertThrows(DaaSecureKeyException::class.java) {
                requireClearedForReplacement(cleared = false)
            }

        assertEquals(DaaSecureKeyError.KeyCreationFailed, error.error)
        assertNull(error.cause)
    }

    @Test
    fun `allows key creation once durable state is cleared`() {
        assertDoesNotThrow { requireClearedForReplacement(cleared = true) }
    }
}
