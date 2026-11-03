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
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class DaaSecureRandomTest {
    @Test
    fun `returns exactly the requested number of bytes`() {
        // 32 is the size the registration code verifier is built from; 1 and a
        // non-multiple-of-3 length are included because a buffer-reuse or
        // encoding-shaped bug tends to survive only the round sizes.
        listOf(1, 2, 3, 16, 31, 32, 64, 1024).forEach { count ->
            assertEquals(count, DaaSecureRandom.bytes(count).size, "wrong length for count=$count")
        }
    }

    @Test
    fun `returns a fresh distinct buffer on every call`() {
        val samples = List(64) { DaaSecureRandom.bytes(32).toList() }

        // Two equal 32-byte draws from a CSPRNG will not be observed; if this ever
        // fails, the generator is broken rather than unlucky.
        assertEquals(samples.size, samples.toSet().size, "a 32-byte draw repeated")

        // Distinct contents alone would still pass if one buffer were handed out
        // and mutated in place, so identity is checked too.
        val first = DaaSecureRandom.bytes(32)
        val second = DaaSecureRandom.bytes(32)
        assertTrue(first !== second, "the same buffer was returned twice")
    }

    @Test
    fun `does not return a constant or all-zero buffer`() {
        val bytes = DaaSecureRandom.bytes(32)

        assertTrue(bytes.any { it != 0.toByte() }, "an all-zero draw")
        assertTrue(bytes.toSet().size > 1, "every byte of the draw was identical")
    }

    @Test
    fun `rejects a non-positive count`() {
        listOf(0, -1, Int.MIN_VALUE).forEach { count ->
            val error = assertThrows(IllegalArgumentException::class.java) { DaaSecureRandom.bytes(count) }
            // The rejected value is not echoed: a length is not itself a secret,
            // but the message is a contract, not a debugging channel.
            assertEquals("random byte count must be positive", error.message)
        }
    }
}
