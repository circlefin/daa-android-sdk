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

package com.circle.daa.sdk.internal.authkey

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test
import java.util.Base64
import kotlin.random.Random

/**
 * `java.util.Base64` appears here as the ORACLE, not as the implementation.
 *
 * Main sources cannot use it — it is API 26 against a `minSdk` of 23, and
 * reaching for it obliges every consuming app to enable core library desugaring.
 * Test sources are under no such constraint: they run on a JVM. That asymmetry
 * is what makes a differential test possible, and it is the strongest evidence
 * available that the hand-written codec behaves exactly like the JDK's.
 */
class Base64UrlTest {
    private val jdk: Base64.Encoder = Base64.getUrlEncoder().withoutPadding()

    @Test
    fun `decodes only unpadded canonical base64url`() {
        assertArrayEquals(byteArrayOf(0), Base64Url.decode("AA"))
        assertNull(Base64Url.decode("AA=="))
        assertNull(Base64Url.decode("AB"))
        assertNull(Base64Url.decode(""))
        assertNull(Base64Url.decode("é"))
    }

    @Test
    fun `encodes identically to the JDK across every length remainder`() {
        val random = Random(20260903)
        for (length in 0..96) {
            val data = random.nextBytes(length)
            assertEquals(jdk.encodeToString(data), Base64Url.encode(data), "length $length")
        }
    }

    @Test
    fun `encodes byte values the sign bit would corrupt`() {
        // Kotlin's Byte is signed, so a naive implementation loses 0x80..0xFF.
        val data = ByteArray(256) { it.toByte() }
        assertEquals(jdk.encodeToString(data), Base64Url.encode(data))
    }

    @Test
    fun `round-trips every length`() {
        val random = Random(20260904)
        for (length in 1..96) {
            val data = random.nextBytes(length)
            assertArrayEquals(data, Base64Url.decode(Base64Url.encode(data)), "length $length")
        }
    }

    @Test
    fun `encodes every one and two byte input exactly as the JDK does`() {
        // Exhaustive, not sampled. Lengths of 1 and 2 mod 3 are the ragged cases
        // — the ones with trailing bits to place — and they are small enough to
        // enumerate completely, so no bit-alignment error can hide in a seed.
        for (first in 0..255) {
            val one = byteArrayOf(first.toByte())
            assertEquals(jdk.encodeToString(one), Base64Url.encode(one), "byte $first")
            for (second in 0..255) {
                val two = byteArrayOf(first.toByte(), second.toByte())
                assertEquals(jdk.encodeToString(two), Base64Url.encode(two), "bytes $first,$second")
            }
        }
    }

    @Test
    fun `decodes back to the bytes the JDK encoded, over many random inputs`() {
        // The differential above pins encode. This pins decode against the same
        // oracle: whatever the JDK encoded, decode must return the original bytes.
        val random = Random(20260905)
        repeat(5000) {
            // From 1: the empty string is deliberately refused, so it is covered
            // by the rejection cases rather than the round-trip ones.
            val data = random.nextBytes(random.nextInt(1, 129))
            val encoded = jdk.encodeToString(data)
            assertArrayEquals(data, Base64Url.decode(encoded), encoded)
        }
    }

    @Test
    fun `rejects the standard alphabet and padding`() {
        // 0xFB 0xFF encodes as `-_8` in base64url and `+/8` in standard base64;
        // accepting the latter would give one byte string two spellings.
        assertArrayEquals(byteArrayOf(0xFB.toByte(), 0xFF.toByte(), 0x00), Base64Url.decode("-_8A"))
        assertNull(Base64Url.decode("+/8A"))
        assertNull(Base64Url.decode("AAAA="))
    }

    @Test
    fun `rejects lengths that cannot encode whole bytes`() {
        // 1 mod 4 carries six bits: too few for a byte, too many to discard.
        assertNull(Base64Url.decode("A"))
        assertNull(Base64Url.decode("AAAAA"))
    }

    @Test
    fun `rejects non-zero trailing bits`() {
        // "AA" is the canonical spelling of a single zero byte; the other three
        // two-character strings decoding to it differ only in discarded bits.
        assertArrayEquals(byteArrayOf(0), Base64Url.decode("AA"))
        for (spelling in listOf("AB", "AC", "AD")) {
            assertNull(Base64Url.decode(spelling), spelling)
        }
    }

    @Test
    fun `rejects whitespace and embedded newlines`() {
        assertNull(Base64Url.decode(" AA"))
        assertNull(Base64Url.decode("AA "))
        assertNull(Base64Url.decode("AA\nAA"))
    }
}
