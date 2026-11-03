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

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class DuplicateJsonKeysTest {
    @Test
    fun `accepts an object with unique top-level keys`() {
        assertFalse(DuplicateJsonKeys.existAtTopLevel("""{"a":1,"b":2,"c":3}"""))
    }

    @Test
    fun `rejects a repeated top-level key regardless of its value`() {
        assertTrue(DuplicateJsonKeys.existAtTopLevel("""{"a":1,"a":2}"""))
        assertTrue(DuplicateJsonKeys.existAtTopLevel("""{"discriminator":"transfer","discriminator":"withdrawal"}"""))
    }

    @Test
    fun `does not mistake a nested object's keys for top-level duplicates`() {
        assertFalse(DuplicateJsonKeys.existAtTopLevel("""{"a":{"a":1},"b":2}"""))
    }

    @Test
    fun `does not mistake a nested array's contents for top-level duplicates`() {
        assertFalse(DuplicateJsonKeys.existAtTopLevel("""{"a":[1,2,3],"b":["a","b"]}"""))
    }

    @Test
    fun `ignores key-shaped text inside a string value`() {
        assertFalse(DuplicateJsonKeys.existAtTopLevel("""{"a":"\"a\":1, \"a\":2","b":2}"""))
    }

    @Test
    fun `treats a colon inside a string value as part of the string, not a member separator`() {
        assertFalse(DuplicateJsonKeys.existAtTopLevel("""{"body_sha256":"ab:cd","method":"GET"}"""))
    }

    @Test
    fun `accepts an empty object`() {
        assertFalse(DuplicateJsonKeys.existAtTopLevel("{}"))
    }

    @Test
    fun `detects a duplicate that appears after a nested structure`() {
        assertTrue(DuplicateJsonKeys.existAtTopLevel("""{"a":{"x":1},"b":2,"a":3}"""))
    }

    @Test
    fun `rejects a top-level key whose Unicode-escaped spelling would collide with a plain one`() {
        // The first key is spelled entirely in JSON \u0061\u0075\u0064 escapes, which decodes to "aud" --
        // the same three-character key as the second, plainly-spelled key below. Comparing the
        // raw bytes between the quotes -- as `existAtTopLevel` does -- cannot see that they are
        // the same key, which is exactly why any escape in key position is rejected outright
        // rather than decoded and compared: silently treating them as distinct would let this
        // exact case pass `keys == allowedSet` with the right cardinality while actually holding
        // two spellings of one key.
        assertTrue(DuplicateJsonKeys.existAtTopLevel("""{"\u0061\u0075\u0064":1,"aud":2}"""))
    }

    @Test
    fun `rejects a top-level key containing an escaped quote even when it is not a duplicate`() {
        assertTrue(DuplicateJsonKeys.existAtTopLevel("""{"a\"b":1,"c":2}"""))
    }
}
