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

/**
 * Whether a JSON object's text repeats a top-level member name.
 *
 * `kotlinx.serialization`'s `Json.parseToJsonElement` collapses repeated top-level keys to their
 * last value before a validator's own `keys == allowedSet` check ever runs, and a verifier on the
 * other side of the wire may resolve them its own way. Two parsers happening to agree is not the
 * same as either side enforcing it, and nothing in the wire format itself requires two JSON
 * parsers to keep agreeing. [existAtTopLevel] recovers the member names the parsed
 * structure would otherwise discard by walking the text once, tracking only string boundaries and
 * object/array nesting depth.
 *
 * Comparison is on the literal bytes between the quotes, not on the JSON string's decoded value: a
 * top-level key is rejected outright the moment a backslash appears while it is being captured,
 * rather than decoded and compared. A Unicode-escaped spelling of an ordinary ASCII key and its
 * plain spelling are the same logical key once decoded, and decoding-then-comparing would be the
 * more literal fix, but every fixed field name in both signing inputs is plain ASCII with no
 * legitimate reason to ever carry an escape, so treating any escape in key position as reason
 * enough to reject is both correct here and simpler than writing a decoder whose own correctness
 * would then need to be re-verified.
 *
 * It is not a general JSON validator and makes no claim about malformed input: text that is not
 * valid JSON may or may not be reported as having a duplicate key, but a real parser downstream
 * still owns rejecting it either way, so a wrong answer here on malformed text never turns into a
 * wrong accept — at worst it defers to that parser instead of pre-empting it.
 */
internal object DuplicateJsonKeys {
    internal fun existAtTopLevel(text: String): Boolean {
        var depth = 0
        var inString = false
        var escaped = false
        var expectMemberName = false
        var capturingKey = false
        val key = StringBuilder()
        val seen = mutableSetOf<String>()
        for (char in text) {
            if (inString) {
                when {
                    escaped -> escaped = false
                    char == '\\' -> {
                        // An escape inside a candidate top-level key -- literal or `\uXXXX` --
                        // means the true key name cannot be read off the raw bytes; see the class
                        // doc for why blanket rejection, not decoding, is the correct response.
                        if (capturingKey) return true
                        escaped = true
                    }
                    char == '"' -> {
                        inString = false
                        capturingKey = false
                    }
                    capturingKey -> key.append(char)
                }
                continue
            }
            when (char) {
                '"' -> {
                    inString = true
                    if (depth == 1 && expectMemberName) {
                        capturingKey = true
                        key.setLength(0)
                    }
                }
                '{' -> {
                    // Only the outermost object opening arms member-name capture; a nested
                    // object's own keys must never be mistaken for top-level ones.
                    if (depth == 0) expectMemberName = true
                    depth++
                }
                '[' -> depth++
                '}', ']' -> depth--
                ',' -> if (depth == 1) expectMemberName = true
                ':' ->
                    if (depth == 1 && expectMemberName) {
                        if (!seen.add(key.toString())) return true
                        expectMemberName = false
                    }
            }
        }
        return false
    }
}
