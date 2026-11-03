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
 * Unpadded canonical Base64URL, implemented here rather than delegated.
 *
 * `java.util.Base64` is API 26 while this library's `minSdk` is 23, so using it
 * obliges every consuming app to turn on core library desugaring — AGP records
 * that in the published AAR's metadata and refuses to build an app that has not.
 * A codec is not worth imposing a build-configuration change on every
 * integrator. `android.util.Base64` would clear the API level but not the
 * second constraint: it is a stub in JVM unit tests, so the suites covering this
 * would need Robolectric or unmocking to keep running.
 *
 * [decode] is deliberately strict, and that strictness is load-bearing rather
 * than tidiness: these values are compared against digests and reproduced into
 * signing inputs, so an encoding with more than one valid spelling would let two
 * different strings denote the same bytes. It therefore accepts only the
 * canonical unpadded form — no `=` padding, no non-zero trailing bits, no
 * whitespace, and no standard-alphabet `+` or `/`.
 */
internal object Base64Url {
    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

    internal fun encode(data: ByteArray): String {
        val out = StringBuilder((data.size * 4 + 2) / 3)
        var index = 0
        while (index < data.size) {
            val first = data[index].toInt() and 0xff
            val second = if (index + 1 < data.size) data[index + 1].toInt() and 0xff else -1
            val third = if (index + 2 < data.size) data[index + 2].toInt() and 0xff else -1

            out.append(ALPHABET[first ushr 2])
            if (second < 0) {
                // Trailing bits are emitted as zero, which is what makes the
                // round-trip check in decode() reject a non-canonical spelling.
                out.append(ALPHABET[(first and 0x03) shl 4])
            } else {
                out.append(ALPHABET[((first and 0x03) shl 4) or (second ushr 4)])
                if (third < 0) {
                    out.append(ALPHABET[(second and 0x0f) shl 2])
                } else {
                    out.append(ALPHABET[((second and 0x0f) shl 2) or (third ushr 6)])
                    out.append(ALPHABET[third and 0x3f])
                }
            }
            index += 3
        }
        return out.toString()
    }

    internal fun decode(value: String): ByteArray? {
        // A length of 1 mod 4 cannot be produced by any input: it carries six
        // bits, too few for a byte and too many to discard.
        if (value.isEmpty() || value.length % 4 == 1) {
            return null
        }

        val out = ByteArray(value.length * 3 / 4)
        var accumulator = 0
        var bits = 0
        var written = 0
        for (character in value) {
            val position = ALPHABET.indexOf(character)
            // Rejects padding, the standard alphabet's `+` and `/`, whitespace,
            // and anything non-ASCII, without a separate character scan.
            if (position < 0) {
                return null
            }
            accumulator = (accumulator shl 6) or position
            bits += 6
            if (bits >= 8) {
                bits -= 8
                out[written++] = ((accumulator ushr bits) and 0xff).toByte()
            }
        }

        // Canonicality: any input whose discarded trailing bits were not zero
        // re-encodes to a different string than the one supplied.
        return out.takeIf { encode(it) == value }
    }
}
