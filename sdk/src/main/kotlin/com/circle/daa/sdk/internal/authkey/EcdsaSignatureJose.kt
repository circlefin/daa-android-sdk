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

internal object EcdsaSignatureJose {
    private const val RAW_BYTE_COUNT: Int = 64
    private const val SCALAR_BYTE_COUNT: Int = RAW_BYTE_COUNT / 2

    private val GROUP_ORDER: ByteArray =
        byteArrayOf(
            0xFF.toByte(),
            0xFF.toByte(),
            0xFF.toByte(),
            0xFF.toByte(),
            0x00,
            0x00,
            0x00,
            0x00,
            0xFF.toByte(),
            0xFF.toByte(),
            0xFF.toByte(),
            0xFF.toByte(),
            0xFF.toByte(),
            0xFF.toByte(),
            0xFF.toByte(),
            0xFF.toByte(),
            0xBC.toByte(),
            0xE6.toByte(),
            0xFA.toByte(),
            0xAD.toByte(),
            0xA7.toByte(),
            0x17,
            0x9E.toByte(),
            0x84.toByte(),
            0xF3.toByte(),
            0xB9.toByte(),
            0xCA.toByte(),
            0xC2.toByte(),
            0xFC.toByte(),
            0x63,
            0x25,
            0x51,
        )

    internal fun rawRepresentation(der: ByteArray): ByteArray {
        val sequence = parseSequence(der)
        val r = parseIntegerScalar(der, sequence.contentOffset)
        val s = parseIntegerScalar(der, r.nextOffset)
        if (s.nextOffset != sequence.endOffset) {
            throw AuthKeyWireError.MalformedEcdsaSignature
        }

        return r.raw + s.raw
    }

    internal fun derRepresentation(raw: ByteArray): ByteArray {
        if (raw.size != RAW_BYTE_COUNT) {
            throw AuthKeyWireError.MalformedEcdsaSignature
        }

        val r = raw.copyOfRange(0, SCALAR_BYTE_COUNT)
        val s = raw.copyOfRange(SCALAR_BYTE_COUNT, raw.size)
        if (!isValidScalar(r) || !isValidScalar(s)) {
            throw AuthKeyWireError.MalformedEcdsaSignature
        }

        val derR = encodeInteger(r)
        val derS = encodeInteger(s)
        val sequenceLength = derR.size + derS.size
        return byteArrayOf(0x30, sequenceLength.toByte()) + derR + derS
    }

    private fun parseSequence(der: ByteArray): ParsedValue {
        if (der.firstOrNull() != 0x30.toByte()) {
            throw AuthKeyWireError.MalformedEcdsaSignature
        }

        val length = parseLength(der, 1)
        val endOffset = length.nextOffset + length.value
        if (endOffset != der.size) {
            throw AuthKeyWireError.MalformedEcdsaSignature
        }
        return ParsedValue(contentOffset = length.nextOffset, endOffset = endOffset)
    }

    private fun parseIntegerScalar(
        der: ByteArray,
        offset: Int,
    ): ParsedScalar {
        if (offset >= der.size || der[offset] != 0x02.toByte()) {
            throw AuthKeyWireError.MalformedEcdsaSignature
        }

        val length = parseLength(der, offset + 1)
        if (length.value <= 0) {
            throw AuthKeyWireError.MalformedEcdsaSignature
        }

        val valueEnd = length.nextOffset + length.value
        if (valueEnd > der.size) {
            throw AuthKeyWireError.MalformedEcdsaSignature
        }

        val value = der.copyOfRange(length.nextOffset, valueEnd)
        val unsigned = canonicalUnsignedInteger(value)
        if (unsigned.size > SCALAR_BYTE_COUNT) {
            throw AuthKeyWireError.MalformedEcdsaSignature
        }

        val raw = ByteArray(SCALAR_BYTE_COUNT)
        unsigned.copyInto(raw, destinationOffset = SCALAR_BYTE_COUNT - unsigned.size)
        if (!isValidScalar(raw)) {
            throw AuthKeyWireError.MalformedEcdsaSignature
        }

        return ParsedScalar(raw = raw, nextOffset = valueEnd)
    }

    private fun canonicalUnsignedInteger(value: ByteArray): ByteArray {
        if (value.isEmpty()) {
            throw AuthKeyWireError.MalformedEcdsaSignature
        }

        return when {
            value[0] == 0x00.toByte() -> {
                if (value.size == 1 || value[1].toInt() and 0x80 == 0 || value[1] == 0x00.toByte()) {
                    throw AuthKeyWireError.MalformedEcdsaSignature
                }
                value.copyOfRange(1, value.size)
            }

            value[0].toInt() and 0x80 != 0 -> throw AuthKeyWireError.MalformedEcdsaSignature

            else -> value
        }
    }

    private fun encodeInteger(raw: ByteArray): ByteArray {
        val significant = raw.dropWhile { it == 0.toByte() }.toByteArray()
        val canonical =
            if (significant.first().toInt() and 0x80 != 0) {
                byteArrayOf(0x00) + significant
            } else {
                significant
            }
        return byteArrayOf(0x02, canonical.size.toByte()) + canonical
    }

    private fun parseLength(
        bytes: ByteArray,
        offset: Int,
    ): ParsedLength {
        if (offset >= bytes.size) {
            throw AuthKeyWireError.MalformedEcdsaSignature
        }

        val first = bytes[offset].toInt() and 0xFF
        // Canonical P-256 ECDSA sequences and INTEGERs are always shorter than 128 bytes.
        if (first and 0x80 != 0) {
            throw AuthKeyWireError.MalformedEcdsaSignature
        }
        return ParsedLength(value = first, nextOffset = offset + 1)
    }

    private fun isValidScalar(raw: ByteArray): Boolean =
        raw.size == SCALAR_BYTE_COUNT &&
            raw.any { it != 0.toByte() } &&
            compareUnsigned(raw, GROUP_ORDER) < 0

    private fun compareUnsigned(
        left: ByteArray,
        right: ByteArray,
    ): Int {
        for (index in left.indices) {
            val difference = (left[index].toInt() and 0xFF) - (right[index].toInt() and 0xFF)
            if (difference != 0) {
                return difference
            }
        }
        return 0
    }

    private data class ParsedLength(
        val value: Int,
        val nextOffset: Int,
    )

    private data class ParsedValue(
        val contentOffset: Int,
        val endOffset: Int,
    )

    private data class ParsedScalar(
        val raw: ByteArray,
        val nextOffset: Int,
    )
}
