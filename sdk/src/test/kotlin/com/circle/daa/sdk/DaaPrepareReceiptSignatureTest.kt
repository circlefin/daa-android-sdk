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

import com.circle.daa.sdk.internal.authkey.AuthKeyWireFixture
import com.circle.daa.sdk.internal.authkey.EcdsaSignatureJose
import com.circle.daa.sdk.internal.authkey.P256PublicKeyEncoding
import com.circle.daa.sdk.internal.authkey.hexToByteArray
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.lang.reflect.Modifier
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

class DaaPrepareReceiptSignatureTest {
    @Test
    fun `accepts the RFC 6979 P-256 SHA-256 vectors`() {
        rfc6979Vectors.forEach { (message, signatureHex) ->
            assertTrue(
                DaaPrepareReceiptSignature.verify(
                    publicKeyX963 = RFC6979_PUBLIC_KEY_X963.hexToByteArray(),
                    signingInput = message.toByteArray(Charsets.US_ASCII),
                    signature = signatureHex.hexToByteArray(),
                ),
                message,
            )
        }
    }

    @Test
    fun `accepts the shared wire fixture's known-answer signature`() {
        val vector = AuthKeyWireFixture.load().signedMessage

        assertTrue(
            DaaPrepareReceiptSignature.verify(
                publicKeyX963 = vector.publicKeyX963Hex.hexToByteArray(),
                signingInput = vector.messageHex.hexToByteArray(),
                signature = vector.rawHex.hexToByteArray(),
            ),
        )
    }

    @Test
    fun `accepts a fresh platform signature over JWS signing input`() {
        val keyPair = p256KeyPair()
        val signingInput = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJyZWNlaXB0In0".toByteArray(Charsets.US_ASCII)

        assertTrue(
            DaaPrepareReceiptSignature.verify(
                publicKeyX963 = x963(keyPair),
                signingInput = signingInput,
                signature = joseSignature(keyPair, signingInput),
            ),
        )
    }

    @Test
    fun `rejects tampered signing input`() {
        val signingInput = "sample".toByteArray(Charsets.US_ASCII)
        signingInput[0] = (signingInput[0].toInt() xor 0x01).toByte()

        assertFalse(
            DaaPrepareReceiptSignature.verify(
                publicKeyX963 = RFC6979_PUBLIC_KEY_X963.hexToByteArray(),
                signingInput = signingInput,
                signature = rfc6979Vectors.getValue("sample").hexToByteArray(),
            ),
        )
    }

    @Test
    fun `rejects a tampered signature`() {
        val signature = rfc6979Vectors.getValue("sample").hexToByteArray()
        signature[63] = (signature[63].toInt() xor 0x01).toByte()

        assertFalse(
            DaaPrepareReceiptSignature.verify(
                publicKeyX963 = RFC6979_PUBLIC_KEY_X963.hexToByteArray(),
                signingInput = "sample".toByteArray(Charsets.US_ASCII),
                signature = signature,
            ),
        )
    }

    @Test
    fun `rejects a signature under a different key`() {
        assertFalse(
            DaaPrepareReceiptSignature.verify(
                publicKeyX963 = x963(p256KeyPair()),
                signingInput = "sample".toByteArray(Charsets.US_ASCII),
                signature = rfc6979Vectors.getValue("sample").hexToByteArray(),
            ),
        )
    }

    @Test
    fun `rejects any signature that is not exactly 64 bytes`() {
        val valid = rfc6979Vectors.getValue("sample").hexToByteArray()
        val candidates =
            mapOf(
                "empty" to ByteArray(0),
                "63 bytes" to valid.copyOfRange(0, 63),
                "65 bytes" to valid + byteArrayOf(0),
                "DER" to EcdsaSignatureJose.derRepresentation(valid),
            )

        candidates.forEach { (name, signature) ->
            assertFalse(
                DaaPrepareReceiptSignature.verify(
                    publicKeyX963 = RFC6979_PUBLIC_KEY_X963.hexToByteArray(),
                    signingInput = "sample".toByteArray(Charsets.US_ASCII),
                    signature = signature,
                ),
                name,
            )
        }
    }

    @Test
    fun `rejects r or s outside the scalar range`() {
        val valid = rfc6979Vectors.getValue("sample").hexToByteArray()
        val r = valid.copyOfRange(0, 32)
        val s = valid.copyOfRange(32, 64)
        val zero = ByteArray(32)
        val order = GROUP_ORDER.toFixed32()
        val allOnes = ByteArray(32) { 0xFF.toByte() }
        val candidates =
            mapOf(
                "r = 0" to zero + s,
                "s = 0" to r + zero,
                "r = n" to order + s,
                "s = n" to r + order,
                "r > n" to allOnes + s,
                "s > n" to r + allOnes,
            )

        candidates.forEach { (name, signature) ->
            assertEquals(64, signature.size, name)
            assertFalse(
                DaaPrepareReceiptSignature.verify(
                    publicKeyX963 = RFC6979_PUBLIC_KEY_X963.hexToByteArray(),
                    signingInput = "sample".toByteArray(Charsets.US_ASCII),
                    signature = signature,
                ),
                name,
            )
        }
    }

    @Test
    fun `rejects the shared fixture's out-of-range raw signatures`() {
        AuthKeyWireFixture.load().rejected.ecdsaRaw.forEach { vector ->
            assertFalse(
                DaaPrepareReceiptSignature.verify(
                    publicKeyX963 = RFC6979_PUBLIC_KEY_X963.hexToByteArray(),
                    signingInput = "sample".toByteArray(Charsets.US_ASCII),
                    signature = vector.hex.hexToByteArray(),
                ),
                vector.name,
            )
        }
    }

    @Test
    fun `throws for a public key that is not on P-256`() {
        val onCurve = RFC6979_PUBLIC_KEY_X963.hexToByteArray()
        val yPlusOne = onCurve.copyOf()
        yPlusOne[64] = (yPlusOne[64] + 1).toByte()
        val keys =
            mapOf(
                "y + 1" to yPlusOne,
                "origin" to byteArrayOf(0x04) + ByteArray(64),
                "x = p" to byteArrayOf(0x04) + FIELD_PRIME.toFixed32() + onCurve.copyOfRange(33, 65),
            )

        keys.forEach { (name, key) ->
            assertThrows(IllegalArgumentException::class.java, {
                DaaPrepareReceiptSignature.verify(
                    publicKeyX963 = key,
                    signingInput = "sample".toByteArray(Charsets.US_ASCII),
                    signature = rfc6979Vectors.getValue("sample").hexToByteArray(),
                )
            }, name)
        }
    }

    @Test
    fun `throws for a malformed public key encoding`() {
        val valid = RFC6979_PUBLIC_KEY_X963.hexToByteArray()
        val keys =
            AuthKeyWireFixture.load().rejected.x963PublicKeys.associate { it.name to it.hex.hexToByteArray() } +
                mapOf(
                    "empty" to ByteArray(0),
                    "64 bytes" to valid.copyOfRange(0, 64),
                    "66 bytes" to valid + byteArrayOf(0),
                    "SPKI instead of X9.63" to P256PublicKeyEncoding.subjectPublicKeyInfo(valid),
                )

        keys.forEach { (name, key) ->
            assertThrows(IllegalArgumentException::class.java, {
                DaaPrepareReceiptSignature.verify(
                    publicKeyX963 = key,
                    signingInput = "sample".toByteArray(Charsets.US_ASCII),
                    signature = rfc6979Vectors.getValue("sample").hexToByteArray(),
                )
            }, name)
        }
    }

    @Test
    fun `a bad key is reported even when the signature is also malformed`() {
        assertThrows(IllegalArgumentException::class.java) {
            DaaPrepareReceiptSignature.verify(
                publicKeyX963 = byteArrayOf(0x04) + ByteArray(64),
                signingInput = ByteArray(0),
                signature = ByteArray(0),
            )
        }
    }

    @Test
    fun `exposes only verify, with no signing or private-key surface`() {
        val publicMethods =
            DaaPrepareReceiptSignature::class.java.declaredMethods
                .filter { Modifier.isPublic(it.modifiers) }
        assertEquals(listOf("verify"), publicMethods.map { it.name })

        val touchesPrivateKey =
            DaaPrepareReceiptSignature::class.java.declaredMethods.any { method ->
                PrivateKey::class.java.isAssignableFrom(method.returnType) ||
                    method.parameterTypes.any { PrivateKey::class.java.isAssignableFrom(it) }
            } ||
                DaaPrepareReceiptSignature::class.java.declaredFields.any {
                    PrivateKey::class.java.isAssignableFrom(it.type)
                }
        assertFalse(touchesPrivateKey)
    }

    private fun p256KeyPair(): KeyPair =
        KeyPairGenerator.getInstance("EC").run {
            initialize(ECGenParameterSpec("secp256r1"))
            generateKeyPair()
        }

    private fun x963(keyPair: KeyPair): ByteArray {
        val point = (keyPair.public as ECPublicKey).w
        return byteArrayOf(0x04) + point.affineX.toFixed32() + point.affineY.toFixed32()
    }

    private fun joseSignature(
        keyPair: KeyPair,
        signingInput: ByteArray,
    ): ByteArray =
        EcdsaSignatureJose.rawRepresentation(
            Signature.getInstance("SHA256withECDSA").run {
                initSign(keyPair.private)
                update(signingInput)
                sign()
            },
        )

    private fun BigInteger.toFixed32(): ByteArray {
        val raw = toByteArray().let { if (it.size > 32 && it[0] == 0.toByte()) it.copyOfRange(1, it.size) else it }
        return ByteArray(32 - raw.size) + raw
    }

    private companion object {
        // RFC 6979 appendix A.2.5: the P-256 key and its SHA-256 signatures.
        const val RFC6979_PUBLIC_KEY_X963: String =
            "04" +
                "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6" +
                "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"

        val rfc6979Vectors: Map<String, String> =
            mapOf(
                "sample" to
                    "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716" +
                    "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
                "test" to
                    "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367" +
                    "019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083",
            )

        val GROUP_ORDER: BigInteger =
            BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)

        val FIELD_PRIME: BigInteger =
            BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
    }
}
