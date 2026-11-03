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
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec

class EcdsaSignatureJoseTest {
    @Test
    fun `converts JCA DER signature to JOSE and back`() {
        val keyPair =
            KeyPairGenerator.getInstance("EC").run {
                initialize(ECGenParameterSpec("secp256r1"))
                generateKeyPair()
            }
        val message = "exact request bytes".toByteArray()
        val der =
            Signature.getInstance("SHA256withECDSA").run {
                initSign(keyPair.private)
                update(message)
                sign()
            }

        val raw = EcdsaSignatureJose.rawRepresentation(der = der)
        assertEquals(64, raw.size)

        val roundTripDer = EcdsaSignatureJose.derRepresentation(raw = raw)
        val verified =
            Signature.getInstance("SHA256withECDSA").run {
                initVerify(keyPair.public)
                update(message)
                verify(roundTripDer)
            }
        assertTrue(verified)
    }

    @Test
    fun `matches shared padding vectors in both directions`() {
        val fixture = AuthKeyWireFixture.load()

        fixture.ecdsaSignatures.forEach { vector ->
            val der = vector.derHex.hexToByteArray()
            val raw = vector.rawHex.hexToByteArray()

            assertArrayEquals(raw, EcdsaSignatureJose.rawRepresentation(der = der), vector.name)
            assertArrayEquals(der, EcdsaSignatureJose.derRepresentation(raw = raw), vector.name)
        }
    }

    @Test
    fun `shared known-answer signature verifies`() {
        val vector = AuthKeyWireFixture.load().signedMessage
        val message = vector.messageHex.hexToByteArray()
        val x963 = vector.publicKeyX963Hex.hexToByteArray()
        val der = vector.derHex.hexToByteArray()
        val raw = vector.rawHex.hexToByteArray()
        val spki = P256PublicKeyEncoding.subjectPublicKeyInfo(x963 = x963)
        val publicKey = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(spki))

        assertArrayEquals(raw, EcdsaSignatureJose.rawRepresentation(der = der), vector.name)
        assertArrayEquals(der, EcdsaSignatureJose.derRepresentation(raw = raw), vector.name)
        assertTrue(
            Signature.getInstance("SHA256withECDSA").run {
                initVerify(publicKey)
                update(message)
                verify(der)
            },
            vector.name,
        )
    }

    @Test
    fun `rejects malformed DER wrong lengths and invalid scalars`() {
        val rejected = AuthKeyWireFixture.load().rejected

        rejected.ecdsaDer.forEach { vector ->
            assertMalformedDer(vector.hex.hexToByteArray(), vector.name)
        }
        rejected.ecdsaRaw.forEach { vector ->
            assertMalformedRaw(vector.hex.hexToByteArray(), vector.name)
        }

        listOf(0, 63, 65).forEach { count ->
            assertMalformedRaw(ByteArray(count), "raw length $count")
        }
    }

    @Test
    fun `rejects negative non-minimal overlong and trailing-byte DER encodings`() {
        val negativeR = "3006020180020101".hexToByteArray()
        val unnecessaryPadding = "300702020001020101".hexToByteArray()
        val overlongSequenceLength = "308106020101020101".hexToByteArray()
        val overflowingIntegerLength = "300602847fffffff".hexToByteArray()
        val trailingByte = "300602010102010100".hexToByteArray()

        listOf(
            "negative r" to negativeR,
            "unnecessary integer padding" to unnecessaryPadding,
            "overlong sequence length" to overlongSequenceLength,
            "overflowing integer length" to overflowingIntegerLength,
            "trailing byte" to trailingByte,
        ).forEach { (name, value) ->
            assertMalformedDer(value, name)
        }
    }

    private fun assertMalformedDer(
        der: ByteArray,
        name: String,
    ) {
        val error =
            assertThrows(AuthKeyWireError::class.java) {
                EcdsaSignatureJose.rawRepresentation(der = der)
            }.also { assertEquals(AuthKeyWireError.MalformedEcdsaSignature, it, name) }
        assertSame(AuthKeyWireError.MalformedEcdsaSignature, error)
    }

    private fun assertMalformedRaw(
        raw: ByteArray,
        name: String,
    ) {
        val error =
            assertThrows(AuthKeyWireError::class.java) {
                EcdsaSignatureJose.derRepresentation(raw = raw)
            }.also { assertEquals(AuthKeyWireError.MalformedEcdsaSignature, it, name) }
        assertSame(AuthKeyWireError.MalformedEcdsaSignature, error)
    }
}
