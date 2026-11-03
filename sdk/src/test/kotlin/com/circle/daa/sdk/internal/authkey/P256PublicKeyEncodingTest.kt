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
import org.junit.jupiter.api.Test

class P256PublicKeyEncodingTest {
    @Test
    fun `P-256 generator point matches shared SPKI and thumbprint vectors`() {
        val fixture = AuthKeyWireFixture.load()
        val x963 = fixture.p256PublicKey.x963Hex.hexToByteArray()

        val spki = P256PublicKeyEncoding.subjectPublicKeyInfo(x963 = x963)

        assertEquals(91, spki.size)
        assertEquals(fixture.p256PublicKey.spkiBase64Url, Base64Url.encode(spki))
        assertEquals(
            fixture.p256PublicKey.jwkThumbprint,
            P256PublicKeyEncoding.jwkThumbprint(spki = spki),
        )
        assertEquals(
            fixture.p256PublicKey.spkiBase64Url,
            P256PublicKeyEncoding.subjectPublicKeyInfoBase64Url(x963 = x963),
        )
        assertArrayEquals(
            x963,
            P256PublicKeyEncoding.x963Representation(spki = spki),
        )
    }

    @Test
    fun `rejects compressed and malformed public keys`() {
        val fixture = AuthKeyWireFixture.load()

        fixture.rejected.x963PublicKeys.forEach { vector ->
            assertMalformedX963(vector.hex.hexToByteArray(), vector.name)
        }
        fixture.rejected.subjectPublicKeyInfo.forEach { vector ->
            assertMalformedSpki(vector.hex.hexToByteArray(), vector.name)
        }
    }

    @Test
    fun `rejects SPKI with wrong algorithm identifier or point payload`() {
        val fixture = AuthKeyWireFixture.load()
        val x963 = fixture.p256PublicKey.x963Hex.hexToByteArray()
        val validSpki = P256PublicKeyEncoding.subjectPublicKeyInfo(x963 = x963)

        val wrongAlgorithmOid = validSpki.copyOf().also { it[12] = 0x02 }
        val wrongBitStringHeader = validSpki.copyOf().also { it[24] = 0x41 }
        val compressedPointSpki = validSpki.copyOf().also { it[26] = 0x02 }

        listOf(
            "wrong algorithm OID" to wrongAlgorithmOid,
            "wrong bit-string header" to wrongBitStringHeader,
            "compressed point" to compressedPointSpki,
        ).forEach { (name, value) ->
            assertMalformedSpki(value, name)
        }
    }

    private fun assertMalformedX963(
        x963: ByteArray,
        name: String,
    ) {
        val error =
            assertThrows(AuthKeyWireError::class.java) {
                P256PublicKeyEncoding.subjectPublicKeyInfo(x963 = x963)
            }.also { assertEquals(AuthKeyWireError.MalformedP256PublicKey, it, name) }
        assertSame(AuthKeyWireError.MalformedP256PublicKey, error)
    }

    private fun assertMalformedSpki(
        spki: ByteArray,
        name: String,
    ) {
        val error =
            assertThrows(AuthKeyWireError::class.java) {
                P256PublicKeyEncoding.x963Representation(spki = spki)
            }.also { assertEquals(AuthKeyWireError.MalformedP256PublicKey, it, name) }
        assertSame(AuthKeyWireError.MalformedP256PublicKey, error)
    }
}
