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
import com.circle.daa.sdk.internal.authkey.Base64Url
import org.junit.jupiter.api.Assertions.assertDoesNotThrow
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec

class SigningInputAtSignatureTimeTest {
    @Test
    fun `accepts a still-fresh signing input`() {
        assertDoesNotThrow {
            requireValidSigningInputAtSignatureTime(signingInput(iat = TEST_NOW - 1, exp = TEST_NOW + 299), TEST_NOW)
        }
    }

    @Test
    fun `reports an input that expired before signature update`() {
        val expired = signingInput(iat = TEST_NOW - 361, exp = TEST_NOW - 61)
        val error =
            assertThrows(DaaSecureKeyException::class.java) {
                requireValidSigningInputAtSignatureTime(expired, TEST_NOW)
            }
        assertEquals(DaaSecureKeyError.SigningInputExpired, error.error)

        val signatureError =
            assertThrows(DaaSecureKeyException::class.java) {
                signInitializedAt(Signature.getInstance("SHA256withECDSA"), expired, TEST_NOW)
            }
        assertEquals(DaaSecureKeyError.SigningInputExpired, signatureError.error)
    }

    @Test
    fun `signs fresh bytes and maps signature failures`() {
        val message = signingInput(iat = TEST_NOW - 1, exp = TEST_NOW + 299)
        val keyPair =
            KeyPairGenerator.getInstance("EC").run {
                initialize(ECGenParameterSpec("secp256r1"))
                generateKeyPair()
            }
        val signer = Signature.getInstance("SHA256withECDSA").apply { initSign(keyPair.private) }

        val der = signInitializedAt(signer, message, TEST_NOW)

        val verifier = Signature.getInstance("SHA256withECDSA").apply { initVerify(keyPair.public) }
        verifier.update(message)
        assertTrue(verifier.verify(der))

        val error =
            assertThrows(DaaSecureKeyException::class.java) {
                signInitializedAt(Signature.getInstance("SHA256withECDSA"), message, TEST_NOW)
            }
        assertEquals(DaaSecureKeyError.SigningFailed, error.error)
    }

    @Test
    fun `reports malformed signing bytes separately from expiry`() {
        val error =
            assertThrows(DaaSecureKeyException::class.java) {
                requireValidSigningInputAtSignatureTime("not-a-jws".toByteArray(), TEST_NOW)
            }

        assertEquals(DaaSecureKeyError.InvalidSigningInput, error.error)
    }

    private fun signingInput(
        iat: Long,
        exp: Long,
    ): ByteArray {
        val header = """{"alg":"ES256","kid":"key-1","typ":"aw-device-authorization+jws"}"""
        val payload =
            "{\"aud\":\"circle-digital-asset-accounts\",\"body_sha256\":\"${Base64Url.encode(ByteArray(32))}\"," +
                "\"canonical_path\":\"/v1/accounts/auth/sessions\"," +
                "\"discriminator\":\"complete_social_login\"," +
                "\"exp\":$exp,\"iat\":$iat,\"idempotency_key\":\"01234567-89ab-cdef-0123-456789abcdef\"," +
                "\"jti\":\"01234567-89ab-cdef-0123-456789abcdef\",\"method\":\"POST\",\"schema_version\":1}"
        return "${Base64Url.encode(header.toByteArray())}.${Base64Url.encode(payload.toByteArray())}".toByteArray()
    }

    private companion object {
        const val TEST_NOW = 1_700_000_000L
    }
}
