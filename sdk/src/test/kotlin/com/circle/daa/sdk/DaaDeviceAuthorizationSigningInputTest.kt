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

import com.circle.daa.sdk.internal.authkey.Base64Url
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.security.MessageDigest
import java.time.Instant

class DaaDeviceAuthorizationSigningInputTest {
    @Test
    fun `accepts the complete social login v1 profile and preserves exact bytes`() {
        val now = Instant.now().epochSecond
        val bytes = signingInput(completePayload(iat = now - 1, exp = now + 299))

        val input = DaaDeviceAuthorizationSigningInput(bytes)

        assertArrayEquals(bytes, input.signingBytesAt(now))
    }

    @Test
    fun `accepts the bodyless get device context v1 profile`() {
        assertTrue(
            DaaDeviceAuthorizationSigningInputValidator.valid(
                signingInput(contextPayload()),
                TEST_NOW,
            ),
        )
    }

    @Test
    fun `accepts all six registry operations with literal paths`() {
        val payloads =
            listOf(
                completePayload(),
                contextPayload(),
                postPayload("create_account", "/v1/accounts"),
                postPayload("transfer", "/v1/accounts/transfers"),
                postPayload("withdrawal", "/v1/accounts/withdrawals"),
                postPayload("register_device_key", "/v1/accounts/auth/deviceKeyRegistration"),
            )

        assertTrue(completePayload().contains("\"canonical_path\":\"/v1/accounts/auth/sessions\""))
        assertTrue(contextPayload().contains("\"canonical_path\":\"/v1/accounts/auth/context\""))
        payloads.forEach { payload ->
            assertTrue(
                DaaDeviceAuthorizationSigningInputValidator.valid(signingInput(payload), TEST_NOW),
                payload,
            )
        }
    }

    @Test
    fun `rejects a social sessions path outside the operation registry`() {
        assertEquals(
            DaaSecureKeyError.InvalidSigningInput,
            DaaDeviceAuthorizationSigningInputValidator.error(
                signingInput(postPayload("complete_social_login", "/v1/accounts/auth/social/sessions")),
                TEST_NOW,
            ),
        )
    }

    @Test
    fun `permits pending registration for enrollment operations`() {
        val now = Instant.now().epochSecond

        assertTrue(
            DaaDeviceAuthorizationSigningInput(
                signingInput(completePayload(iat = now - 1, exp = now + 299)),
            ).permitsPendingRegistration,
        )
        assertTrue(
            DaaDeviceAuthorizationSigningInput(
                signingInput(
                    postPayload(
                        "register_device_key",
                        "/v1/accounts/auth/deviceKeyRegistration",
                        iat = now - 1,
                        exp = now + 299,
                    ),
                ),
            ).permitsPendingRegistration,
        )
        listOf(
            contextPayload(iat = now - 1, exp = now + 299),
            postPayload("create_account", "/v1/accounts", iat = now - 1, exp = now + 299),
            postPayload("transfer", "/v1/accounts/transfers", iat = now - 1, exp = now + 299),
            postPayload("withdrawal", "/v1/accounts/withdrawals", iat = now - 1, exp = now + 299),
        ).forEach { payload ->
            assertFalse(
                DaaDeviceAuthorizationSigningInput(signingInput(payload)).permitsPendingRegistration,
                payload,
            )
        }
    }

    @Test
    fun `rejects malformed compact input at construction`() {
        val error =
            assertThrows(DaaSecureKeyException::class.java) {
                DaaDeviceAuthorizationSigningInput("not-a-jws".toByteArray())
            }

        assertEquals(DaaSecureKeyError.InvalidSigningInput, error.error)
    }

    @Test
    fun `rejects operation substitutions and mismatched operation fields`() {
        val cases =
            listOf(
                completePayload().replace("complete_social_login", "get_device_context"),
                completePayload().replace("/v1/accounts/auth/sessions", "/v1/accounts/auth/context"),
                completePayload().replace("/v1/accounts/auth/sessions", "/v1/accounts/auth/social/sessions"),
                completePayload().replace("\"method\":\"POST\"", "\"method\":\"GET\""),
                completePayload().replace("\"schema_version\":1", "\"schema_version\":2"),
                completePayload().replace("\"schema_version\":1", "\"schema_version\":\"1\""),
                completePayload().replace("\"schema_version\":1", "\"schema_version\":1.5"),
                completePayload().replace("circle-digital-asset-accounts", "circle-wallets"),
                contextPayload().replace("/v1/accounts/auth/context", "/v1/accounts/auth/social/sessions"),
                contextPayload().replace("\"method\":\"GET\"", "\"method\":\"POST\""),
                contextPayload().replace(
                    "\"body_sha256\":\"${emptyBodyDigest()}\"",
                    "\"body_sha256\":\"${Base64Url.encode(ByteArray(32))}\"",
                ),
            )

        cases.forEach { payload ->
            assertEquals(
                DaaSecureKeyError.InvalidSigningInput,
                DaaDeviceAuthorizationSigningInputValidator.error(signingInput(payload), TEST_NOW),
                payload,
            )
        }
    }

    @Test
    fun `requires a UUID idempotency key only for complete social login`() {
        val cases =
            listOf(
                completePayload().replace("\"idempotency_key\":\"$IDEMPOTENCY_KEY\",", ""),
                completePayload().replace(IDEMPOTENCY_KEY, "not-a-uuid"),
                contextPayload().dropLast(1) + ",\"idempotency_key\":\"$IDEMPOTENCY_KEY\"}",
            )

        cases.forEach { payload ->
            assertEquals(
                DaaSecureKeyError.InvalidSigningInput,
                DaaDeviceAuthorizationSigningInputValidator.error(signingInput(payload), TEST_NOW),
                payload,
            )
        }
    }

    @Test
    fun `rejects malformed header unknown claims and expiry`() {
        val cases =
            listOf(
                signingInput(
                    completePayload(),
                    "{\"alg\":\"RS256\",\"kid\":\"key-1\",\"typ\":\"aw-device-authorization+jws\"}",
                ),
                signingInput(
                    completePayload(),
                    "{\"alg\":\"ES256\",\"kid\":\"\",\"typ\":\"aw-device-authorization+jws\"}",
                ),
                signingInput(
                    completePayload(),
                    "{\"alg\":\"ES256\",\"kid\":\"key-1\",\"typ\":\"JWT\"}",
                ),
                signingInput(
                    completePayload(),
                    "{\"alg\":\"ES256\",\"kid\":\"key-1\",\"typ\":\"aw-device-authorization+jws\",\"x\":1}",
                ),
                signingInput(completePayload().dropLast(1) + ",\"unexpected\":true}"),
                signingInput(completePayload(iat = TEST_NOW + 61)),
                signingInput(completePayload(iat = 0)),
                signingInput(completePayload(exp = TEST_NOW + 300)),
            )

        cases.forEach { input ->
            assertEquals(
                DaaSecureKeyError.InvalidSigningInput,
                DaaDeviceAuthorizationSigningInputValidator.error(input, TEST_NOW),
            )
        }
        assertEquals(
            DaaSecureKeyError.SigningInputExpired,
            DaaDeviceAuthorizationSigningInputValidator.error(
                signingInput(completePayload(iat = TEST_NOW - 361, exp = TEST_NOW - 61)),
                TEST_NOW,
            ),
        )
    }

    @Test
    fun `rejects a duplicated top-level key even when the last value alone would validate`() {
        val duplicatedPayloadKey = contextPayload().dropLast(1) + ",\"discriminator\":\"get_device_context\"}"
        val duplicatedHeaderKey =
            signingInput(
                contextPayload(),
                "{\"alg\":\"ES256\",\"kid\":\"key-1\",\"typ\":\"aw-device-authorization+jws\",\"kid\":\"key-1\"}",
            )

        assertEquals(
            DaaSecureKeyError.InvalidSigningInput,
            DaaDeviceAuthorizationSigningInputValidator.error(signingInput(duplicatedPayloadKey), TEST_NOW),
        )
        assertEquals(
            DaaSecureKeyError.InvalidSigningInput,
            DaaDeviceAuthorizationSigningInputValidator.error(duplicatedHeaderKey, TEST_NOW),
        )
    }

    private fun signingInput(
        payload: String,
        header: String = "{\"alg\":\"ES256\",\"kid\":\"key-1\",\"typ\":\"aw-device-authorization+jws\"}",
    ): ByteArray = "${Base64Url.encode(header.toByteArray())}.${Base64Url.encode(payload.toByteArray())}".toByteArray()

    private fun completePayload(
        iat: Long = TEST_NOW - 1,
        exp: Long = TEST_NOW + 299,
    ): String =
        "{\"aud\":\"circle-digital-asset-accounts\",\"body_sha256\":\"${Base64Url.encode(ByteArray(32))}\"," +
            "\"canonical_path\":\"/v1/accounts/auth/sessions\",\"discriminator\":\"complete_social_login\"," +
            "\"exp\":$exp,\"iat\":$iat,\"idempotency_key\":\"$IDEMPOTENCY_KEY\"," +
            "\"jti\":\"$JTI\",\"method\":\"POST\",\"schema_version\":1}"

    private fun postPayload(
        discriminator: String,
        path: String,
        iat: Long = TEST_NOW - 1,
        exp: Long = TEST_NOW + 299,
    ): String =
        "{\"aud\":\"circle-digital-asset-accounts\",\"body_sha256\":\"${Base64Url.encode(ByteArray(32))}\"," +
            "\"canonical_path\":\"$path\",\"discriminator\":\"$discriminator\"," +
            "\"exp\":$exp,\"iat\":$iat,\"idempotency_key\":\"$IDEMPOTENCY_KEY\"," +
            "\"jti\":\"$JTI\",\"method\":\"POST\",\"schema_version\":1}"

    private fun contextPayload(
        iat: Long = TEST_NOW - 1,
        exp: Long = TEST_NOW + 299,
    ): String =
        "{\"aud\":\"circle-digital-asset-accounts\",\"body_sha256\":\"${emptyBodyDigest()}\"," +
            "\"canonical_path\":\"/v1/accounts/auth/context\",\"discriminator\":\"get_device_context\"," +
            "\"exp\":$exp,\"iat\":$iat,\"jti\":\"$JTI\"," +
            "\"method\":\"GET\",\"schema_version\":1}"

    private fun emptyBodyDigest(): String = Base64Url.encode(MessageDigest.getInstance("SHA-256").digest(ByteArray(0)))

    private companion object {
        const val TEST_NOW = 1_700_000_000L
        const val IDEMPOTENCY_KEY = "01234567-89ab-cdef-0123-456789abcdef"
        const val JTI = "fedcba98-7654-3210-fedc-ba9876543210"
    }
}
