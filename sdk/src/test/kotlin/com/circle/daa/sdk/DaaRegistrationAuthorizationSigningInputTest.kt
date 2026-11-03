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
import com.circle.daa.sdk.internal.authkey.Base64Url
import com.circle.daa.sdk.internal.authkey.TestP256Jwk
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.time.Instant

class DaaRegistrationAuthorizationSigningInputTest {
    @Test
    fun `accepts both registration typs and preserves exact bytes`() {
        val now = Instant.now().epochSecond
        val flowBytes = signingInput(flowPayload(iat = now - 1, exp = now + 299), flowHeader())
        val deviceBytes = signingInput(devicePayload(iat = now - 1, exp = now + 299), deviceHeader())

        assertArrayEquals(flowBytes, DaaRegistrationAuthorizationSigningInput(flowBytes).signingBytesAt(now))
        assertArrayEquals(deviceBytes, DaaRegistrationAuthorizationSigningInput(deviceBytes).signingBytesAt(now))
        assertTrue(
            DaaRegistrationAuthorizationSigningInputValidator.valid(
                signingInput(flowPayload(), flowHeader()),
                TEST_NOW,
            ),
        )
        assertTrue(
            DaaRegistrationAuthorizationSigningInputValidator.valid(
                signingInput(devicePayload(), deviceHeader()),
                TEST_NOW,
            ),
        )
    }

    @Test
    fun `signingBytes for one typ rejects the other`() {
        val now = Instant.now().epochSecond
        val flow =
            DaaRegistrationAuthorizationSigningInput(
                signingInput(flowPayload(iat = now - 1, exp = now + 299), flowHeader()),
            )
        val device =
            DaaRegistrationAuthorizationSigningInput(
                signingInput(devicePayload(iat = now - 1, exp = now + 299), deviceHeader()),
            )

        assertEquals(
            DaaSecureKeyError.InvalidSigningInput,
            assertThrows(DaaSecureKeyException::class.java) {
                flow.signingBytes(DaaRegistrationAuthorizationSigningInputValidator.DEVICE_TYP)
            }.error,
        )
        assertEquals(
            DaaSecureKeyError.InvalidSigningInput,
            assertThrows(DaaSecureKeyException::class.java) {
                device.signingBytes(DaaRegistrationAuthorizationSigningInputValidator.FLOW_TYP)
            }.error,
        )
        assertArrayEquals(
            flow.signingBytes(),
            flow.signingBytes(DaaRegistrationAuthorizationSigningInputValidator.FLOW_TYP),
        )
        assertArrayEquals(
            device.signingBytes(),
            device.signingBytes(DaaRegistrationAuthorizationSigningInputValidator.DEVICE_TYP),
        )
    }

    @Test
    fun `binds the literal device key registration path`() {
        val payload = flowPayload()

        assertTrue(payload.contains("\"canonical_path\":\"/v1/accounts/auth/deviceKeyRegistration\""))
        assertTrue(
            DaaRegistrationAuthorizationSigningInputValidator.valid(
                signingInput(payload, flowHeader()),
                TEST_NOW,
            ),
        )
    }

    @Test
    fun `rejects kid present wrong path extra claim and unknown typ`() {
        val cases =
            listOf(
                signingInput(flowPayload(), headerWithKid()),
                signingInput(
                    flowPayload().replace(
                        "/v1/accounts/auth/deviceKeyRegistration",
                        "/v1/accounts/auth/sessions",
                    ),
                    flowHeader(),
                ),
                signingInput(flowPayload().dropLast(1) + ",\"unexpected\":true}", flowHeader()),
                signingInput(devicePayload().dropLast(1) + ",\"unexpected\":true}", deviceHeader()),
                signingInput(
                    flowPayload(),
                    """{"alg":"ES256","typ":"aw-device-authorization+jws","jwk":$EMBEDDED_JWK}""",
                ),
            )

        cases.forEach { input ->
            assertEquals(
                DaaSecureKeyError.InvalidSigningInput,
                DaaRegistrationAuthorizationSigningInputValidator.error(input, TEST_NOW),
                String(input),
            )
        }
    }

    @Test
    fun `accepts a device payload with exactly the ten request-binding claims`() {
        val payload = devicePayload()

        assertEquals(DEVICE_CLAIMS, claimNames(payload))
        assertTrue(
            DaaRegistrationAuthorizationSigningInputValidator.valid(signingInput(payload, deviceHeader()), TEST_NOW),
        )
    }

    @Test
    fun `rejects a device payload carrying any registration-binding claim`() {
        val inputs =
            REGISTRATION_BINDING_CLAIMS.map { claim ->
                claim to signingInput(payload(flowClaims().filterKeys { it in DEVICE_CLAIMS + claim }), deviceHeader())
            } + ("all four" to signingInput(flowPayload(), deviceHeader()))

        inputs.forEach { (label, input) ->
            assertEquals(
                DaaSecureKeyError.InvalidSigningInput,
                DaaRegistrationAuthorizationSigningInputValidator.error(input, TEST_NOW),
                label,
            )
        }
    }

    @Test
    fun `requires the full fourteen claims on the flow payload`() {
        assertEquals(DEVICE_CLAIMS + REGISTRATION_BINDING_CLAIMS, claimNames(flowPayload()))
        assertTrue(
            DaaRegistrationAuthorizationSigningInputValidator.valid(
                signingInput(flowPayload(), flowHeader()),
                TEST_NOW,
            ),
        )

        val inputs =
            REGISTRATION_BINDING_CLAIMS.map { claim ->
                "without $claim" to signingInput(payload(flowClaims() - claim), flowHeader())
            } + ("device claim set" to signingInput(devicePayload(), flowHeader()))

        inputs.forEach { (label, input) ->
            assertEquals(
                DaaSecureKeyError.InvalidSigningInput,
                DaaRegistrationAuthorizationSigningInputValidator.error(input, TEST_NOW),
                label,
            )
        }
    }

    @Test
    fun `still validates the shape of the flow payload's registration-binding claims`() {
        val shortDigest = "\"${Base64Url.encode(ByteArray(31))}\""
        val cases =
            listOf(
                "registration_handle_sha256" to shortDigest,
                "code_verifier_sha256" to shortDigest,
                "auth_key_thumbprint" to shortDigest,
                "profile_id" to "\"\"",
            )

        cases.forEach { (claim, value) ->
            assertEquals(
                DaaSecureKeyError.InvalidSigningInput,
                DaaRegistrationAuthorizationSigningInputValidator.error(
                    signingInput(payload(flowClaims() + (claim to value)), flowHeader()),
                    TEST_NOW,
                ),
                claim,
            )
        }
    }

    @Test
    fun `retains the RFC 7638 thumbprint of the embedded header jwk for both typs`() {
        val expected = AuthKeyWireFixture.load().p256PublicKey.jwkThumbprint
        val now = Instant.now().epochSecond

        assertEquals(
            expected,
            DaaRegistrationAuthorizationSigningInput(
                signingInput(devicePayload(iat = now - 1, exp = now + 299), deviceHeader()),
            ).headerJwkThumbprint,
        )
        assertEquals(
            expected,
            DaaRegistrationAuthorizationSigningInput(
                signingInput(flowPayload(iat = now - 1, exp = now + 299), flowHeader()),
            ).headerJwkThumbprint,
        )
    }

    @Test
    fun `rejects a duplicated top-level key even when the last value alone would validate`() {
        val duplicatedPayloadKey =
            flowPayload().dropLast(1) + ",\"profile_id\":\"$PROFILE_ID\"}"
        val duplicatedHeaderKey =
            signingInput(
                flowPayload(),
                """{"alg":"ES256","typ":"daa-registration-flow-authorization+jws","jwk":$EMBEDDED_JWK,""" +
                    """"typ":"daa-registration-flow-authorization+jws"}""",
            )

        assertEquals(
            DaaSecureKeyError.InvalidSigningInput,
            DaaRegistrationAuthorizationSigningInputValidator.error(
                signingInput(duplicatedPayloadKey, flowHeader()),
                TEST_NOW,
            ),
        )
        assertEquals(
            DaaSecureKeyError.InvalidSigningInput,
            DaaRegistrationAuthorizationSigningInputValidator.error(duplicatedHeaderKey, TEST_NOW),
        )
    }

    @Test
    fun `rejects an embedded JWK whose point is not on P-256`() {
        val offCurveY = Base64Url.encode(ByteArray(32) { 2 })
        val header =
            """{"alg":"ES256","typ":"daa-registration-flow-authorization+jws",""" +
                """"jwk":{"kty":"EC","crv":"P-256","x":"$JWK_X","y":"$offCurveY"}}"""

        assertEquals(
            DaaSecureKeyError.InvalidSigningInput,
            DaaRegistrationAuthorizationSigningInputValidator.error(
                signingInput(flowPayload(), header),
                TEST_NOW,
            ),
        )
    }

    @Test
    fun `rejects an embedded JWK coordinate outside the field`() {
        val outOfField = Base64Url.encode(ByteArray(32) { 0xFF.toByte() })
        val header =
            """{"alg":"ES256","typ":"daa-device-authorization+jws",""" +
                """"jwk":{"kty":"EC","crv":"P-256","x":"$outOfField","y":"$JWK_Y"}}"""

        assertEquals(
            DaaSecureKeyError.InvalidSigningInput,
            DaaRegistrationAuthorizationSigningInputValidator.error(
                signingInput(devicePayload(), header),
                TEST_NOW,
            ),
        )
    }

    @Test
    fun `rejects malformed compact input at construction`() {
        val error =
            assertThrows(DaaSecureKeyException::class.java) {
                DaaRegistrationAuthorizationSigningInput("not-a-jws".toByteArray())
            }

        assertEquals(DaaSecureKeyError.InvalidSigningInput, error.error)
    }

    @Test
    fun `rejects expired registration input`() {
        assertEquals(
            DaaSecureKeyError.SigningInputExpired,
            DaaRegistrationAuthorizationSigningInputValidator.error(
                signingInput(flowPayload(iat = TEST_NOW - 361, exp = TEST_NOW - 61), flowHeader()),
                TEST_NOW,
            ),
        )
    }

    private fun signingInput(
        payload: String,
        header: String,
    ): ByteArray = "${Base64Url.encode(header.toByteArray())}.${Base64Url.encode(payload.toByteArray())}".toByteArray()

    private fun flowHeader(): String =
        """{"alg":"ES256","typ":"daa-registration-flow-authorization+jws","jwk":$EMBEDDED_JWK}"""

    private fun deviceHeader(): String = """{"alg":"ES256","typ":"daa-device-authorization+jws","jwk":$EMBEDDED_JWK}"""

    private fun headerWithKid(): String =
        """{"alg":"ES256","kid":"key-1","typ":"daa-registration-flow-authorization+jws","jwk":$EMBEDDED_JWK}"""

    /** The full fourteen-claim registration-flow payload. */
    private fun flowPayload(
        iat: Long = TEST_NOW - 1,
        exp: Long = TEST_NOW + 299,
    ): String = payload(flowClaims(iat, exp))

    /** The ten-claim device payload: request binding only. */
    private fun devicePayload(
        iat: Long = TEST_NOW - 1,
        exp: Long = TEST_NOW + 299,
    ): String = payload(flowClaims(iat, exp).filterKeys { it in DEVICE_CLAIMS })

    /** Claim name to raw JSON value, in a stable order. */
    private fun flowClaims(
        iat: Long = TEST_NOW - 1,
        exp: Long = TEST_NOW + 299,
    ): Map<String, String> =
        linkedMapOf(
            "aud" to "\"circle-digital-asset-accounts\"",
            "auth_key_thumbprint" to "\"$DIGEST32\"",
            "body_sha256" to "\"$DIGEST32\"",
            "canonical_path" to "\"/v1/accounts/auth/deviceKeyRegistration\"",
            "code_verifier_sha256" to "\"$DIGEST32\"",
            "discriminator" to "\"device_key_registration.v1\"",
            "exp" to "$exp",
            "iat" to "$iat",
            "idempotency_key" to "\"$IDEMPOTENCY_KEY\"",
            "jti" to "\"$JTI\"",
            "method" to "\"POST\"",
            "profile_id" to "\"$PROFILE_ID\"",
            "registration_handle_sha256" to "\"$DIGEST32\"",
            "schema_version" to "1",
        )

    private fun payload(claims: Map<String, String>): String =
        claims.entries.joinToString(separator = ",", prefix = "{", postfix = "}") { (name, value) ->
            "\"$name\":$value"
        }

    private fun claimNames(payload: String): Set<String> = Json.parseToJsonElement(payload).jsonObject.keys

    private companion object {
        const val TEST_NOW = 1_700_000_000L
        const val IDEMPOTENCY_KEY = "01234567-89ab-cdef-0123-456789abcdef"
        const val JTI = "fedcba98-7654-3210-fedc-ba9876543210"
        const val PROFILE_ID = "profile-1"
        val DIGEST32: String = Base64Url.encode(ByteArray(32))
        val JWK_X: String = TestP256Jwk.X
        val JWK_Y: String = TestP256Jwk.Y
        val EMBEDDED_JWK: String = """{"kty":"EC","crv":"P-256","x":"$JWK_X","y":"$JWK_Y"}"""
        val DEVICE_CLAIMS: Set<String> =
            setOf(
                "discriminator",
                "schema_version",
                "aud",
                "method",
                "canonical_path",
                "body_sha256",
                "idempotency_key",
                "jti",
                "iat",
                "exp",
            )
        val REGISTRATION_BINDING_CLAIMS: Set<String> =
            setOf("registration_handle_sha256", "profile_id", "auth_key_thumbprint", "code_verifier_sha256")
    }
}
