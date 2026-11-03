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
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import java.security.MessageDigest

class AuthKeyRegistrationMetadataTest {
    private val thumbprint = "A".repeat(43)
    private val otherThumbprint = "B".repeat(43)
    private val record =
        AuthKeyRegistrationRecord(
            authKeyId = "0f6a3c1e-8b2d-4e5f-9a7b-1c2d3e4f5a6b",
            ownerBindingId = "7d9e8f10-2a3b-4c5d-8e9f-a0b1c2d3e4f5",
            registeredAtEpochMillis = 1_767_225_600_000,
        )

    /** Stands in for the Keystore HMAC: a keyed digest the test can compute but a forger cannot. */
    private fun mac(input: String): String = keyedDigest("device-secret", input)

    private fun keyedDigest(
        secret: String,
        input: String,
    ): String = Base64Url.encode(MessageDigest.getInstance("SHA-256").digest("$secret:$input".toByteArray()))

    @Test
    fun `round trips a legacy marker bound to the exact key as an acknowledgement without identifiers`() {
        val marker = AuthKeyRegistrationMetadata.encode(thumbprint, ::mac)

        assertEquals("v1:registration:registered:${mac(thumbprint)}", marker)
        assertNull(AuthKeyRegistrationMetadata.decode(marker, thumbprint, ::mac))
    }

    @Test
    fun `round trips a marker carrying the registration identifiers`() {
        val marker = AuthKeyRegistrationMetadata.encode(record, thumbprint, ::mac)

        assertEquals(record, AuthKeyRegistrationMetadata.decode(marker, thumbprint, ::mac))
    }

    @Test
    fun `keeps the identifiers exactly as Circle issued them`() {
        val upperCase = record.copy(authKeyId = record.authKeyId.uppercase())
        val marker = AuthKeyRegistrationMetadata.encode(upperCase, thumbprint, ::mac)

        assertEquals(upperCase, AuthKeyRegistrationMetadata.decode(marker, thumbprint, ::mac))
    }

    @Test
    fun `rejects missing malformed and mismatched markers`() {
        val values =
            listOf(
                null,
                1,
                "",
                "registered",
                "v1:registration:pending:${mac(thumbprint)}",
                "v1:registration:registered:short",
                "v1:registration:registered:${mac(thumbprint)}:extra",
                // Bound to another key.
                AuthKeyRegistrationMetadata.encode(otherThumbprint, ::mac),
                AuthKeyRegistrationMetadata.encode(record, otherThumbprint, ::mac),
                // Forged without the device's authenticator key.
                AuthKeyRegistrationMetadata.encode(thumbprint) { keyedDigest("forger", it) },
                AuthKeyRegistrationMetadata.encode(record, thumbprint) { keyedDigest("forger", it) },
                // A bare thumbprint, without the keyed MAC, is not a binding.
                "v1:registration:registered:$thumbprint",
            )

        values.forEach { value ->
            val error =
                assertThrows(DaaSecureKeyException::class.java) {
                    AuthKeyRegistrationMetadata.decode(value, thumbprint, ::mac)
                }
            assertEquals(DaaSecureKeyError.KeyMetadataUnavailable, error.error, "$value")
        }
    }

    @Test
    fun `rejects identifiers or a time edited after the marker was written`() {
        val marker = AuthKeyRegistrationMetadata.encode(record, thumbprint, ::mac)
        val edited =
            listOf(
                marker.replace(record.authKeyId, "11111111-2222-4333-8444-555555555555"),
                marker.replace(record.ownerBindingId, "11111111-2222-4333-8444-555555555555"),
                marker.replace(":${record.registeredAtEpochMillis}:", ":${record.registeredAtEpochMillis + 1}:"),
                // Swapping the two identifiers keeps every field well formed.
                marker.replace(record.authKeyId, "#").replace(record.ownerBindingId, record.authKeyId)
                    .replace("#", record.ownerBindingId),
                // A legacy binding on a marker that claims identifiers.
                "v2:registration:registered:${record.authKeyId}:${record.ownerBindingId}:" +
                    "${record.registeredAtEpochMillis}:${mac(thumbprint)}",
            )

        edited.forEach { value ->
            val error =
                assertThrows(DaaSecureKeyException::class.java) {
                    AuthKeyRegistrationMetadata.decode(value, thumbprint, ::mac)
                }
            assertEquals(DaaSecureKeyError.KeyMetadataUnavailable, error.error, value)
        }
    }

    @Test
    fun `rejects a marker whose identifier fields are not well formed`() {
        val binding = mac(thumbprint)
        val values =
            listOf(
                "v2:registration:registered:not-a-uuid:${record.ownerBindingId}:1:$binding",
                "v2:registration:registered:${record.authKeyId}:not-a-uuid:1:$binding",
                "v2:registration:registered:${record.authKeyId}:${record.ownerBindingId}:-1:$binding",
                "v2:registration:registered:${record.authKeyId}:${record.ownerBindingId}:01:$binding",
                "v2:registration:registered:${record.authKeyId}:${record.ownerBindingId}:99999999999999999999:$binding",
                "v2:registration:registered:${record.authKeyId}:${record.ownerBindingId}:$binding",
                "v2:registration:registered:$binding",
            )

        values.forEach { value ->
            val error =
                assertThrows(DaaSecureKeyException::class.java) {
                    AuthKeyRegistrationMetadata.decode(value, thumbprint, ::mac)
                }
            assertEquals(DaaSecureKeyError.KeyMetadataUnavailable, error.error, value)
        }
    }

    @Test
    fun `distinguishes a future metadata version from malformed metadata`() {
        val error =
            assertThrows(DaaSecureKeyException::class.java) {
                AuthKeyRegistrationMetadata.decode("v3:registration:registered:${mac(thumbprint)}", thumbprint, ::mac)
            }

        assertEquals(DaaSecureKeyError.KeyMetadataVersionUnsupported, error.error)
    }

    @Test
    fun `a record holds only UUID identifiers and a non-negative time`() {
        listOf(
            { record.copy(authKeyId = "") },
            { record.copy(authKeyId = "0f6a3c1e8b2d4e5f9a7b1c2d3e4f5a6b") },
            { record.copy(ownerBindingId = "${record.ownerBindingId}:x") },
            { record.copy(ownerBindingId = " ${record.ownerBindingId}") },
            { record.copy(registeredAtEpochMillis = -1) },
        ).forEach { build ->
            assertThrows(IllegalArgumentException::class.java) { build() }
        }
    }
}
