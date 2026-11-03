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
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class RestorableRegistrationTest {
    private val spki = ByteArray(91) { 7 }
    private val recorded = "v2:${AuthKeyProtectionMode.UserPresence.name}"

    private var validated = false

    private fun restore(
        protectionRecord: () -> Any? = { recorded },
        validateExisting: (AuthKeyProtectionMode) -> Unit = { validated = true },
        marker: () -> String? = { "marker" },
        certificate: () -> ByteArray = { spki },
        decode: (String, ByteArray) -> String? = { _, _ -> "restored" },
    ): String? = restorableRegistration(protectionRecord, validateExisting, marker, certificate, decode)

    @Test
    fun `restores a registration whose metadata is present and trusted`() {
        assertEquals("restored", restore())
    }

    @Test
    fun `a missing protection record means nothing to restore`() {
        assertNull(restore(protectionRecord = { null }))
        assertFalse(validated)
    }

    @Test
    fun `an unparsable protection record means nothing to restore`() {
        listOf("", "v1:UserPresence", "v2:Unknown", "v3:UserPresence", 7).forEach { record ->
            assertNull(restore(protectionRecord = { record }), "$record")
        }
        assertFalse(validated)
    }

    @Test
    fun `a failure to read the metadata throws KeyAccessFailed rather than reading as nothing`() {
        val readFailure = IllegalStateException("Unable to read AuthKey metadata")
        listOf<() -> String?>(
            { restore(protectionRecord = { throw readFailure }) },
            { restore(marker = { throw readFailure }) },
        ).forEach { read ->
            val error = assertThrows(DaaSecureKeyException::class.java) { read() }
            assertEquals(DaaSecureKeyError.KeyAccessFailed, error.error)
            assertSame(readFailure, error.cause)
        }
    }

    @Test
    fun `an HMAC failure while checking the marker throws KeyAccessFailed`() {
        val error =
            assertThrows(DaaSecureKeyException::class.java) {
                restore(decode = { _, _ -> throw IllegalStateException("Mac unavailable") })
            }
        assertEquals(DaaSecureKeyError.KeyAccessFailed, error.error)
    }

    @Test
    fun `existing-key validation failures still throw`() {
        listOf(
            DaaSecureKeyError.ProtectionMismatch,
            DaaSecureKeyError.SecureHardwareUnavailable,
            DaaSecureKeyError.KeyAccessFailed,
        ).forEach { expected ->
            val failure = DaaSecureKeyException(expected)
            val thrown =
                assertThrows(DaaSecureKeyException::class.java) {
                    restore(validateExisting = { throw failure })
                }
            assertSame(failure, thrown)
        }
    }

    @Test
    fun `a certificate that cannot be read still throws`() {
        val failure = DaaSecureKeyException(DaaSecureKeyError.KeyMetadataUnavailable)
        val thrown = assertThrows(DaaSecureKeyException::class.java) { restore(certificate = { throw failure }) }
        assertSame(failure, thrown)
    }

    @Test
    fun `no acknowledgement and an untrusted acknowledgement both mean nothing to restore`() {
        assertNull(restore(marker = { null }))
        listOf(DaaSecureKeyError.KeyMetadataUnavailable, DaaSecureKeyError.KeyMetadataVersionUnsupported).forEach {
            assertNull(restore(decode = { _, _ -> throw DaaSecureKeyException(it) }))
        }
        // A legacy acknowledgement, which records no identifiers, decodes to no registration.
        assertNull(restore(decode = { _, _ -> null }))
    }

    @Test
    fun `resolution still reports a missing or unparsable protection record as KeyMetadataUnavailable`() {
        // The other half of the shared rule: the paths that act on an existing key -- resolveOrCreate,
        // the registration-state read, acknowledgement -- fail closed on the same record that restore
        // reports as nothing to restore, and never re-mint the key for it.
        listOf<Any?>(null, "", "v1:UserPresence", "v3:UserPresence").forEach { record ->
            val error = assertThrows(DaaSecureKeyException::class.java) { requireRecordedProtection(record) }
            assertEquals(DaaSecureKeyError.KeyMetadataUnavailable, error.error, "$record")
        }
        assertEquals(AuthKeyProtectionMode.UserPresence, requireRecordedProtection(recorded))
        assertEquals(
            AuthKeyProtectionMode.DeviceUnlocked,
            requireRecordedProtection("v2:${AuthKeyProtectionMode.DeviceUnlocked.name}"),
        )
    }
}
