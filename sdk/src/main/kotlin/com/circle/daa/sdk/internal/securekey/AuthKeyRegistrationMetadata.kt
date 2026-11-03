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
import java.security.MessageDigest

/**
 * The server-assigned identifiers recorded with a registration acknowledgement, and the time
 * that acknowledgement was written. Both identifiers are UUID strings, kept exactly as the server
 * issued them: [authKeyId] becomes a JWS `kid` that is compared byte for byte.
 */
internal data class AuthKeyRegistrationRecord(
    val authKeyId: String,
    val ownerBindingId: String,
    val registeredAtEpochMillis: Long,
) {
    init {
        require(isRegistrationId(authKeyId) && isRegistrationId(ownerBindingId) && registeredAtEpochMillis >= 0)
    }

    internal companion object {
        private val UUID_PATTERN =
            Regex("[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}")

        /**
         * Whether [value] is a 36-character hyphenated UUID string: the only identifier shape
         * recorded here. Either letter case is accepted and kept.
         */
        fun isRegistrationId(value: String): Boolean = UUID_PATTERN.matches(value)
    }
}

/**
 * Durable local record, bound to one public key, written after enrollment succeeds.
 *
 * Two versions exist, and both read as "acknowledged":
 *
 * - `v1:registration:registered:<binding>` -- the legacy acknowledgement, carrying no
 *   identifiers. `binding` is the authenticator over the key's RFC 7638 thumbprint alone.
 * - `v2:registration:registered:<authKeyId>:<ownerBindingId>:<registeredAtEpochMillis>:<binding>`
 *   -- carries the server-assigned identifiers. `binding` authenticates the thumbprint *and* every
 *   other field (see [registrationBindingInput]), so an identifier cannot be swapped without
 *   failing the check, and a record copied from another key fails it the same way a `v1` one does.
 *
 * This is a plain string in private no-backup app storage: anything able to write app-private
 * storage can write an arbitrary value here. What makes a forged value fail [decode] is the
 * binding itself: callers pass an authenticator ([mac]) backed by a dedicated, non-exportable
 * Android Keystore key (see [registrationMac] in `AndroidAuthKeyBackend`), so producing a matching
 * field requires an actual Keystore Sign operation this object never performs. The comparison
 * below is constant-time so that property is not undermined by a length- or prefix-dependent
 * timing difference in the check itself.
 */
internal object AuthKeyRegistrationMetadata {
    private const val LEGACY_VERSION = "v1"
    private const val VERSION = "v2"
    private val VERSION_PATTERN = Regex("v[0-9]+")
    private val KEY_BINDING_PATTERN = Regex("[A-Za-z0-9_-]{43}")
    private val EPOCH_MILLIS_PATTERN = Regex("0|[1-9][0-9]{0,18}")

    /** The legacy marker, which records an acknowledgement but no identifiers. */
    fun encode(
        thumbprint: String,
        mac: (String) -> String,
    ): String = "$LEGACY_VERSION:registration:registered:${requireBinding(mac(thumbprint))}"

    /** The current marker, which records [record] alongside the acknowledgement. */
    fun encode(
        record: AuthKeyRegistrationRecord,
        thumbprint: String,
        mac: (String) -> String,
    ): String {
        val binding = requireBinding(mac(registrationBindingInput(thumbprint, record)))
        return "$VERSION:registration:registered:${record.authKeyId}:${record.ownerBindingId}:" +
            "${record.registeredAtEpochMillis}:$binding"
    }

    /**
     * Validates [value] against the key whose thumbprint is [thumbprint] and returns the recorded
     * identifiers, or `null` for a valid legacy marker that recorded none. Anything that is not a
     * valid marker for this exact key throws: [DaaSecureKeyError.KeyMetadataVersionUnsupported]
     * for a version this SDK does not know, [DaaSecureKeyError.KeyMetadataUnavailable] otherwise.
     */
    fun decode(
        value: Any?,
        thumbprint: String,
        mac: (String) -> String,
    ): AuthKeyRegistrationRecord? {
        val text = value as? String ?: throw metadataUnavailable()
        val fields = text.split(':')
        val version = fields.firstOrNull()
        if (version != LEGACY_VERSION && version != VERSION && version?.matches(VERSION_PATTERN) == true) {
            throw DaaSecureKeyException(DaaSecureKeyError.KeyMetadataVersionUnsupported)
        }
        if (fields.size < 4 || fields[1] != "registration" || fields[2] != "registered") {
            throw metadataUnavailable()
        }
        return when (version) {
            LEGACY_VERSION -> {
                if (fields.size != 4) throw metadataUnavailable()
                requireBound(fields[3]) { mac(thumbprint) }
                null
            }
            VERSION -> {
                if (fields.size != 7 || !EPOCH_MILLIS_PATTERN.matches(fields[5]) ||
                    !AuthKeyRegistrationRecord.isRegistrationId(fields[3]) ||
                    !AuthKeyRegistrationRecord.isRegistrationId(fields[4])
                ) {
                    throw metadataUnavailable()
                }
                val registeredAt = fields[5].toLongOrNull() ?: throw metadataUnavailable()
                val record = AuthKeyRegistrationRecord(fields[3], fields[4], registeredAt)
                requireBound(fields[6]) { mac(registrationBindingInput(thumbprint, record)) }
                record
            }
            else -> throw metadataUnavailable()
        }
    }

    /**
     * What a `v2` binding authenticates. Prefixed with the version so it can never equal a `v1`
     * input (a bare 43-character thumbprint), and colon-separated over fields that cannot contain
     * a colon, so no two distinct records share an input.
     */
    private fun registrationBindingInput(
        thumbprint: String,
        record: AuthKeyRegistrationRecord,
    ): String =
        "$VERSION:registration:$thumbprint:${record.authKeyId}:${record.ownerBindingId}:" +
            "${record.registeredAtEpochMillis}"

    private fun requireBinding(binding: String): String {
        require(KEY_BINDING_PATTERN.matches(binding))
        return binding
    }

    private inline fun requireBound(
        stored: String,
        expected: () -> String,
    ) {
        if (!KEY_BINDING_PATTERN.matches(stored) ||
            !MessageDigest.isEqual(
                stored.toByteArray(Charsets.US_ASCII),
                expected().toByteArray(Charsets.US_ASCII),
            )
        ) {
            throw metadataUnavailable()
        }
    }

    private fun metadataUnavailable() = DaaSecureKeyException(DaaSecureKeyError.KeyMetadataUnavailable)
}
