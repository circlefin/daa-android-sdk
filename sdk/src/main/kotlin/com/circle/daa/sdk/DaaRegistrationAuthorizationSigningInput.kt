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

import com.circle.daa.sdk.internal.EpochSeconds
import com.circle.daa.sdk.internal.authkey.AuthKeyWireError
import com.circle.daa.sdk.internal.authkey.Base64Url
import com.circle.daa.sdk.internal.authkey.DuplicateJsonKeys
import com.circle.daa.sdk.internal.authkey.P256PublicKeyEncoding
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.longOrNull
import java.util.UUID

/**
 * Validated exact bytes for a Device Registration Complete compact-JWS input.
 *
 * Sibling of [DaaDeviceAuthorizationSigningInput]. The protected header embeds
 * the signer's public JWK rather than a trusted-server `kid`, because Complete
 * runs before Circle has registered the AuthKey. Construction validates; it
 * does not re-encode.
 *
 * Complete carries two proofs over one request, and the header `typ` decides
 * which payload claim set is required, exactly:
 *
 * - The registration-flow proof (`daa-registration-flow-authorization+jws`)
 *   carries the full set: the ten request-binding claims plus the four
 *   registration-binding claims `registration_handle_sha256`, `profile_id`,
 *   `auth_key_thumbprint`, and `code_verifier_sha256`.
 * - The device proof (`daa-device-authorization+jws`) proves possession of the
 *   AuthKey only, so it carries just the ten request-binding claims. Any of the
 *   four registration-binding claims in a device payload is rejected, because
 *   Circle decodes that payload strictly and refuses unknown fields.
 *
 * This type validates the embedded header `jwk` (shape and on-curve point), but
 * it cannot prove the `jwk` belongs to any particular key: that needs the
 * actual signer, which this type does not have. [headerJwkThumbprint] below
 * retains the RFC 7638 thumbprint of the validated `jwk` so
 * [DaaSecureKey.signRegistrationDeviceAuthorization] can compare it against its
 * own key's `thumbprint()` before signing, the same way
 * [DaaDeviceAuthorizationSigningInput.operation] retains the validated operation
 * for a signing-time gate rather than being re-parsed there.
 */
public class DaaRegistrationAuthorizationSigningInput(exactBytes: ByteArray) {
    private val exactBytes: ByteArray = exactBytes.copyOf()

    /**
     * The RFC 7638 thumbprint of the embedded header `jwk`, computed from the
     * validated coordinates. Validated at construction for shape, not for
     * ownership. See the type-level doc comment above. Read from the single
     * validation pass below and never re-parsed.
     */
    internal val headerJwkThumbprint: String

    init {
        when (
            val validation =
                DaaRegistrationAuthorizationSigningInputValidator.validate(
                    this.exactBytes,
                    EpochSeconds.now(),
                )
        ) {
            is DaaRegistrationAuthorizationValidation.Accepted -> headerJwkThumbprint = validation.headerJwkThumbprint
            is DaaRegistrationAuthorizationValidation.Rejected -> throw DaaSecureKeyException(validation.error)
        }
    }

    internal fun signingBytes(): ByteArray = signingBytesAt(EpochSeconds.now())

    internal fun signingBytesAt(nowEpochSeconds: Long): ByteArray =
        revalidatedBytes(expectedTyp = null, nowEpochSeconds)

    /**
     * Re-validate and return the exact bytes only if the header `typ` matches
     * [expectedTyp]. Each signer owns one `typ`; a mismatch is
     * [DaaSecureKeyError.InvalidSigningInput], not a successful sign.
     */
    internal fun signingBytes(expectedTyp: String): ByteArray = signingBytesAt(expectedTyp, EpochSeconds.now())

    internal fun signingBytesAt(
        expectedTyp: String,
        nowEpochSeconds: Long,
    ): ByteArray = revalidatedBytes(expectedTyp, nowEpochSeconds)

    private fun revalidatedBytes(
        expectedTyp: String?,
        nowEpochSeconds: Long,
    ): ByteArray =
        exactBytes.copyOf().also { bytes ->
            when (
                val result =
                    DaaRegistrationAuthorizationSigningInputValidator.validate(bytes, nowEpochSeconds)
            ) {
                is DaaRegistrationAuthorizationValidation.Accepted -> {
                    if (expectedTyp != null && result.typ != expectedTyp) {
                        throw DaaSecureKeyException(DaaSecureKeyError.InvalidSigningInput)
                    }
                }
                is DaaRegistrationAuthorizationValidation.Rejected ->
                    throw DaaSecureKeyException(result.error)
            }
        }
}

/**
 * Result of one validation pass: the accepted registration `typ` and the RFC 7638
 * thumbprint of the embedded header `jwk` (validated for shape only, see
 * [DaaRegistrationAuthorizationSigningInput]'s type-level doc comment), or the
 * first rejection.
 */
internal sealed interface DaaRegistrationAuthorizationValidation {
    data class Accepted(val typ: String, val headerJwkThumbprint: String) : DaaRegistrationAuthorizationValidation

    data class Rejected(val error: DaaSecureKeyError) : DaaRegistrationAuthorizationValidation
}

internal object DaaRegistrationAuthorizationSigningInputValidator {
    private val json = Json { isLenient = false }
    private val headerKeys = setOf("alg", "jwk", "typ")
    private val jwkKeys = setOf("crv", "kty", "x", "y")

    // The request-binding claims both proofs carry. This is the device proof's
    // whole payload: it proves AuthKey possession and nothing else.
    private val devicePayloadKeys =
        setOf(
            "aud",
            "body_sha256",
            "canonical_path",
            "discriminator",
            "exp",
            "iat",
            "idempotency_key",
            "jti",
            "method",
            "schema_version",
        )

    // Only the registration-flow proof binds the request to the registration
    // attempt, the profile, and the AuthKey being registered.
    private val registrationBindingKeys =
        setOf(
            "auth_key_thumbprint",
            "code_verifier_sha256",
            "profile_id",
            "registration_handle_sha256",
        )
    private val flowPayloadKeys = devicePayloadKeys + registrationBindingKeys
    private const val MAXIMUM_AUTHORIZATION_LIFETIME = 300L
    private const val CLOCK_SKEW_LEEWAY = 60L
    internal const val FLOW_TYP: String = "daa-registration-flow-authorization+jws"
    internal const val DEVICE_TYP: String = "daa-device-authorization+jws"
    private const val AUDIENCE = "circle-digital-asset-accounts"
    private const val DEVICE_KEY_REGISTRATION_PATH = "/v1/accounts/auth/deviceKeyRegistration"
    private const val EXPECTED_DISCRIMINATOR = "device_key_registration.v1"
    private const val EXPECTED_SCHEMA_VERSION = 1L
    private const val UNCOMPRESSED_POINT_MARKER: Byte = 0x04

    internal fun valid(
        input: ByteArray,
        nowEpochSeconds: Long,
    ): Boolean = error(input, nowEpochSeconds) == null

    internal fun error(
        input: ByteArray,
        nowEpochSeconds: Long,
    ): DaaSecureKeyError? =
        when (val result = validate(input, nowEpochSeconds)) {
            is DaaRegistrationAuthorizationValidation.Accepted -> null
            is DaaRegistrationAuthorizationValidation.Rejected -> result.error
        }

    internal fun validate(
        input: ByteArray,
        nowEpochSeconds: Long,
    ): DaaRegistrationAuthorizationValidation {
        val text = input.toString(Charsets.UTF_8)
        if (!text.toByteArray().contentEquals(input)) return malformed()
        val parts = text.split('.')
        if (parts.size != 2) return malformed()
        val header = objectOf(parts[0]) ?: return malformed()
        val payload = objectOf(parts[1]) ?: return malformed()
        val (typ, jwkThumbprint) = validatedHeader(header) ?: return malformed()
        return payloadValidation(payload, typ, jwkThumbprint, nowEpochSeconds)
    }

    private fun malformed() = DaaRegistrationAuthorizationValidation.Rejected(DaaSecureKeyError.InvalidSigningInput)

    private fun objectOf(value: String): JsonObject? =
        try {
            Base64Url.decode(value)?.let { bytes ->
                val text = bytes.toString(Charsets.UTF_8)
                if (!text.toByteArray(Charsets.UTF_8).contentEquals(bytes) ||
                    DuplicateJsonKeys.existAtTopLevel(text)
                ) {
                    null
                } else {
                    json.parseToJsonElement(text).jsonObject
                }
            }
        } catch (_: SerializationException) {
            null
        } catch (_: IllegalArgumentException) {
            null
        }

    /** The header's `typ` and the RFC 7638 thumbprint of its embedded `jwk`, or null if invalid. */
    private fun validatedHeader(header: JsonObject): Pair<String, String>? {
        if (header.keys != headerKeys || header.string("alg") != "ES256") return null
        val typ = header.string("typ") ?: return null
        val typIsValid =
            when (typ) {
                FLOW_TYP, DEVICE_TYP -> true
                else -> false
            }
        if (!typIsValid) return null
        val jwk = header["jwk"]
        if (jwk !is JsonObject) return null
        val jwkThumbprint = embeddedJwkThumbprint(jwk) ?: return null
        return typ to jwkThumbprint
    }

    private fun embeddedJwkThumbprint(jwk: JsonObject): String? {
        if (jwk.keys != jwkKeys) return null
        if (jwk.string("kty") != "EC" || jwk.string("crv") != "P-256") return null
        val x = jwk.string("x")?.let(Base64Url::decode) ?: return null
        val y = jwk.string("y")?.let(Base64Url::decode) ?: return null
        if (x.size != 32 || y.size != 32) return null
        return p256Thumbprint(x, y)
    }

    // Reuses the wire layer's strict point validation (coordinates in field
    // range, point on the curve, accepted by the platform key factory) and its
    // RFC 7638 thumbprint, so the result compares directly with
    // DaaSecureKey.thumbprint(). Null when the point is invalid.
    private fun p256Thumbprint(
        x: ByteArray,
        y: ByteArray,
    ): String? =
        try {
            P256PublicKeyEncoding.jwkThumbprint(
                P256PublicKeyEncoding.subjectPublicKeyInfo(byteArrayOf(UNCOMPRESSED_POINT_MARKER) + x + y),
            )
        } catch (_: AuthKeyWireError) {
            null
        }

    private fun payloadValidation(
        value: JsonObject,
        typ: String,
        jwkThumbprint: String,
        nowEpochSeconds: Long,
    ): DaaRegistrationAuthorizationValidation {
        val requiredKeys =
            when (typ) {
                FLOW_TYP -> flowPayloadKeys
                DEVICE_TYP -> devicePayloadKeys
                else -> return malformed()
            }
        if (value.keys != requiredKeys) return malformed()
        if (typ == FLOW_TYP && !registrationBindingClaimsAreValid(value)) return malformed()
        val path = value.string("canonical_path") ?: return malformed()
        val pathIsValid =
            when (path) {
                DEVICE_KEY_REGISTRATION_PATH -> true
                else -> false
            }
        val iat = value.integer("iat") ?: return malformed()
        val exp = value.integer("exp") ?: return malformed()
        val bodyDigest = value.string("body_sha256") ?: return malformed()
        val idempotency = value.string("idempotency_key") ?: return malformed()
        val jti = value.string("jti") ?: return malformed()
        val discriminator = value.string("discriminator") ?: return malformed()
        val schemaVersion = value.integer("schema_version") ?: return malformed()
        val claimsAreValid =
            pathIsValid &&
                value.string("method") == "POST" &&
                value.string("aud") == AUDIENCE &&
                discriminator == EXPECTED_DISCRIMINATOR &&
                schemaVersion == EXPECTED_SCHEMA_VERSION &&
                Base64Url.decode(bodyDigest)?.size == 32 &&
                runCatching { UUID.fromString(idempotency) }.isSuccess &&
                runCatching { UUID.fromString(jti) }.isSuccess &&
                exp > iat &&
                exp - iat <= MAXIMUM_AUTHORIZATION_LIFETIME &&
                iat > 0
        if (!claimsAreValid || iat > nowEpochSeconds + CLOCK_SKEW_LEEWAY) {
            return malformed()
        }
        return if (exp < nowEpochSeconds - CLOCK_SKEW_LEEWAY) {
            DaaRegistrationAuthorizationValidation.Rejected(DaaSecureKeyError.SigningInputExpired)
        } else {
            DaaRegistrationAuthorizationValidation.Accepted(typ, jwkThumbprint)
        }
    }

    // The flow proof's registration-binding claims. The claimed
    // `auth_key_thumbprint` is checked for shape only; no SDK signer compares it
    // with a key, and the device proof's signer is bound through the header
    // `jwk` instead.
    private fun registrationBindingClaimsAreValid(value: JsonObject): Boolean {
        val handleDigest = value.string("registration_handle_sha256") ?: return false
        val verifierDigest = value.string("code_verifier_sha256") ?: return false
        val thumbprint = value.string("auth_key_thumbprint") ?: return false
        val profileId = value.string("profile_id") ?: return false
        return profileId.isNotEmpty() &&
            Base64Url.decode(handleDigest)?.size == 32 &&
            Base64Url.decode(verifierDigest)?.size == 32 &&
            Base64Url.decode(thumbprint)?.size == 32
    }

    private fun JsonObject.string(name: String): String? {
        val value = get(name) ?: return null
        if (value !is JsonPrimitive) return null
        return value.takeIf { it.isString }?.content
    }

    private fun JsonObject.integer(name: String): Long? {
        val value = get(name) ?: return null
        if (value !is JsonPrimitive) return null
        return if (value.isString || value.booleanOrNull != null) null else value.longOrNull
    }
}
