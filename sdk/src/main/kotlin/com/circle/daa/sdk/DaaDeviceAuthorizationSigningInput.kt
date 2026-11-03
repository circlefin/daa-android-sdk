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
import com.circle.daa.sdk.internal.authkey.Base64Url
import com.circle.daa.sdk.internal.authkey.DuplicateJsonKeys
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.longOrNull
import java.security.MessageDigest
import java.util.UUID

public class DaaDeviceAuthorizationSigningInput(exactBytes: ByteArray) {
    private val exactBytes: ByteArray = exactBytes.copyOf()

    /**
     * The validated operation discriminator (`transfer`, `withdrawal`, `create_account`,
     * `get_device_context`, `register_device_key`, or `complete_social_login`), read from the
     * single validation pass below and never re-parsed. Exposed so a protection-profile gate can
     * be applied against the operation class without re-decoding the input.
     */
    internal val operation: String

    /**
     * True for Device Registration Complete (`register_device_key`) and
     * `complete_social_login`, the enrollment operations an AuthKey may sign while
     * still `Created`, before its registration is acknowledged. Read from
     * [operation], never re-parsed.
     */
    internal val permitsPendingRegistration: Boolean

    init {
        val validation =
            DaaDeviceAuthorizationSigningInputValidator.validate(this.exactBytes, EpochSeconds.now())
        operation =
            when (validation) {
                is DaaDeviceAuthorizationValidation.Accepted -> validation.operation
                is DaaDeviceAuthorizationValidation.Rejected -> throw DaaSecureKeyException(validation.error)
            }
        permitsPendingRegistration =
            operation == DaaDeviceAuthorizationSigningInputValidator.COMPLETE_SOCIAL_LOGIN ||
            operation == DaaDeviceAuthorizationSigningInputValidator.REGISTER_DEVICE_KEY
    }

    internal fun signingBytes(): ByteArray = signingBytesAt(EpochSeconds.now())

    internal fun signingBytesAt(nowEpochSeconds: Long): ByteArray =
        exactBytes.copyOf().also {
            DaaDeviceAuthorizationSigningInputValidator.error(it, nowEpochSeconds)?.let { error ->
                throw DaaSecureKeyException(error)
            }
        }
}

/** Result of one validation pass: the accepted DAA operation, or the first rejection. */
internal sealed interface DaaDeviceAuthorizationValidation {
    data class Accepted(val operation: String) : DaaDeviceAuthorizationValidation

    data class Rejected(val error: DaaSecureKeyError) : DaaDeviceAuthorizationValidation
}

internal object DaaDeviceAuthorizationSigningInputValidator {
    private val json = Json { isLenient = false }
    private val headerKeys = setOf("alg", "kid", "typ")
    private val sharedPayloadKeys =
        setOf(
            "aud",
            "body_sha256",
            "canonical_path",
            "discriminator",
            "exp",
            "iat",
            "jti",
            "method",
            "schema_version",
        )
    private const val MAXIMUM_AUTHORIZATION_LIFETIME = 300L
    private const val CLOCK_SKEW_LEEWAY = 60L

    internal fun valid(
        input: ByteArray,
        nowEpochSeconds: Long,
    ): Boolean = error(input, nowEpochSeconds) == null

    internal fun error(
        input: ByteArray,
        nowEpochSeconds: Long,
    ): DaaSecureKeyError? = (validate(input, nowEpochSeconds) as? DaaDeviceAuthorizationValidation.Rejected)?.error

    internal fun validate(
        input: ByteArray,
        nowEpochSeconds: Long,
    ): DaaDeviceAuthorizationValidation {
        val text = input.toString(Charsets.UTF_8)
        if (!text.toByteArray().contentEquals(input)) return malformed()
        val parts = text.split('.')
        if (parts.size != 2) return malformed()
        val header = objectOf(parts[0]) ?: return malformed()
        val payload = objectOf(parts[1]) ?: return malformed()
        if (header.keys != headerKeys || header.string("alg") != "ES256" ||
            header.string("typ") != "aw-device-authorization+jws" || header.string("kid").isNullOrEmpty()
        ) {
            return malformed()
        }
        return payloadValidation(payload, nowEpochSeconds)
    }

    private fun malformed() = DaaDeviceAuthorizationValidation.Rejected(DaaSecureKeyError.InvalidSigningInput)

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

    private fun payloadValidation(
        value: JsonObject,
        nowEpochSeconds: Long,
    ): DaaDeviceAuthorizationValidation {
        val operation = value.string("discriminator") ?: return malformed()
        val path = value.string("canonical_path") ?: return malformed()
        val iat = value.integer("iat") ?: return malformed()
        val exp = value.integer("exp") ?: return malformed()
        val idempotency = value["idempotency_key"]
        val bodyDigest = value.string("body_sha256") ?: return malformed()
        val operationIsValid =
            when (operation) {
                COMPLETE_SOCIAL_LOGIN ->
                    isPostWithIdempotency(value, path, COMPLETE_SOCIAL_LOGIN_PATH, idempotency)
                GET_DEVICE_CONTEXT ->
                    value.keys == sharedPayloadKeys &&
                        path == GET_DEVICE_CONTEXT_PATH &&
                        value.string("method") == "GET" &&
                        bodyDigest == EMPTY_BODY_SHA256
                CREATE_ACCOUNT -> isPostWithIdempotency(value, path, CREATE_ACCOUNT_PATH, idempotency)
                TRANSFER -> isPostWithIdempotency(value, path, TRANSFER_PATH, idempotency)
                WITHDRAWAL -> isPostWithIdempotency(value, path, WITHDRAWAL_PATH, idempotency)
                REGISTER_DEVICE_KEY -> isPostWithIdempotency(value, path, REGISTER_DEVICE_KEY_PATH, idempotency)
                else -> false
            }
        val claimsAreValid =
            operationIsValid &&
                Base64Url.decode(bodyDigest)?.size == 32 &&
                value.integer("schema_version") == 1L &&
                value.string("aud") == AUDIENCE &&
                runCatching { UUID.fromString(value.string("jti")) }.isSuccess &&
                exp > iat && exp - iat <= MAXIMUM_AUTHORIZATION_LIFETIME &&
                iat > 0
        if (!claimsAreValid || iat > nowEpochSeconds + CLOCK_SKEW_LEEWAY) {
            return malformed()
        }
        return if (exp < nowEpochSeconds - CLOCK_SKEW_LEEWAY) {
            DaaDeviceAuthorizationValidation.Rejected(DaaSecureKeyError.SigningInputExpired)
        } else {
            DaaDeviceAuthorizationValidation.Accepted(operation)
        }
    }

    private fun isPostWithIdempotency(
        value: JsonObject,
        path: String,
        expectedPath: String,
        idempotency: JsonElement?,
    ): Boolean =
        value.keys == sharedPayloadKeys + "idempotency_key" &&
            path == expectedPath &&
            value.string("method") == "POST" &&
            idempotency is JsonPrimitive &&
            idempotency.isString &&
            runCatching { UUID.fromString(idempotency.content) }.isSuccess

    private fun JsonObject.string(name: String): String? =
        (get(name) as? JsonPrimitive)?.takeIf { it.isString }?.content

    private fun JsonObject.integer(name: String): Long? {
        val value = get(name) as? JsonPrimitive ?: return null
        return if (value.isString || value.booleanOrNull != null) null else value.longOrNull
    }

    internal const val COMPLETE_SOCIAL_LOGIN: String = "complete_social_login"
    internal const val REGISTER_DEVICE_KEY: String = "register_device_key"
    internal const val GET_DEVICE_CONTEXT: String = "get_device_context"
    internal const val CREATE_ACCOUNT: String = "create_account"
    internal const val TRANSFER: String = "transfer"
    internal const val WITHDRAWAL: String = "withdrawal"

    /**
     * The only operations `AuthKeyProtectionMode.DeviceUnlocked` is permitted to sign — every
     * operation the module's on-device instrumentation tests exercise under it, and nothing
     * else. `DaaSecureKey.signDeviceAuthorization` throws for any operation outside this set under
     * that protection, since `DeviceUnlocked` authorizes signing with no per-signature user
     * verification.
     *
     * Written as an allowlist rather than a denylist of consequential operations (moving money,
     * creating an account) on purpose: an operation this code has never been taught about must
     * fail closed and force a deliberate decision here, not inherit a pass the way a newly added
     * consequential operation would if this only listed what to refuse.
     */
    internal val DEVICE_UNLOCKED_PERMITTED_OPERATIONS: Set<String> =
        setOf(GET_DEVICE_CONTEXT, REGISTER_DEVICE_KEY, COMPLETE_SOCIAL_LOGIN)
    private const val AUDIENCE = "circle-digital-asset-accounts"
    private const val COMPLETE_SOCIAL_LOGIN_PATH = "/v1/accounts/auth/sessions"
    private const val GET_DEVICE_CONTEXT_PATH = "/v1/accounts/auth/context"
    private const val CREATE_ACCOUNT_PATH = "/v1/accounts"
    private const val TRANSFER_PATH = "/v1/accounts/transfers"
    private const val WITHDRAWAL_PATH = "/v1/accounts/withdrawals"
    private const val REGISTER_DEVICE_KEY_PATH = "/v1/accounts/auth/deviceKeyRegistration"
    private val EMPTY_BODY_SHA256: String =
        Base64Url.encode(MessageDigest.getInstance("SHA-256").digest(ByteArray(0)))
}
