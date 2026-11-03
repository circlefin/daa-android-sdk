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

package com.circle.daa.sdk.sca.internal

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import org.junit.jupiter.api.Assertions.fail
import java.security.MessageDigest

/**
 * The shared SCA conformance vectors. The canonical artifact is the iOS SDK's
 * `Conformance/ScaCallbackV1.json`; this test-resource copy must be byte-identical to it,
 * which the pinned SHA-256 enforces, as it does for `AuthKeyWireV1.json`.
 */
internal class ScaConformanceFixture(
    val callbackVectors: List<CallbackVector>,
    val redirectAccept: List<Named>,
    val redirectReject: List<Named>,
    val platformRules: List<PlatformRule>,
    val circleOriginVectors: List<CircleOriginVector>,
    val timeouts: Timeouts,
    val pageCodes: List<String>,
    val androidLocalErrors: List<String>,
) {
    /** One callback outcome, as the fixture spells it. */
    internal data class Outcome(
        val outcome: String,
        val result: String? = null,
        val code: String? = null,
        val message: String? = null,
    ) {
        // Kept short: a payload or message can run to tens of kilobytes.
        override fun toString(): String =
            listOfNotNull(
                outcome,
                code,
                result?.let { "result(${it.length} chars)" },
                message?.let { "message(${it.length} chars)" },
            ).joinToString(" ")
    }

    internal class CallbackVector(
        val id: String,
        val redirectUri: String,
        val state: String,
        val ceremony: String,
        val callback: String,
        val ios: Outcome,
        val android: Outcome,
    )

    internal class Named(
        val id: String,
        val input: String,
    )

    internal class PlatformRule(
        val id: String,
        val platform: String,
        val redirectUri: String,
        val ceremony: String?,
        val expected: String,
    )

    internal class CircleOriginVector(
        val id: String,
        val environment: String,
        val circleOrigin: String?,
        val outcome: String,
        val origin: String?,
    )

    internal class Timeouts(
        val approveDefaultMillis: Long,
        val enrollDefaultMillis: Long,
        val minimumMillis: Long,
        val maximumMillis: Long,
        val vectors: List<TimeoutVector>,
    )

    internal class TimeoutVector(
        val id: String,
        val millis: Long,
        val expected: String,
    )

    internal companion object {
        private const val RESOURCE: String = "/Fixtures/ScaCallbackV1.json"
        private const val EXPECTED_PROFILE: String = "daa-sca-callback-v1"
        private const val EXPECTED_SHA256: String =
            "881bba7768a467612a16b955fb30f4693f8b9da412f53abd95711e7c2f25e9a1"

        internal fun load(): ScaConformanceFixture {
            val bytes =
                ScaConformanceFixture::class.java
                    .getResourceAsStream(RESOURCE)
                    ?.use { it.readBytes() }
                    ?: fail("Missing ScaCallbackV1.json fixture")
            val actualSha256 = MessageDigest.getInstance("SHA-256").digest(bytes).toLowerHex()
            if (actualSha256 != EXPECTED_SHA256) {
                throw AssertionError("Unexpected ScaCallbackV1.json SHA-256: $actualSha256")
            }
            val root = Json.parseToJsonElement(bytes.toString(Charsets.UTF_8)).jsonObject
            if (root.int("version") != 1 || root.string("profile") != EXPECTED_PROFILE) {
                throw AssertionError("Unexpected ScaCallbackV1.json metadata")
            }
            return parse(root)
        }

        private fun parse(root: JsonObject): ScaConformanceFixture {
            val redirect = root.obj("redirectUriVectors")
            val timeouts = root.obj("timeoutVectors")
            val vocabulary = root.obj("errorVocabulary")
            return ScaConformanceFixture(
                callbackVectors = root.array("callbackVectors").map { callbackVector(it.jsonObject) },
                redirectAccept = redirect.array("accept").map { named(it.jsonObject) },
                redirectReject = redirect.array("reject").map { named(it.jsonObject) },
                platformRules =
                    root.array("platformRules").map {
                        val rule = it.jsonObject
                        val input = rule.obj("input")
                        PlatformRule(
                            id = rule.string("id"),
                            platform = rule.string("platform"),
                            redirectUri = input.string("redirectUri"),
                            ceremony = input.optionalString("ceremony"),
                            expected = rule.string("expected"),
                        )
                    },
                circleOriginVectors =
                    root.array("circleOriginVectors").map {
                        val vector = it.jsonObject
                        val input = vector.obj("input")
                        val expected = vector.obj("expected")
                        CircleOriginVector(
                            id = vector.string("id"),
                            environment = input.string("environment"),
                            circleOrigin = input.optionalString("circleOrigin"),
                            outcome = expected.string("outcome"),
                            origin = expected.optionalString("origin"),
                        )
                    },
                timeouts =
                    Timeouts(
                        approveDefaultMillis = timeouts.obj("defaults").long("approveMs"),
                        enrollDefaultMillis = timeouts.obj("defaults").long("enrollMs"),
                        minimumMillis = timeouts.obj("bounds").long("minimumMs"),
                        maximumMillis = timeouts.obj("bounds").long("maximumMs"),
                        vectors =
                            timeouts.array("vectors").map {
                                val vector = it.jsonObject
                                TimeoutVector(vector.string("id"), vector.long("input"), vector.string("expected"))
                            },
                    ),
                pageCodes = vocabulary.array("pageCodes").map { it.jsonPrimitive.content },
                androidLocalErrors = vocabulary.obj("sdkLocal").array("android").map { it.jsonPrimitive.content },
            )
        }

        private fun callbackVector(vector: JsonObject): CallbackVector {
            val input = vector.obj("input")
            val expected = vector.obj("expected")
            val perPlatform = "ios" in expected
            return CallbackVector(
                id = vector.string("id"),
                redirectUri = generated(input.getValue("redirectUri")),
                state = input.string("state"),
                ceremony = input.string("ceremony"),
                callback = generated(input.getValue("callback")),
                ios = outcome(if (perPlatform) expected.obj("ios") else expected),
                android = outcome(if (perPlatform) expected.obj("android") else expected),
            )
        }

        private fun outcome(value: JsonObject): Outcome =
            Outcome(
                outcome = value.string("outcome"),
                result = value["result"]?.takeUnless { it is JsonNull }?.let(::generated),
                code = value.optionalString("code"),
                message = value["message"]?.takeUnless { it is JsonNull }?.let(::generated),
            )

        private fun named(value: JsonObject): Named = Named(value.string("id"), generated(value.getValue("input")))

        /**
         * A fixture string: a literal, `{"repeat": s, "count": n}`, or `{"concat": [parts]}`.
         * Oversized inputs are generated so the fixture never inlines them.
         */
        internal fun generated(value: JsonElement): String =
            when (value) {
                is JsonPrimitive -> value.content
                is JsonObject ->
                    value["concat"]?.jsonArray?.joinToString(separator = "") { generated(it) }
                        ?: value.string("repeat").repeat(value.int("count"))
                else -> throw AssertionError("Unexpected generated string: $value")
            }

        private fun JsonObject.obj(key: String): JsonObject = getValue(key).jsonObject

        private fun JsonObject.array(key: String): JsonArray = getValue(key).jsonArray

        private fun JsonObject.string(key: String): String = getValue(key).jsonPrimitive.content

        private fun JsonObject.optionalString(key: String): String? =
            get(key)?.takeUnless { it is JsonNull }?.jsonPrimitive?.content

        private fun JsonObject.int(key: String): Int = getValue(key).jsonPrimitive.int

        private fun JsonObject.long(key: String): Long = getValue(key).jsonPrimitive.long
    }
}

private fun ByteArray.toLowerHex(): String =
    joinToString(separator = "") { byte ->
        (byte.toInt() and 0xFF).toString(16).padStart(2, '0')
    }
