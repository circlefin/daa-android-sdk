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

import com.circle.daa.sdk.DaaEnvironment
import com.circle.daa.sdk.sca.DaaScaApproveContract
import com.circle.daa.sdk.sca.DaaScaConfig
import com.circle.daa.sdk.sca.DaaScaEnrollContract
import com.circle.daa.sdk.sca.DaaScaError
import com.circle.daa.sdk.sca.DaaScaResult
import com.circle.daa.sdk.sca.DaaScaUnsupportedReason
import org.junit.jupiter.api.Assertions.assertDoesNotThrow
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Drives the real parser, configuration rules, and ceremony controller with the vectors the
 * iOS SDK runs too. Where the SDKs differ by design the fixture names each side's outcome,
 * and this suite checks the Android one.
 */
class ScaConformanceTest {
    private val fixture = ScaConformanceFixture.load()

    // Callbacks

    @Test
    fun `every callback vector has the expected Android outcome`() {
        assertFalse(fixture.callbackVectors.isEmpty())
        fixture.callbackVectors.forEach { vector ->
            assertEquals(vector.android, outcomeOf(vector), vector.id)
        }
    }

    @Test
    fun `callback vector ids are unique`() {
        val ids = fixture.callbackVectors.map { it.id }
        assertEquals(ids.size, ids.toSet().size)
    }

    @Test
    fun `an ignored callback leaves the ceremony waiting and the real one still lands`() {
        val ignored = fixture.callbackVectors.filter { it.android.outcome == IGNORED }
        assertTrue(ignored.isNotEmpty())
        ignored.forEach { vector ->
            val controller = controller(vector)
            assertSame(ScaAction.Wait, controller.onCallback(NOW, vector.callback), vector.id)
            assertFalse(controller.finished, vector.id)

            val real = "${vector.redirectUri}#v=1&state=${vector.state}&kind=error&code=Cancelled"
            assertEquals(ScaAction.Finish(DaaScaResult.Cancelled), controller.onCallback(NOW, real), vector.id)
        }
    }

    @Test
    fun `a callback that is not ignored ends the ceremony with the same outcome`() {
        fixture.callbackVectors.filter { it.android.outcome != IGNORED }.forEach { vector ->
            val action = controller(vector).onCallback(NOW, vector.callback)
            val finished = (action as? ScaAction.Finish)?.result
            assertEquals(vector.android, finished?.let(::outcomeOf), vector.id)
        }
    }

    @Test
    fun `only Android ignores a callback and only iOS reports a state mismatch`() {
        fixture.callbackVectors.forEach { vector ->
            assertNotEquals(IGNORED, vector.ios.outcome, vector.id)
            assertNotEquals("stateMismatch", vector.android.outcome, vector.id)
            // Every iOS state mismatch is a callback Android ignores.
            if (vector.ios.outcome == "stateMismatch") assertEquals(IGNORED, vector.android.outcome, vector.id)
        }
    }

    private fun request(vector: ScaConformanceFixture.CallbackVector): ScaCeremonyRequest =
        ScaCeremonyRequest(
            kind = ScaCeremonyKind.entries.single { it.wireValue == vector.ceremony },
            circleOrigin = "https://daa-sca-sandbox.circle.com",
            redirectUri = vector.redirectUri,
            frameToken = "frame-token",
            state = vector.state,
            timeoutMillis = DaaScaConfig.DEFAULT_APPROVE_TIMEOUT_MILLIS,
        )

    private fun controller(vector: ScaConformanceFixture.CallbackVector): ScaCeremonyController =
        ScaCeremonyController(request(vector), deadline = NOW + 60_000, launched = ScaSurfaceKind.CustomTab)

    private fun outcomeOf(vector: ScaConformanceFixture.CallbackVector): ScaConformanceFixture.Outcome =
        when (val outcome = ScaCallback.parse(vector.callback, request(vector))) {
            is ScaCallbackOutcome.Ignored -> ScaConformanceFixture.Outcome(IGNORED)
            is ScaCallbackOutcome.Final -> outcomeOf(outcome.result)
        }

    // Redirect URIs

    @Test
    fun `every accepted redirect URI builds a config`() {
        assertFalse(fixture.redirectAccept.isEmpty())
        fixture.redirectAccept.forEach { vector ->
            assertTrue(ScaConfigRules.isValidRedirectUri(vector.input), vector.id)
            assertEquals(vector.input, DaaScaConfig(DaaEnvironment.Sandbox, vector.input).redirectUri, vector.id)
        }
    }

    @Test
    fun `every rejected redirect URI is refused at construction`() {
        assertFalse(fixture.redirectReject.isEmpty())
        fixture.redirectReject.forEach { vector ->
            assertFalse(ScaConfigRules.isValidRedirectUri(vector.input), vector.id)
            assertConfigError(INVALID_REDIRECT_URI, vector.id) { DaaScaConfig(DaaEnvironment.Sandbox, vector.input) }
        }
    }

    @Test
    fun `the redirect URI length limit is the fixture's`() {
        assertEquals(ScaConfigRules.MAX_REDIRECT_URI_CHARS, fixture.redirectAccept.maxOf { it.input.length })
        assertEquals(ScaConfigRules.MAX_REDIRECT_URI_CHARS + 1, fixture.redirectReject.maxOf { it.input.length })
    }

    @Test
    fun `the Android platform rules`() {
        val rules = fixture.platformRules.filter { it.platform == "android" }
        assertTrue(rules.isNotEmpty())
        rules.forEach { rule ->
            val config = DaaScaConfig(DaaEnvironment.Sandbox, rule.redirectUri)
            val build: () -> Unit =
                when (rule.ceremony) {
                    "challenge" -> { -> DaaScaApproveContract(config) }
                    "registration" -> { -> DaaScaEnrollContract(config) }
                    else -> throw AssertionError("Unknown ceremony for ${rule.id}")
                }
            when (rule.expected) {
                "accept" -> assertDoesNotThrow(build, rule.id)
                "reject" -> assertThrows(IllegalArgumentException::class.java, build, rule.id)
                else -> throw AssertionError("Unknown expectation ${rule.expected} for ${rule.id}")
            }
        }
    }

    // Ceremony origin

    @Test
    fun `every circle origin vector`() {
        assertFalse(fixture.circleOriginVectors.isEmpty())
        fixture.circleOriginVectors.forEach { vector ->
            environments(vector.environment).forEach { environment ->
                val build = { DaaScaConfig(environment, REDIRECT, vector.circleOrigin) }
                if (vector.outcome == "accept") {
                    assertEquals(vector.origin, build().circleOrigin, vector.id)
                } else {
                    val prefix = CONFIG_ERRORS[vector.outcome] ?: throw AssertionError("Unknown ${vector.outcome}")
                    assertConfigError(prefix, vector.id, build)
                }
            }
            // The origin rule alone agrees with the config outcome.
            if (vector.circleOrigin != null && vector.environment == "sandbox") {
                assertEquals(
                    vector.outcome == "accept",
                    ScaConfigRules.isValidOriginOverride(vector.circleOrigin),
                    vector.id,
                )
            }
        }
    }

    @Test
    fun `only the non-public environment vectors expect an unsupported environment`() {
        // Android does not run these vectors, so check they still say what that relies on.
        val (nonPublic, public) = fixture.circleOriginVectors.partition { it.environment == NON_PUBLIC }
        assertFalse(nonPublic.isEmpty())
        nonPublic.forEach { assertEquals(UNSUPPORTED_ENVIRONMENT, it.outcome, it.id) }
        public.forEach { assertNotEquals(UNSUPPORTED_ENVIRONMENT, it.outcome, it.id) }
        fixture.callbackVectors.forEach { vector ->
            assertNotEquals(UNSUPPORTED_ENVIRONMENT, vector.ios.outcome, vector.id)
            assertNotEquals(UNSUPPORTED_ENVIRONMENT, vector.android.outcome, vector.id)
        }
    }

    private fun environments(name: String): List<DaaEnvironment> =
        when (name) {
            "sandbox" -> listOf(DaaEnvironment.Sandbox)
            "production" -> listOf(DaaEnvironment.Production)
            // DaaEnvironment has no non-public value, so the type itself enforces these vectors.
            NON_PUBLIC -> emptyList()
            else -> throw AssertionError("Unknown environment $name")
        }

    // Timeouts

    @Test
    fun `the timeout defaults and bounds are the fixture's`() {
        val timeouts = fixture.timeouts
        assertEquals(timeouts.approveDefaultMillis, DaaScaConfig.DEFAULT_APPROVE_TIMEOUT_MILLIS)
        assertEquals(timeouts.enrollDefaultMillis, DaaScaConfig.DEFAULT_ENROLL_TIMEOUT_MILLIS)
        assertEquals(timeouts.minimumMillis, DaaScaConfig.MINIMUM_TIMEOUT_MILLIS)
        assertEquals(timeouts.maximumMillis, DaaScaConfig.MAXIMUM_TIMEOUT_MILLIS)
        val config = DaaScaConfig(DaaEnvironment.Sandbox, REDIRECT)
        assertEquals(timeouts.approveDefaultMillis, config.approveTimeoutMillis)
        assertEquals(timeouts.enrollDefaultMillis, config.enrollTimeoutMillis)
    }

    @Test
    fun `every timeout vector for both ceremonies`() {
        assertFalse(fixture.timeouts.vectors.isEmpty())
        fixture.timeouts.vectors.forEach { vector ->
            val millis = vector.millis
            val approve = { DaaScaConfig(DaaEnvironment.Sandbox, REDIRECT, approveTimeoutMillis = millis) }
            val enroll = { DaaScaConfig(DaaEnvironment.Sandbox, REDIRECT, enrollTimeoutMillis = millis) }
            when (vector.expected) {
                "accept" -> {
                    assertEquals(millis, approve().approveTimeoutMillis, vector.id)
                    assertEquals(millis, enroll().enrollTimeoutMillis, vector.id)
                }
                "reject" -> {
                    assertConfigError(INVALID_TIMEOUT, vector.id, approve)
                    assertConfigError(INVALID_TIMEOUT, vector.id, enroll)
                }
                else -> throw AssertionError("Unknown expectation ${vector.expected} for ${vector.id}")
            }
        }
    }

    // Error vocabulary

    @Test
    fun `the error vocabulary is exactly Android's errors`() {
        // Cancelled is a DaaScaResult, not a DaaScaError, on Android.
        assertEquals(
            fixture.pageCodes.filter { it != "Cancelled" } + fixture.androidLocalErrors,
            DaaScaError.entries.map { it.name },
        )
    }

    @Test
    fun `every page code has a callback vector on both platforms`() {
        fixture.pageCodes.forEach { code ->
            assertTrue(fixture.callbackVectors.any { it.ios.code == code && it.android.code == code }, code)
        }
    }

    private fun assertConfigError(
        messagePrefix: String,
        id: String,
        build: () -> Any,
    ) {
        val error = assertThrows(IllegalArgumentException::class.java, { build() }, id)
        assertTrue(error.message.orEmpty().startsWith(messagePrefix), "$id: ${error.message}")
    }

    internal companion object {
        const val IGNORED: String = "ignored"
        private const val NOW: Long = 1_000_000L
        private const val REDIRECT: String = "https://app.example.com/sca/callback"
        private const val INVALID_REDIRECT_URI: String = "redirectUri must be"
        private const val INVALID_TIMEOUT: String = "ceremony timeouts must be"
        private const val NON_PUBLIC: String = "nonPublic"
        private const val UNSUPPORTED_ENVIRONMENT: String = "unsupportedEnvironment"

        // DaaScaConfig reports each refusal as an IllegalArgumentException; its message says which.
        private val CONFIG_ERRORS: Map<String, String> =
            mapOf(
                "circleOriginOverrideNotAllowed" to "circleOrigin is a development override",
                "invalidCircleOrigin" to "circleOrigin must be",
            )

        internal fun outcomeOf(result: DaaScaResult): ScaConformanceFixture.Outcome =
            when (result) {
                is DaaScaResult.Completed -> ScaConformanceFixture.Outcome("result", result = result.response)
                DaaScaResult.Cancelled -> ScaConformanceFixture.Outcome("error", code = "Cancelled")
                is DaaScaResult.Failed ->
                    when (result.error) {
                        DaaScaError.Protocol -> ScaConformanceFixture.Outcome("protocolError")
                        DaaScaError.Unsupported -> {
                            // The page's Unsupported is the one reason the SDK cannot narrow.
                            assertEquals(DaaScaUnsupportedReason.PasskeyUnavailable, result.unsupportedReason)
                            ScaConformanceFixture.Outcome("error", code = "Unsupported", message = result.message)
                        }
                        else ->
                            ScaConformanceFixture.Outcome(
                                "error",
                                code = result.error.name,
                                message = result.message,
                            )
                    }
            }
    }
}
