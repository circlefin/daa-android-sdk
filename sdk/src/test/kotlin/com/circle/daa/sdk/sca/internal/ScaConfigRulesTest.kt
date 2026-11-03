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
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource

class ScaConfigRulesTest {
    @Test
    fun `Sandbox and Production resolve to the public ceremony origins`() {
        // These must equal Circle's configured WebAuthn origins byte for byte, and match the
        // web SDK's table; a drift here fails every ceremony's origin check.
        assertEquals("https://daa-sca-sandbox.circle.com", DaaScaConfig(DaaEnvironment.Sandbox, REDIRECT).circleOrigin)
        assertEquals("https://daa-sca.circle.com", DaaScaConfig(DaaEnvironment.Production, REDIRECT).circleOrigin)
    }

    @Test
    fun `Sandbox and Production are the only environments`() {
        // Other Circle hosts are reached with Sandbox and a circleOrigin override, never with
        // an environment of their own.
        assertEquals(listOf(DaaEnvironment.Sandbox, DaaEnvironment.Production), DaaEnvironment.entries)
    }

    @Test
    fun `Sandbox with an override reaches another Circle host`() {
        assertEquals(TEST_ORIGIN, DaaScaConfig(DaaEnvironment.Sandbox, REDIRECT, TEST_ORIGIN).circleOrigin)
    }

    @ParameterizedTest
    @ValueSource(
        strings = [
            "https://app.example.com/sca/callback",
            "https://app.example.com",
            "https://app.example.com/cb?tenant=acme",
            "https://app.example.com/cb?at=10:30",
            "https://app.example.com/cb?tenant=o%27reilly",
            "https://app.example.com/%7Ecb",
            "https://app.example.com/sca.v2/..cb/.well/cb.",
            "com.example.app:/sca",
            "acme://sca-callback",
            "acme://cb?tenant=o'reilly",
        ],
    )
    fun `accepts https and custom-scheme redirect URIs`(uri: String) {
        assertTrue(ScaConfigRules.isValidRedirectUri(uri), uri)
    }

    @ParameterizedTest
    @ValueSource(
        strings = [
            "",
            "/sca/callback",
            "http://app.example.com/cb",
            "https://app.example.com/cb#x",
            "https://app.example.com/cb#",
            "https://user:pass@app.example.com/cb",
            "https://app.example.com:8443/cb",
            "https://app.example.com:443/cb",
            "https://app.example.com:/cb",
            "https://app.example.com:8443",
            "https:///cb",
            "javascript:alert(1)",
            "intent://cb#Intent;scheme=acme;end",
            "data:text/html,x",
            "file:///sdcard/x",
            "content://x/y",
            "Acme://cb",
            "com.Example.Wallet:/sca/callback",
            "HTTPS://app.example.com/cb",
            " https://app.example.com/cb",
            "https://app.example.com/cb ",
            "https://app.example.com/c\tb",
            "https://app.example.com/cb\u0000",
            "https://app.example.com/caf\u00e9",
            "https://App.Example.com/cb",
            "https://APP.EXAMPLE.COM/cb",
            "https://app.ex%61mple.com/cb",
            "https://0x7f.1/cb",
            "https://127.1/cb",
            "https://127.0.0.1/cb",
            "https://example.123./cb",
            "https://[::1]/cb",
            "https://app.example.com/cb?name=\u00e9",
            "https://bücher.example/cb",
            "not a uri",
        ],
    )
    fun `rejects redirect URIs the ceremony page would refuse`(uri: String) {
        assertFalse(ScaConfigRules.isValidRedirectUri(uri), uri)
    }

    @ParameterizedTest
    @ValueSource(
        strings = [
            // The browser removes dot segments, literal or percent-encoded in any case.
            "https://app.example.com/sca/../callback",
            "https://app.example.com/sca/./callback",
            "https://app.example.com/sca/%2e%2e/callback",
            "https://app.example.com/sca/%2E%2E/callback",
            "https://app.example.com/sca/.%2E/callback",
            "https://app.example.com/sca/%2e./callback",
            "https://app.example.com/sca/%2E/callback",
            "https://app.example.com/sca/..",
            "https://app.example.com/.",
            "https://app.example.com/cb/..?x=1",
            "com.example.app:/sca/../callback",
            "acme://host/a/%2e%2e/b",
            // For https the browser percent-encodes an apostrophe in the query.
            "https://app.example.com/cb?tenant=o'reilly",
            "https://app.example.com/cb?'",
        ],
    )
    fun `rejects redirect URIs the browser would rewrite before the callback`(uri: String) {
        assertFalse(ScaConfigRules.isValidRedirectUri(uri), uri)
        assertThrows(IllegalArgumentException::class.java) { DaaScaConfig(DaaEnvironment.Sandbox, uri) }
    }

    @ParameterizedTest
    @ValueSource(
        strings = ["https://circle.com", "https://sca.example.circle.com"],
    )
    fun `accepts a bare https origin on circle_com as an override`(origin: String) {
        assertTrue(ScaConfigRules.isValidOriginOverride(origin), origin)
    }

    @ParameterizedTest
    @ValueSource(
        strings = [
            "https://sca.example.circle.com/",
            "https://sca.example.circle.com/ceremony",
            "https://sca.example.circle.com?x=1",
            "https://sca.example.circle.com#x",
            "https://sca.example.circle.com#",
            "http://sca.example.circle.com",
            "https://user@sca.example.circle.com",
            "https://sca.example.circle.com:8443",
            "https://sca.example.circle.com:443",
            "https://sca.example.circle.com:",
            "https://SCA.example.circle.com",
            "https://evilcircle.com",
            "https://circle.com.evil.example",
            "https://example.com",
            "http://localhost:3000",
            "https://localhost",
            "sca.example.circle.com",
        ],
    )
    fun `rejects any override that is not a bare https circle_com origin`(origin: String) {
        assertFalse(ScaConfigRules.isValidOriginOverride(origin), origin)
        assertThrows(IllegalArgumentException::class.java) { DaaScaConfig(DaaEnvironment.Sandbox, REDIRECT, origin) }
    }

    @ParameterizedTest
    @ValueSource(
        strings = [
            "https://-sca.circle.com",
            "https://sca-.circle.com",
            "https://sca.circle.com.",
            "https://sca..circle.com",
            "https://.circle.com",
            "https://sca.circle.com ",
            " https://sca.circle.com",
            "https://sca .circle.com",
            "https://sca.circle.com\t",
            "https://sca.circle.com\n",
            "https://scä.circle.com",
            "https://xn--sca.circle.com​",
            "https://ｓｃａ.circle.com",
            "https://sca.circle.com/",
            "https://sca.circle.com:",
        ],
    )
    fun `rejects an override whose host is not lowercase DNS labels`(origin: String) {
        assertFalse(ScaConfigRules.isValidOriginOverride(origin), origin)
        assertThrows(IllegalArgumentException::class.java) { DaaScaConfig(DaaEnvironment.Sandbox, REDIRECT, origin) }
    }

    @ParameterizedTest
    @ValueSource(strings = ["https://circle.com", "https://xn--bcher-kva.circle.com", "https://a-1.b2.circle.com"])
    fun `accepts an override of lowercase DNS labels, including the apex and punycode`(origin: String) {
        assertTrue(ScaConfigRules.isValidOriginOverride(origin), origin)
        assertEquals(origin, DaaScaConfig(DaaEnvironment.Sandbox, REDIRECT, origin).circleOrigin)
    }

    @Test
    fun `an override label may be 63 characters but not 64`() {
        assertTrue(ScaConfigRules.isValidOriginOverride("https://${"a".repeat(63)}.circle.com"))
        assertFalse(ScaConfigRules.isValidOriginOverride("https://${"a".repeat(64)}.circle.com"))
    }

    @Test
    fun `an override host may be 253 characters but not 254`() {
        val labels = "${"a".repeat(63)}.${"b".repeat(63)}.${"c".repeat(63)}."
        val longest = "${labels}${"d".repeat(50)}.circle.com"
        val tooLong = "${labels}${"d".repeat(51)}.circle.com"
        assertEquals(253, longest.length)
        assertTrue(ScaConfigRules.isValidOriginOverride("https://$longest"))
        assertFalse(ScaConfigRules.isValidOriginOverride("https://$tooLong"))
        assertThrows(IllegalArgumentException::class.java) {
            DaaScaConfig(DaaEnvironment.Sandbox, REDIRECT, "https://$tooLong")
        }
    }

    @Test
    fun `any override is refused for Production, even an empty one`() {
        listOf("", "https://daa-sca.circle.com", "not an origin").forEach { origin ->
            val error =
                assertThrows(IllegalArgumentException::class.java) {
                    DaaScaConfig(DaaEnvironment.Production, REDIRECT, circleOrigin = origin)
                }
            assertTrue(error.message.orEmpty().startsWith("circleOrigin is a development override"), origin)
        }
    }

    @Test
    fun `config fails at construction, not mid-ceremony`() {
        assertThrows(IllegalArgumentException::class.java) { DaaScaConfig(DaaEnvironment.Production, "http://x/cb") }
        assertThrows(IllegalArgumentException::class.java) {
            DaaScaConfig(DaaEnvironment.Sandbox, REDIRECT, circleOrigin = "$TEST_ORIGIN/")
        }
    }

    @Test
    fun `origin override is refused for Production`() {
        assertThrows(IllegalArgumentException::class.java) {
            DaaScaConfig(DaaEnvironment.Production, REDIRECT, circleOrigin = "https://daa-sca.circle.com")
        }
    }

    @Test
    fun `timeouts default to the ceremony token lifetimes`() {
        val config = DaaScaConfig(DaaEnvironment.Sandbox, REDIRECT)

        assertEquals(300_000L, config.approveTimeoutMillis)
        assertEquals(600_000L, config.enrollTimeoutMillis)
        assertEquals(30_000L, DaaScaConfig.MINIMUM_TIMEOUT_MILLIS)
    }

    @Test
    fun `timeouts are configurable down to 30 s and no lower`() {
        val config = DaaScaConfig(DaaEnvironment.Sandbox, REDIRECT, null, 30_000L, 45_000L)
        assertEquals(30_000L, config.approveTimeoutMillis)
        assertEquals(45_000L, config.enrollTimeoutMillis)

        assertThrows(IllegalArgumentException::class.java) {
            DaaScaConfig(DaaEnvironment.Sandbox, REDIRECT, approveTimeoutMillis = 29_999L)
        }
        assertThrows(IllegalArgumentException::class.java) {
            DaaScaConfig(DaaEnvironment.Sandbox, REDIRECT, enrollTimeoutMillis = 0L)
        }
    }

    @Test
    fun `timeouts are configurable up to one hour and no higher`() {
        assertEquals(3_600_000L, DaaScaConfig.MAXIMUM_TIMEOUT_MILLIS)
        val config = DaaScaConfig(DaaEnvironment.Sandbox, REDIRECT, null, 3_600_000L, 3_600_000L)
        assertEquals(3_600_000L, config.approveTimeoutMillis)
        assertEquals(3_600_000L, config.enrollTimeoutMillis)

        for (tooLong in listOf(3_600_001L, Long.MAX_VALUE)) {
            assertThrows(IllegalArgumentException::class.java) {
                DaaScaConfig(DaaEnvironment.Sandbox, REDIRECT, approveTimeoutMillis = tooLong)
            }
            assertThrows(IllegalArgumentException::class.java) {
                DaaScaConfig(DaaEnvironment.Sandbox, REDIRECT, enrollTimeoutMillis = tooLong)
            }
        }
    }

    @Test
    fun `a redirect URI may be up to 2048 characters, the longest Circle accepts`() {
        val prefix = "https://app.example.com/"
        val longest = prefix + "a".repeat(2048 - prefix.length)

        assertEquals(longest, DaaScaConfig(DaaEnvironment.Sandbox, longest).redirectUri)
        assertThrows(IllegalArgumentException::class.java) { DaaScaConfig(DaaEnvironment.Sandbox, longest + "a") }
    }

    @Test
    fun `step-up refuses a custom-scheme redirect URI at construction`() {
        val custom = DaaScaConfig(DaaEnvironment.Sandbox, "com.example.app:/sca")

        assertThrows(IllegalArgumentException::class.java) { DaaScaApproveContract(custom) }
        // Enrollment keeps accepting it, and step-up accepts https.
        DaaScaEnrollContract(custom)
        DaaScaApproveContract(DaaScaConfig(DaaEnvironment.Sandbox, REDIRECT))
    }

    @Test
    fun `ceremony URL carries token and state in the fragment under the keys the page reads`() {
        val request =
            ScaCeremonyRequest(
                kind = ScaCeremonyKind.Challenge,
                circleOrigin = "https://daa-sca.circle.com",
                redirectUri = REDIRECT,
                frameToken = "a b+c&d=é",
                state = "k3Jx0Qp2V9mZsYbT7uWc1eFgHiLnOrAdEvGhIjKlMn0",
                timeoutMillis = 300_000,
            )

        // encodeURIComponent("a b+c&d=é") === "a%20b%2Bc%26d%3D%C3%A9"
        assertEquals(
            "https://daa-sca.circle.com/ceremony#token=a%20b%2Bc%26d%3D%C3%A9" +
                "&state=k3Jx0Qp2V9mZsYbT7uWc1eFgHiLnOrAdEvGhIjKlMn0",
            request.ceremonyUrl(),
        )
        // The page's own extraction regex must find the token, not a bare-fragment miss.
        val token = Regex("[#&]token=([^&]+)").find(request.ceremonyUrl())?.groupValues?.get(1)
        assertEquals("a%20b%2Bc%26d%3D%C3%A9", token)
    }

    @Test
    fun `state matches the pattern the page echoes, and is fresh each ceremony`() {
        val states = List(32) { ScaCeremonyRequest.newState() }

        states.forEach { assertTrue(Regex("[A-Za-z0-9_-]{16,128}").matches(it), it) }
        assertEquals(states.size, states.toSet().size)
    }

    @Test
    fun `neither the request nor the config reveals the token in toString`() {
        val request =
            ScaCeremonyRequest(
                ScaCeremonyKind.Registration,
                "https://daa-sca.circle.com",
                REDIRECT,
                "secret-token",
                "s",
                600_000,
            )

        assertFalse(request.toString().contains("secret-token"))
    }

    private companion object {
        const val REDIRECT = "https://app.example.com/sca/callback"
        const val TEST_ORIGIN = "https://sca.example.circle.com"
    }
}
