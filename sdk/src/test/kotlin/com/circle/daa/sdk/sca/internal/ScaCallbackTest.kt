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

import com.circle.daa.sdk.sca.DaaScaError
import com.circle.daa.sdk.sca.DaaScaResult
import com.circle.daa.sdk.sca.DaaScaUnsupportedReason
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource

class ScaCallbackTest {
    private val request =
        ScaCeremonyRequest(
            kind = ScaCeremonyKind.Challenge,
            circleOrigin = "https://sca.example.circle.com",
            redirectUri = REDIRECT,
            frameToken = "tok-1",
            state = STATE,
            timeoutMillis = 300_000,
        )

    // Both vectors were produced by the ceremony page's own encoding in Node:
    // base64url(TextEncoder().encode(JSON.stringify(payload))), padding stripped.
    // Decoding them here is the cross-language check that the two ends agree.
    @Test
    fun `a result relays the exact JSON text the page encoded`() {
        val result = parse(callback("kind=result&ceremony=challenge&payload=$ASSERTION_B64"))

        val completed = assertInstanceOf(DaaScaResult.Completed::class.java, result)
        assertEquals(ASSERTION_JSON, completed.response)
    }

    @Test
    fun `non-ASCII payload text survives the round trip`() {
        val result =
            parse(callback("kind=result&ceremony=challenge&payload=eyJpZCI6IsOp4pyT8J-UkSJ9"))

        assertEquals("{\"id\":\"é✓🔑\"}", (result as DaaScaResult.Completed).response)
    }

    @Test
    fun `Cancelled maps to the Cancelled outcome, not a failure`() {
        assertSame(DaaScaResult.Cancelled, parse(callback("kind=error&code=Cancelled")))
    }

    @ParameterizedTest
    @ValueSource(strings = ["Expired", "Unsupported", "AlreadyEnrolled"])
    fun `every error code the page redirects with maps to its DaaScaError`(code: String) {
        val result = parse(callback("kind=error&code=$code"))

        assertEquals(DaaScaError.valueOf(code), (result as DaaScaResult.Failed).error)
    }

    @Test
    fun `the page's Unsupported is a passkey failure, and only Unsupported carries a reason`() {
        val unsupported = parse(callback("kind=error&code=Unsupported&message=NotAllowedError")) as DaaScaResult.Failed
        assertEquals(DaaScaUnsupportedReason.PasskeyUnavailable, unsupported.unsupportedReason)
        assertEquals("NotAllowedError", unsupported.message)

        assertNull((parse(callback("kind=error&code=Expired")) as DaaScaResult.Failed).unsupportedReason)
        assertNull((parse(callback("kind=error&code=AlreadyEnrolled")) as DaaScaResult.Failed).unsupportedReason)
    }

    // The page never redirects these: Transport and Protocol arise before it knows where to
    // redirect, and NotEnrolled is not a ceremony outcome. One arriving with the right state
    // is therefore not the page's contract.
    @ParameterizedTest
    @ValueSource(strings = ["NotEnrolled", "Transport", "Protocol", "cancelled", "Bogus"])
    fun `a code outside the redirect set fails as Protocol`(code: String) {
        val result = parse(callback("kind=error&code=$code"))

        assertEquals(DaaScaError.Protocol, (result as DaaScaResult.Failed).error)
    }

    @Test
    fun `an error message is decoded with encodeURIComponent semantics`() {
        // From encodeURIComponent: a literal plus arrives as %2B and must stay a plus.
        val encoded = "Ceremony%20expired.%20Try%20again%20%2B%20retry%20%26%20go"
        val result = parse(callback("kind=error&code=Expired&message=$encoded"))

        assertEquals("Ceremony expired. Try again + retry & go", (result as DaaScaResult.Failed).message)
        // decodeURIComponent leaves a literal plus alone; form decoding would make it a space.
        val literal = parse(callback("kind=error&code=Expired&message=a+b"))
        assertEquals("a+b", (literal as DaaScaResult.Failed).message)
    }

    @Test
    fun `an https target matches regardless of scheme and host case and a trailing slash`() {
        val bare = request.copy(redirectUri = "https://app.example.com")
        val result = parse("HTTPS://App.Example.com/#$ENVELOPE&kind=error&code=Cancelled", bare)

        assertSame(DaaScaResult.Cancelled, result)
    }

    @Test
    fun `an explicit default https port matches no port, in either direction`() {
        val explicit = request.copy(redirectUri = "https://app.example.com:443/sca/callback")
        assertSame(DaaScaResult.Cancelled, parse(callback("kind=error&code=Cancelled"), explicit))
        assertSame(
            DaaScaResult.Cancelled,
            parse("https://app.example.com:443/sca/callback#$ENVELOPE&kind=error&code=Cancelled"),
        )
        // Any other port is still a different target.
        assertIgnored("https://app.example.com:8443/sca/callback#$ENVELOPE&kind=error&code=Cancelled")
    }

    @ParameterizedTest
    @ValueSource(
        strings = [
            "https://app.example.com/sca/callback?at=10:30",
            "https://app.example.com/sca/callback?tenant=o%27reilly",
            "https://app.example.com/sca/%7Ecb",
        ],
    )
    fun `a valid redirect URI round-trips through the browser and its callback matches`(redirectUri: String) {
        assertTrue(ScaConfigRules.isValidRedirectUri(redirectUri), redirectUri)
        assertSame(
            DaaScaResult.Cancelled,
            parse("$redirectUri#$ENVELOPE&kind=error&code=Cancelled", request.copy(redirectUri = redirectUri)),
        )
    }

    @Test
    fun `a custom-scheme target is matched`() {
        val custom = request.copy(redirectUri = "com.example.app:/sca")
        assertSame(
            DaaScaResult.Cancelled,
            parse("com.example.app:/sca#$ENVELOPE&kind=error&code=Cancelled", custom),
        )
    }

    @ParameterizedTest
    @ValueSource(
        strings = [
            // Not provably this ceremony's: no fragment, another target, malformed.
            "https://app.example.com/sca/callback",
            "https://app.example.com/sca/callback#",
            "https://app.example.com/other#v=1&state=$STATE&kind=error&code=Cancelled",
            "https://evil.example.com/sca/callback#v=1&state=$STATE&kind=error&code=Cancelled",
            "https://app.example.com/sca/callback?x=1#v=1&state=$STATE&kind=error&code=Cancelled",
            "https://app.example.com/sca/callback#v=1&state=$STATE&kind=error&code=Cancelled&=x",
            "https://app.example.com/sca/callback#v=1&state=$STATE&kind=error&code=%ZZ",
            // State: missing, wrong, and duplicated to try to win either first- or last-wins.
            "https://app.example.com/sca/callback#v=1&kind=error&code=Cancelled",
            "https://app.example.com/sca/callback#state=&kind=error&code=Cancelled",
            "https://app.example.com/sca/callback#v=1&state=$OTHER_STATE&kind=error&code=Cancelled",
            "https://app.example.com/sca/callback#v=1&state=${STATE}x&kind=error&code=Cancelled",
            "https://app.example.com/sca/callback#v=1&state=wrong&state=$STATE&kind=error&code=Cancelled",
            "https://app.example.com/sca/callback#v=1&state=$STATE&state=wrong&kind=error&code=Cancelled",
            // Any other repeated key.
            "https://app.example.com/sca/callback#v=1&state=$STATE&kind=error&code=Cancelled&code=Expired",
            "https://app.example.com/sca/callback#v=1&v=1&state=$STATE&kind=error&code=Cancelled",
            // A target carrying credentials, which the configured URI never has.
            "https://user@app.example.com/sca/callback#v=1&state=$STATE&kind=error&code=Cancelled",
            // A forged result payload without the state.
            "https://app.example.com/sca/callback#v=1&kind=result&ceremony=challenge&payload=$ASSERTION_B64",
        ],
    )
    fun `a callback that is not provably this ceremony's is ignored, not acted on`(callback: String) {
        assertIgnored(callback)
    }

    @ParameterizedTest
    @ValueSource(
        strings = [
            // Envelope, with the right state.
            "https://app.example.com/sca/callback#v=2&state=$STATE&kind=error&code=Cancelled",
            "https://app.example.com/sca/callback#v=&state=$STATE&kind=error&code=Cancelled",
            "https://app.example.com/sca/callback#state=$STATE&kind=error&code=Cancelled",
            // Shape.
            "https://app.example.com/sca/callback#v=1&state=$STATE&kind=bogus",
            "https://app.example.com/sca/callback#v=1&state=$STATE&kind=error&code=Bogus",
            "https://app.example.com/sca/callback#v=1&state=$STATE&kind=error",
            // Result: wrong ceremony kind, missing, non-canonical, non-UTF-8, and non-object payloads.
            "https://app.example.com/sca/callback#v=1&state=$STATE&kind=result&ceremony=registration&payload=e30",
            "https://app.example.com/sca/callback#v=1&state=$STATE&kind=result&ceremony=challenge",
            "https://app.example.com/sca/callback#v=1&state=$STATE&kind=result&ceremony=challenge&payload=e30=",
            "https://app.example.com/sca/callback#v=1&state=$STATE&kind=result&ceremony=challenge&payload=e31",
            "https://app.example.com/sca/callback#v=1&state=$STATE&kind=result&ceremony=challenge&payload=_w",
            "https://app.example.com/sca/callback#v=1&state=$STATE&kind=result&ceremony=challenge&payload=WzFd",
            "https://app.example.com/sca/callback#v=1&state=$STATE&kind=result&ceremony=challenge&payload=eyJh",
            // A key the page does not write for that kind.
            "https://app.example.com/sca/callback#v=1&state=$STATE&kind=result&ceremony=challenge&payload=e30&x=1",
            "https://app.example.com/sca/callback#v=1&state=$STATE&kind=error&code=Expired&ceremony=challenge",
            // A payload repeating a top-level member: {"a":1,"a":2}.
            "https://app.example.com/sca/callback#v=1&state=$STATE&kind=result&ceremony=challenge&payload=$REPEATED",
        ],
    )
    fun `an off-contract callback with the right state fails as Protocol and never completes`(callback: String) {
        val result = parse(callback)

        assertEquals(DaaScaError.Protocol, assertInstanceOf(DaaScaResult.Failed::class.java, result).error, callback)
    }

    @Test
    fun `a callback over the size limit is ignored before it is decoded`() {
        val padding = "a".repeat(ScaCallback.MAX_CALLBACK_CHARS)
        assertIgnored(callback("kind=error&code=Cancelled&message=$padding"))
        assertNull(ScaCallback.stateOf(callback("kind=error&code=Cancelled&message=$padding")))
    }

    @Test
    fun `a callback just under the size limit is still read`() {
        val head = callback("kind=error&code=Expired&message=")
        val message = "a".repeat(ScaCallback.MAX_CALLBACK_CHARS - head.length)

        assertEquals(DaaScaError.Expired, (parse(head + message) as DaaScaResult.Failed).error)
    }

    @Test
    fun `a fragment with too many fields is ignored`() {
        assertIgnored(callback("kind=error&code=Cancelled" + (1..12).joinToString("") { "&x$it=1" }))
    }

    // Deep nesting must not escape the parser as a StackOverflowError. Whether the parser
    // gets to the bottom depends on the thread's stack size, so either outcome is allowed:
    // the payload relayed unchanged, or a Protocol failure. A thrown error is not.
    @Test
    fun `deeply nested JSON under the size limit never escapes as an error`() {
        val nested = "{\"a\":" + "[".repeat(20_000) + "]".repeat(20_000) + "}"
        val payload =
            com.circle.daa.sdk.internal.authkey.Base64Url
                .encode(nested.toByteArray())

        when (val result = parse(callback("kind=result&ceremony=challenge&payload=$payload"))) {
            is DaaScaResult.Completed -> assertEquals(nested, result.response)
            is DaaScaResult.Failed -> assertEquals(DaaScaError.Protocol, result.error)
            DaaScaResult.Cancelled -> throw AssertionError("nested JSON read as Cancelled")
        }
    }

    @Test
    fun `the payload is relayed byte for byte, whitespace and key order included`() {
        val json = "{ \"b\" : 1,\n\"a\":\"\\u00e9\" }"
        val payload =
            com.circle.daa.sdk.internal.authkey.Base64Url
                .encode(json.toByteArray())

        val result = parse(callback("kind=result&ceremony=challenge&payload=$payload"))

        assertEquals(json, (result as DaaScaResult.Completed).response)
    }

    @Test
    fun `stateOf reads the state with the same bounded parse`() {
        assertEquals(STATE, ScaCallback.stateOf(callback("kind=error&code=Cancelled")))
        assertNull(ScaCallback.stateOf("https://app.example.com/sca/callback"))
        assertNull(ScaCallback.stateOf("https://app.example.com/sca/callback#state=a&state=b"))
    }

    @Test
    fun `a Protocol message never echoes the callback`() {
        val result = parse(callback("kind=result&ceremony=challenge&payload=WzFd")) as DaaScaResult.Failed

        assertFalse(result.message.orEmpty().contains(STATE))
        assertFalse(result.toString().contains("WzFd"))
    }

    @Test
    fun `a completed result keeps the response out of toString`() {
        val result = parse(callback("kind=result&ceremony=challenge&payload=$ASSERTION_B64"))

        assertFalse(result.toString().contains("cred-1"))
    }

    private fun ScaCeremonyRequest.copy(redirectUri: String) =
        ScaCeremonyRequest(kind, circleOrigin, redirectUri, frameToken, state, timeoutMillis)

    private fun parse(
        callback: String,
        request: ScaCeremonyRequest = this.request,
    ): DaaScaResult =
        assertInstanceOf(
            ScaCallbackOutcome.Final::class.java,
            ScaCallback.parse(callback, request),
        ).result

    private fun assertIgnored(callback: String) {
        assertInstanceOf(ScaCallbackOutcome.Ignored::class.java, ScaCallback.parse(callback, request), callback)
    }

    private fun callback(tail: String) = "$REDIRECT#$ENVELOPE&$tail"

    private companion object {
        const val REDIRECT = "https://app.example.com/sca/callback"
        const val STATE = "k3Jx0Qp2V9mZsYbT7uWc1eFgHiLnOrAdEvGhIjKlMn0"
        const val ENVELOPE = "v=1&state=$STATE"

        // Well-formed, the right length, and not this ceremony's.
        const val OTHER_STATE = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

        // {"a":1,"a":2}: a payload repeating a top-level member.
        const val REPEATED = "eyJhIjoxLCJhIjoyfQ"

        const val ASSERTION_JSON =
            "{\"id\":\"cred-1\",\"rawId\":\"cred-1\",\"type\":\"public-key\",\"response\":{\"clientDataJSON\":" +
                "\"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0\",\"authenticatorData\":\"SZYN5YgO\",\"signature\":\"MEUCIQ\"," +
                "\"userHandle\":\"dXNlcg\"},\"clientExtensionResults\":{},\"authenticatorAttachment\":\"platform\"}"
        const val ASSERTION_B64 =
            "eyJpZCI6ImNyZWQtMSIsInJhd0lkIjoiY3JlZC0xIiwidHlwZSI6InB1YmxpYy1rZXkiLCJyZXNwb25zZSI6eyJjbGllbnREYXRh" +
                "SlNPTiI6ImV5SjBlWEJsSWpvaWQyVmlZWFYwYUc0dVoyVjBJbjAiLCJhdXRoZW50aWNhdG9yRGF0YSI6IlNaWU41WWdPIiwic2ln" +
                "bmF0dXJlIjoiTUVVQ0lRIiwidXNlckhhbmRsZSI6ImRYTmxjZyJ9LCJjbGllbnRFeHRlbnNpb25SZXN1bHRzIjp7fSwiYXV0aGVu" +
                "dGljYXRvckF0dGFjaG1lbnQiOiJwbGF0Zm9ybSJ9"
    }
}
