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

import com.circle.daa.sdk.internal.authkey.Base64Url
import com.circle.daa.sdk.internal.authkey.DuplicateJsonKeys
import com.circle.daa.sdk.sca.DaaScaError
import com.circle.daa.sdk.sca.DaaScaResult
import com.circle.daa.sdk.sca.DaaScaUnsupportedReason
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import java.net.URI
import java.net.URISyntaxException
import java.net.URLDecoder
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.security.MessageDigest

/** What a callback means for the ceremony in flight. */
internal sealed class ScaCallbackOutcome {
    /** The ceremony ended with [result]. */
    class Final(val result: DaaScaResult) : ScaCallbackOutcome()

    /**
     * The callback is not provably this ceremony's, so it is dropped and the ceremony keeps
     * waiting. [reason] is diagnostic text that never echoes the callback.
     */
    class Ignored(val reason: String) : ScaCallbackOutcome()
}

/**
 * Reads the ceremony page's redirect back into a [DaaScaResult].
 *
 * The page navigates to `<redirectUri>#v=1&state=…&kind=result&ceremony=…&payload=…` or
 * `…&kind=error&code=…&message=…`. The result is in the fragment so it never reaches a
 * server access log if the redirect URI is an App Link that falls through to the web.
 *
 * Only the page knows the ceremony's random `state`, so a callback is acted on only once its
 * `state` is proven to match. Anything that fails before that point — wrong target, a
 * missing or different `state`, a repeated key, an oversized or malformed fragment — is
 * [ScaCallbackOutcome.Ignored]: the callback activity is exported, and a callback another
 * app forged must not be able to end a ceremony the user is in the middle of. After `state`
 * matches, an off-contract callback is a defect in the page and ends the ceremony as
 * [DaaScaError.Protocol].
 *
 * The payload text is handed through untouched. The parser does not look inside the
 * WebAuthn response: the server verifies that, and a client that reshaped it would break
 * the exact-bytes relay the backend depends on.
 */
internal object ScaCallback {
    internal const val PROTOCOL_VERSION = 1

    /**
     * Upper bound on a whole callback URI, in characters. A WebAuthn assertion or
     * registration response is a few kilobytes; this leaves an order of magnitude of
     * headroom while keeping a hostile intent from making the parser decode megabytes.
     */
    internal const val MAX_CALLBACK_CHARS = 64 * 1024

    // The page sends at most six fields. The cap bounds the parse before `state` is known;
    // which keys are allowed is checked once it is (see RESULT_KEYS and ERROR_KEYS).
    private const val MAX_FIELDS = 12

    // Exactly the keys the page writes for each kind. Key names are part of the contract and
    // change only together with the SDKs, so any other key is off contract, as on iOS.
    private val RESULT_KEYS = setOf("v", "state", "kind", "ceremony", "payload")
    private val ERROR_KEYS = setOf("v", "state", "kind", "code", "message")

    private const val HTTPS_DEFAULT_PORT = 443

    // The codes the page redirects with. Transport and Protocol cannot arrive here: both
    // happen before the page has loaded the ceremony, when it does not yet know where to
    // redirect, and the SDK reports them through its timeout instead. NotEnrolled is not a
    // ceremony outcome at all: a ceremony only exists for a registration or challenge.
    private const val CANCELLED = "Cancelled"
    private const val EXPIRED = "Expired"
    private const val UNSUPPORTED = "Unsupported"
    private const val ALREADY_ENROLLED = "AlreadyEnrolled"

    internal fun parse(
        callbackUri: String,
        request: ScaCeremonyRequest,
    ): ScaCallbackOutcome {
        val fields = verifiedFields(callbackUri, request.redirectUri, request.state)
        if (fields is Verified.No) return ScaCallbackOutcome.Ignored(fields.reason)
        val params = (fields as Verified.Yes).params

        if (params["v"] != PROTOCOL_VERSION.toString()) return protocol("Unsupported callback version")
        return when (params["kind"]) {
            "result" -> if (RESULT_KEYS.containsAll(params.keys)) readResult(params, request.kind) else unexpectedKey()
            "error" -> if (ERROR_KEYS.containsAll(params.keys)) readError(params) else unexpectedKey()
            else -> protocol("Unknown callback kind")
        }
    }

    private fun unexpectedKey() = protocol("Callback carried an unexpected parameter")

    /**
     * The `state` [callbackUri] carries, read with the same bounded parse [parse] uses, or
     * null if it carries none or the fragment is malformed. The callback activity uses it
     * to drop a forged callback before touching the ceremony, so the browser tab survives.
     */
    internal fun stateOf(callbackUri: String): String? {
        if (callbackUri.length > MAX_CALLBACK_CHARS) return null
        val hash = callbackUri.indexOf('#')
        if (hash < 0) return null
        return readParams(callbackUri.substring(hash + 1))?.get("state")
    }

    /**
     * Whether [callbackUri] arrived at [redirectUri] (the part before `#`, compared as
     * [parse] compares it). The callback activity checks this together with the state before
     * forwarding, so a callback for the wrong target is dropped without touching the tab.
     */
    internal fun arrivedAt(
        callbackUri: String,
        redirectUri: String,
    ): Boolean {
        if (callbackUri.length > MAX_CALLBACK_CHARS) return false
        val hash = callbackUri.indexOf('#')
        return hash >= 0 && sameTarget(callbackUri.substring(0, hash), redirectUri)
    }

    private sealed class Verified {
        class Yes(val params: Map<String, String>) : Verified()

        class No(val reason: String) : Verified()
    }

    private fun verifiedFields(
        callbackUri: String,
        redirectUri: String,
        state: String,
    ): Verified {
        if (callbackUri.length > MAX_CALLBACK_CHARS) return Verified.No("Callback exceeds the size limit")
        val hash = callbackUri.indexOf('#')
        if (hash < 0) return Verified.No("Callback carried no fragment")
        if (!sameTarget(callbackUri.substring(0, hash), redirectUri)) {
            return Verified.No("Callback did not arrive at the configured redirect URI")
        }
        val params = readParams(callbackUri.substring(hash + 1)) ?: return Verified.No("Callback fragment is malformed")
        // State ties this callback to the ceremony this activity opened. Without it, a
        // stale callback from an earlier ceremony, or one fired at the exported callback
        // activity by another app, would be indistinguishable from the real one.
        if (!sameState(params["state"], state)) return Verified.No("Callback state does not match this ceremony")
        return Verified.Yes(params)
    }

    private fun readResult(
        params: Map<String, String>,
        expected: ScaCeremonyKind,
    ): ScaCallbackOutcome {
        if (params["ceremony"] != expected.wireValue) return protocol("Callback is for a different ceremony kind")
        val bytes = params["payload"]?.let(Base64Url::decode) ?: return protocol("Callback payload is not Base64URL")
        val text = strictUtf8(bytes) ?: return protocol("Callback payload is not UTF-8")
        if (!isJsonObject(text)) return protocol("Callback payload is not a JSON object")
        // The parsed object keeps one of two repeated members, but the relayed text keeps both,
        // and the server's parser may pick the other.
        if (DuplicateJsonKeys.existAtTopLevel(text)) return protocol("Callback payload repeats a member")
        // The decoded text itself, not a re-serialization of the parsed object: it becomes
        // a header value the server verifies byte for byte.
        return ScaCallbackOutcome.Final(DaaScaResult.Completed(text))
    }

    private fun readError(params: Map<String, String>): ScaCallbackOutcome {
        val message = params["message"]
        val result =
            when (params["code"]) {
                CANCELLED -> DaaScaResult.Cancelled
                EXPIRED -> DaaScaResult.Failed(DaaScaError.Expired, message)
                ALREADY_ENROLLED -> DaaScaResult.Failed(DaaScaError.AlreadyEnrolled, message)
                // The page sends Unsupported for every WebAuthn failure, so the SDK cannot
                // narrow it further than "the browser could not run the passkey call".
                UNSUPPORTED ->
                    scaUnsupported(DaaScaUnsupportedReason.PasskeyUnavailable, message)
                else -> return protocol("Unknown callback error code")
            }
        return ScaCallbackOutcome.Final(result)
    }

    private fun isJsonObject(text: String): Boolean =
        try {
            Json.parseToJsonElement(text) is JsonObject
        } catch (_: SerializationException) {
            false
        } catch (_: IllegalArgumentException) {
            false
        } catch (_: StackOverflowError) {
            // Deeply nested JSON within the size cap. Only this error is caught: an
            // OutOfMemoryError or other VM failure is not "bad input".
            false
        }

    // Constant-time, so how much of a guessed state matched is not observable.
    private fun sameState(
        actual: String?,
        expected: String,
    ): Boolean = actual != null && MessageDigest.isEqual(actual.toByteArray(), expected.toByteArray())

    // The browser, not this SDK, produced the part before `#`, so compare it structurally:
    // scheme and host are case-insensitive, an empty https path is the same as `/`, and an
    // explicit default port is the same as none. A configured URI never has credentials, so
    // a target that carries them is another target, as on iOS.
    private fun sameTarget(
        actual: String,
        configured: String,
    ): Boolean {
        val a = parseUri(actual) ?: return false
        val c = parseUri(configured) ?: return false
        if (!a.scheme.equals(c.scheme, ignoreCase = true)) return false
        if (a.isOpaque || c.isOpaque) {
            return a.isOpaque && c.isOpaque && a.rawSchemeSpecificPart == c.rawSchemeSpecificPart
        }
        return a.rawUserInfo == null &&
            a.host.equals(c.host, ignoreCase = true) &&
            effectivePort(a) == effectivePort(c) &&
            a.rawPath.ifEmpty { "/" } == c.rawPath.ifEmpty { "/" } &&
            a.rawQuery == c.rawQuery
    }

    private fun effectivePort(uri: URI): Int =
        if (uri.port == -1 && uri.scheme.equals("https", ignoreCase = true)) HTTPS_DEFAULT_PORT else uri.port

    private fun parseUri(value: String): URI? =
        try {
            URI(value)
        } catch (_: URISyntaxException) {
            null
        }

    // A repeated key is rejected rather than resolved first- or last-wins: two readers that
    // pick differently would disagree about what the page said.
    private fun readParams(fragment: String): Map<String, String>? {
        if (fragment.isEmpty()) return null
        val pairs = fragment.split('&', limit = MAX_FIELDS + 1)
        if (pairs.size > MAX_FIELDS) return null
        val out = HashMap<String, String>()
        for (pair in pairs) {
            val eq = pair.indexOf('=')
            if (eq <= 0) return null
            val key = pair.substring(0, eq)
            val value =
                try {
                    // decodeURIComponent semantics, as on iOS: a literal `+` stays a plus.
                    // URLDecoder is form decoding, which would read it as a space.
                    URLDecoder.decode(pair.substring(eq + 1).replace("+", "%2B"), "UTF-8")
                } catch (_: IllegalArgumentException) {
                    return null
                }
            if (out.put(key, value) != null) return null
        }
        return out
    }

    private fun strictUtf8(bytes: ByteArray): String? =
        try {
            Charsets.UTF_8
                .newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes))
                .toString()
        } catch (_: CharacterCodingException) {
            null
        }

    private fun protocol(message: String) = ScaCallbackOutcome.Final(DaaScaResult.Failed(DaaScaError.Protocol, message))
}
