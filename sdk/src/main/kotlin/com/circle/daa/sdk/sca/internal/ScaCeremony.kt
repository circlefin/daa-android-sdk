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

import com.circle.daa.sdk.DaaSecureRandom
import com.circle.daa.sdk.internal.authkey.Base64Url
import com.circle.daa.sdk.sca.DaaScaError
import com.circle.daa.sdk.sca.DaaScaResult
import com.circle.daa.sdk.sca.DaaScaUnsupportedReason
import java.net.URLEncoder

/** The two ceremonies the page runs. [wireValue] is what the callback's `ceremony` field carries. */
internal enum class ScaCeremonyKind(val wireValue: String) {
    Registration("registration"),
    Challenge("challenge"),
}

/**
 * One pending ceremony: everything needed to open it and to recognize its callback.
 *
 * [toString] is overridden because [frameToken] is a capability for one pending ceremony and
 * must not reach a log.
 */
internal class ScaCeremonyRequest(
    val kind: ScaCeremonyKind,
    val circleOrigin: String,
    val redirectUri: String,
    val frameToken: String,
    val state: String,
    val timeoutMillis: Long,
) {
    /**
     * `<origin>/ceremony#token=…&state=…`.
     *
     * Both values ride in the fragment, which the browser never sends to a server or puts
     * in a `Referer`; the page clears it from the address bar once read. The page matches
     * `[#&]token=([^&]+)`, so the `token=` key is load-bearing — a bare `#<token>` is read
     * as no token at all.
     */
    fun ceremonyUrl(): String = "$circleOrigin$CEREMONY_PATH#token=${encode(frameToken)}&state=${encode(state)}"

    override fun toString(): String =
        "ScaCeremonyRequest(kind=$kind, circleOrigin=$circleOrigin, timeoutMillis=$timeoutMillis)"

    internal companion object {
        const val CEREMONY_PATH = "/ceremony"

        // A ceremony token is a short opaque string. The cap bounds what reaches the intent
        // extras and the URL; anything near it is a caller bug, not a token.
        const val MAX_FRAME_TOKEN_CHARS = 4096

        // The page echoes state only if it matches [A-Za-z0-9_-]{16,128}. 32 random bytes
        // encode to 43 unpadded Base64URL characters, inside that range with no escaping.
        private const val STATE_BYTES = 32

        fun newState(): String = Base64Url.encode(DaaSecureRandom.bytes(STATE_BYTES))

        // encodeURIComponent semantics: URLEncoder is form encoding, which writes a space
        // as `+`; decodeURIComponent would read that back as a literal plus.
        private fun encode(value: String): String = URLEncoder.encode(value, "UTF-8").replace("+", "%20")
    }
}

/** A [DaaScaError.Unsupported] failure; every one carries the reason the SDK could tell. */
internal fun scaUnsupported(
    reason: DaaScaUnsupportedReason,
    message: String?,
): DaaScaResult.Failed = DaaScaResult.Failed(DaaScaError.Unsupported, message, reason)
