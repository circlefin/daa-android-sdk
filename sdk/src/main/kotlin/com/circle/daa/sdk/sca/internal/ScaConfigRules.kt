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
import java.net.URI
import java.net.URISyntaxException

/**
 * Configuration rules, kept free of `android.net.Uri` so they run as plain JVM tests.
 *
 * The redirect rules mirror the ceremony page's own check on the URI the API hands it. They
 * are not the authority — Circle's own check when it registers your redirect URIs is — but a URI this
 * rejects would be rejected there too, and failing at construction is cheaper than failing
 * in the sheet.
 */
internal object ScaConfigRules {
    private const val OVERRIDE_DOMAIN = "circle.com"
    private const val HTTPS_PREFIX = "https://"
    private const val MAX_HOST_CHARS = 253
    private const val MAX_LABEL_CHARS = 63

    private val CUSTOM_SCHEME = Regex("[a-z][a-z0-9+.-]*")

    // Schemes a browser would act on itself rather than hand to the app, or that execute
    // content. `intent:` matters most on Android: Chrome resolves it to an arbitrary
    // component, which would let the return target escape the host app entirely. The list
    // matches the schemes Circle's ceremony page and API refuse.
    private val FORBIDDEN_SCHEMES =
        setOf(
            "http", "javascript", "data", "vbscript", "blob", "file", "about", "ftp", "ws", "wss",
            "filesystem", "intent", "content", "chrome", "android-app", "mailto", "tel",
        )

    private val DOT_SEGMENTS = setOf(".", "..")

    // The public ceremony origins. Each must equal the WebAuthn origin Circle validates
    // `clientDataJSON.origin` against, by string equality. Other Circle hosts are reached
    // with DaaEnvironment.Sandbox plus an explicit, validated circleOrigin override.
    internal fun originFor(environment: DaaEnvironment): String =
        when (environment) {
            DaaEnvironment.Sandbox -> "https://daa-sca-sandbox.circle.com"
            DaaEnvironment.Production -> "https://daa-sca.circle.com"
        }

    /**
     * A ceremony-origin override: exactly `https://` followed by `circle.com` or one of its
     * subdomains, and nothing else. Every label of the host is a lowercase DNS label and the
     * host is at most [MAX_HOST_CHARS] characters, so a port, path (even `/`), query,
     * fragment, credentials, trailing dot, uppercase, or whitespace is refused. Circle compares
     * the origin as a string, so a value that would need normalizing is refused rather than
     * normalized. The check reads the raw string, as on iOS.
     *
     * The override exists for development against non-production Circle hosts. It never accepts another domain: the
     * ceremony page is where the user sees what they approve, so pointing it anywhere else
     * would hand that screen to someone other than Circle.
     */
    internal fun isValidOriginOverride(origin: String): Boolean {
        if (!origin.startsWith(HTTPS_PREFIX)) return false
        val host = origin.removePrefix(HTTPS_PREFIX)
        return (host == OVERRIDE_DOMAIN || host.endsWith(".$OVERRIDE_DOMAIN")) &&
            host.length <= MAX_HOST_CHARS &&
            host.split('.').all(::isDnsLabel)
    }

    /**
     * A lowercase LDH label: 1 to [MAX_LABEL_CHARS] of `a-z`, `0-9`, and `-`, not starting or
     * ending with a hyphen.
     */
    private fun isDnsLabel(label: String): Boolean =
        label.length in 1..MAX_LABEL_CHARS && !label.startsWith('-') && !label.endsWith('-') &&
            label.all { it in 'a'..'z' || it in '0'..'9' || it == '-' }

    /** The longest redirect URI Circle accepts when a ceremony is opened. */
    internal const val MAX_REDIRECT_URI_CHARS = 2048

    internal fun isValidRedirectUri(redirectUri: String): Boolean {
        if (redirectUri.length > MAX_REDIRECT_URI_CHARS) return false
        // No whitespace or control character anywhere: Circle matches registered redirect URIs
        // exactly, and a value that differs only in invisible characters must not reach that check.
        if (redirectUri.any { it.isWhitespace() || it.isISOControl() }) return false
        // ASCII only, as the iOS SDK requires: the browser percent-encodes any other character
        // in the path or query, so the callback could never match the configured URI.
        if (redirectUri.any { it.code > 0x7E }) return false
        val uri = parse(redirectUri) ?: return false
        val scheme = uri.scheme ?: return false
        // A fragment is where the result goes; a URI that already has one would be ambiguous.
        if (uri.rawFragment != null || redirectUri.contains('#')) return false
        if (uri.rawUserInfo != null) return false
        // Lowercase only, as the ceremony page, the iOS SDK, and Circle's redirect-URI
        // registration check require. URI keeps the scheme as written, so this sees `Acme` as typed.
        if (scheme != scheme.lowercase()) return false
        if (!survivesBrowserNavigation(uri)) return false
        return when {
            // No port, not even `:443`: App Link verification reads the association file from
            // the default port, so a URI with a port could be registered with Circle yet
            // never be delivered back to the app. Read from the raw authority because `URI.port`
            // is -1 for an empty port such as `https://host:/cb`.
            scheme == "https" -> !uri.host.isNullOrEmpty() && uri.rawAuthority?.contains(':') != true
            scheme in FORBIDDEN_SCHEMES -> false
            else -> CUSTOM_SCHEME.matches(scheme)
        }
    }

    /**
     * Whether the browser navigates to [uri] unchanged. The ceremony page appends the result
     * to the configured URI and navigates there, and the WHATWG URL parser rewrites some
     * URIs on the way; the callback would then not match the configured URI and be dropped.
     * Only what the parser actually changes is refused. Percent-encoded unreserved characters
     * other than `%2e` in a dot segment are left alone because the parser does not decode them.
     */
    private fun survivesBrowserNavigation(uri: URI): Boolean {
        // The parser removes `.` and `..` path segments, written literally or as `%2e` in any case.
        val dotSegment =
            uri.rawPath?.split('/')?.any { it.lowercase().replace("%2e", ".") in DOT_SEGMENTS } == true
        // For https the parser percent-encodes `'` in the query (it does not for other schemes).
        val quoteInHttpsQuery = uri.scheme == "https" && uri.rawQuery?.contains('\'') == true
        return !dotSegment && !quoteInHttpsQuery && (uri.scheme != "https" || isStableHttpsHost(uri.rawAuthority))
    }

    /**
     * Whether the parser leaves an https host as written, matching the iOS SDK's rule. It
     * lowercases the host, percent-decodes it, and re-serializes an IPv4 or IPv6 literal in
     * canonical form (`0x7f.1` becomes `127.0.0.1`); an IP literal cannot serve the App Link
     * association file anyway. Read from the raw authority, since `URI.host` is null for some
     * of these forms.
     */
    private fun isStableHttpsHost(rawAuthority: String?): Boolean {
        val host = rawAuthority ?: return false
        return host == host.lowercase() && '%' !in host && !host.startsWith("[") && !endsInANumber(host)
    }

    /**
     * WHATWG "ends in a number": the last label, ignoring one trailing empty label, is all
     * digits or a `0x` hex number, which sends the host to the IPv4 parser.
     */
    private fun endsInANumber(host: String): Boolean {
        val labels = host.split('.').let { if (it.size > 1 && it.last().isEmpty()) it.dropLast(1) else it }
        val last = labels.lastOrNull()?.lowercase().orEmpty()
        if (last.isEmpty()) return false
        if (last.all { it in '0'..'9' }) return true
        return last.startsWith("0x") && last.drop(2).all { it in '0'..'9' || it in 'a'..'f' }
    }

    /** Whether [redirectUri] is an `https` App Link rather than a custom scheme. */
    internal fun isHttps(redirectUri: String): Boolean = parse(redirectUri)?.scheme == "https"

    private fun parse(value: String): URI? =
        try {
            URI(value).takeIf { it.isAbsolute }
        } catch (_: URISyntaxException) {
            null
        }
}
