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

import androidx.browser.auth.AuthTabIntent
import com.circle.daa.sdk.sca.DaaScaUnsupportedReason
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ScaBrowserPolicyTest {
    @Test
    fun `an allowed browser with Auth Tab gets an Auth Tab for an https callback`() {
        val env = FakeBrowsers(chrome(authTab = true))

        assertEquals(
            ScaLaunchPlan.AuthTab.Https(CHROME, "app.example.com", "/sca/callback"),
            ScaBrowserPolicy.select(env, HTTPS_REDIRECT),
        )
    }

    @Test
    fun `an allowed browser with Auth Tab gets an Auth Tab for a custom scheme`() {
        val env = FakeBrowsers(chrome(authTab = true))

        assertEquals(
            ScaLaunchPlan.AuthTab.CustomScheme(CHROME, "com.example.app"),
            ScaBrowserPolicy.select(env, "com.example.app:/sca"),
        )
    }

    @Test
    fun `a custom scheme is Unsupported, never a Custom Tab, when no allowed browser offers an Auth Tab`() {
        // In a Custom Tab, Android hands a custom-scheme redirect to any app that declares it.
        val env =
            FakeBrowsers(
                chrome(authTab = false),
                browser(FIREFOX, allowlisted(FIREFOX)),
                default = FIREFOX,
            )

        assertEquals(
            ScaLaunchPlan.Unsupported(
                DaaScaUnsupportedReason.InsecureRedirect,
                "A custom-scheme redirect URI needs a browser with Auth Tab support",
            ),
            ScaBrowserPolicy.select(env, CUSTOM_SCHEME_REDIRECT),
        )
    }

    @Test
    fun `a custom scheme uses an Auth Tab in any allowed browser, even one that is not the default`() {
        val env =
            FakeBrowsers(
                browser(FIREFOX, allowlisted(FIREFOX)),
                chrome(authTab = true),
                default = FIREFOX,
            )

        assertEquals(
            ScaLaunchPlan.AuthTab.CustomScheme(CHROME, "com.example.app"),
            ScaBrowserPolicy.select(env, CUSTOM_SCHEME_REDIRECT),
        )
    }

    @Test
    fun `an unlisted browser's Auth Tab does not admit a custom scheme`() {
        val env =
            FakeBrowsers(
                browser("com.example.browser", setOf(DIGEST_A), authTab = true),
                chrome(authTab = false),
            )

        assertUnsupported(
            DaaScaUnsupportedReason.InsecureRedirect,
            ScaBrowserPolicy.select(env, CUSTOM_SCHEME_REDIRECT),
        )
    }

    @Test
    fun `an https callback with an explicit port falls back to a Custom Tab`() {
        val env = FakeBrowsers(chrome(authTab = true))

        assertEquals(ScaLaunchPlan.CustomTab(CHROME), ScaBrowserPolicy.select(env, "https://app.example.com:8443/cb"))
    }

    @Test
    fun `an allowed browser without Auth Tab gets a Custom Tab for an https callback`() {
        val env = FakeBrowsers(browser(FIREFOX, allowlisted(FIREFOX)))

        assertEquals(ScaLaunchPlan.CustomTab(FIREFOX), ScaBrowserPolicy.select(env, HTTPS_REDIRECT))
    }

    @Test
    fun `Auth Tab is preferred even when the default browser only offers a Custom Tab`() {
        val env =
            FakeBrowsers(
                browser(SAMSUNG, allowlisted(SAMSUNG)),
                chrome(authTab = true),
                default = SAMSUNG,
            )

        assertEquals(
            ScaLaunchPlan.AuthTab.Https(CHROME, "app.example.com", "/sca/callback"),
            ScaBrowserPolicy.select(env, HTTPS_REDIRECT),
        )
    }

    @Test
    fun `the default browser is preferred among allowed Custom Tab browsers`() {
        val env =
            FakeBrowsers(
                chrome(authTab = false),
                browser(FIREFOX, allowlisted(FIREFOX)),
                default = FIREFOX,
            )

        assertEquals(ScaLaunchPlan.CustomTab(FIREFOX), ScaBrowserPolicy.select(env, HTTPS_REDIRECT))
    }

    @Test
    fun `an unlisted default browser is skipped, never used`() {
        val env =
            FakeBrowsers(
                browser("com.example.browser", setOf(DIGEST_A)),
                chrome(authTab = false),
                default = "com.example.browser",
            )

        assertEquals(ScaLaunchPlan.CustomTab(CHROME), ScaBrowserPolicy.select(env, HTTPS_REDIRECT))
    }

    @Test
    fun `a listed package name with a different signing certificate is refused`() {
        // An app installed under Chrome's package name but not signed by Chrome's key.
        val env = FakeBrowsers(browser(CHROME, setOf(DIGEST_A), authTab = true))

        assertTrue(ScaBrowserPolicy.select(env, HTTPS_REDIRECT) is ScaLaunchPlan.Unsupported)
    }

    @Test
    fun `an extra unknown signer is refused even beside a listed one`() {
        val env = FakeBrowsers(browser(CHROME, allowlisted(CHROME) + DIGEST_A))

        assertTrue(ScaBrowserPolicy.select(env, HTTPS_REDIRECT) is ScaLaunchPlan.Unsupported)
    }

    @Test
    fun `unreadable signatures are refused`() {
        val env = FakeBrowsers(browser(CHROME, emptySet()))

        assertTrue(ScaBrowserPolicy.select(env, HTTPS_REDIRECT) is ScaLaunchPlan.Unsupported)
    }

    @Test
    fun `no allowed browser is Unsupported, never an external browser`() {
        assertUnsupported(
            DaaScaUnsupportedReason.NoAllowedBrowser,
            ScaBrowserPolicy.select(FakeBrowsers(), HTTPS_REDIRECT),
        )
        val unlisted = FakeBrowsers(browser("com.example.browser", setOf(DIGEST_A), authTab = true))
        assertUnsupported(DaaScaUnsupportedReason.NoAllowedBrowser, ScaBrowserPolicy.select(unlisted, HTTPS_REDIRECT))
        assertUnsupported(
            DaaScaUnsupportedReason.NoAllowedBrowser,
            ScaBrowserPolicy.select(unlisted, CUSTOM_SCHEME_REDIRECT),
        )
    }

    @Test
    fun `allowlist digests are accepted in either case`() {
        assertTrue(ScaBrowserAllowlist.isAllowed(CHROME, allowlisted(CHROME).map { it.lowercase() }.toSet()))
        assertFalse(ScaBrowserAllowlist.isAllowed("com.example.browser", allowlisted(CHROME)))
    }

    @Test
    fun `digest formatting matches the allowlist's form`() {
        assertEquals("00:0F:A0:FF", ScaBrowserAllowlist.format(byteArrayOf(0x00, 0x0F, 0xA0.toByte(), 0xFF.toByte())))
    }

    // A change to this pin is a security change: see ScaBrowserAllowlist for how to update it.
    @Test
    fun `the allowlist is exactly the reviewed set`() {
        assertEquals(
            listOf(
                "com.android.chrome",
                "com.sec.android.app.sbrowser",
                "org.mozilla.firefox",
                "com.microsoft.emmx",
                "com.brave.browser",
                "com.duckduckgo.mobile.android",
                "com.opera.browser",
                "com.opera.mini.native",
                "com.vivaldi.browser",
                "org.mozilla.focus",
                "org.mozilla.klar",
                "cz.seznam.sbrowser",
            ),
            ScaBrowserAllowlist.BROWSERS.keys.toList(),
        )
        assertEquals(12, ScaBrowserAllowlist.BROWSERS.values.sumOf { it.size })
        // Release signers only; Google's list also carries these userdebug signers.
        val userdebug =
            setOf(
                "19:75:B2:F1:71:77:BC:89:A5:DF:F3:1F:9E:64:A6:CA:E2:81:A5:3D:C1:D1:D5:9B:1D:14:7F:E1:C8:2A:FA:00",
                "C8:A2:E9:BC:CF:59:7C:2F:B6:DC:66:BE:E2:93:FC:13:F2:FC:47:EC:77:BC:6B:2B:0D:52:C1:1F:51:19:2A:B8",
            )
        assertTrue(ScaBrowserAllowlist.BROWSERS.values.flatten().none { it in userdebug })
        ScaBrowserAllowlist.BROWSERS.values.flatten().forEach { digest ->
            assertTrue(Regex("([0-9A-F]{2}:){31}[0-9A-F]{2}").matches(digest), digest)
        }
    }

    @Test
    fun `with no override the production allowlist is in force`() {
        assertTrue(ScaAllowlistOverride.browsers == null)
        assertTrue(ScaBrowserAllowlist.effective() === ScaBrowserAllowlist.BROWSERS)
    }

    @Test
    fun `Auth Tab result codes match the library's`() {
        assertEquals(AuthTabIntent.RESULT_OK, ScaAuthTabResult.OK)
        assertEquals(AuthTabIntent.RESULT_CANCELED, ScaAuthTabResult.CANCELED)
        assertEquals(AuthTabIntent.RESULT_VERIFICATION_FAILED, ScaAuthTabResult.VERIFICATION_FAILED)
        assertEquals(AuthTabIntent.RESULT_VERIFICATION_TIMED_OUT, ScaAuthTabResult.VERIFICATION_TIMED_OUT)
    }

    private fun assertUnsupported(
        reason: DaaScaUnsupportedReason,
        plan: ScaLaunchPlan,
    ) {
        assertEquals(reason, assertInstanceOf(ScaLaunchPlan.Unsupported::class.java, plan).reason)
    }

    private data class Browser(val packageName: String, val digests: Set<String>, val authTab: Boolean)

    private class FakeBrowsers(
        vararg browsers: Browser,
        private val default: String? = null,
    ) : ScaBrowserEnvironment {
        private val byName = browsers.associateBy { it.packageName }

        override fun customTabsPackages(): List<String> = byName.keys.toList()

        override fun defaultBrowserPackage(): String? = default

        override fun signerDigests(packageName: String): Set<String> = byName[packageName]?.digests.orEmpty()

        override fun supportsAuthTab(packageName: String): Boolean = byName[packageName]?.authTab == true
    }

    private companion object {
        const val CHROME = "com.android.chrome"
        const val FIREFOX = "org.mozilla.firefox"
        const val SAMSUNG = "com.sec.android.app.sbrowser"
        const val HTTPS_REDIRECT = "https://app.example.com/sca/callback"
        const val CUSTOM_SCHEME_REDIRECT = "com.example.app:/sca"
        val DIGEST_A = List(32) { "AA" }.joinToString(":")

        fun allowlisted(packageName: String): Set<String> =
            setOf(
                ScaBrowserAllowlist.BROWSERS.getValue(packageName).first(),
            )

        fun browser(
            packageName: String,
            digests: Set<String>,
            authTab: Boolean = false,
        ) = Browser(packageName, digests, authTab)

        fun chrome(authTab: Boolean) = browser(CHROME, allowlisted(CHROME), authTab)
    }
}
