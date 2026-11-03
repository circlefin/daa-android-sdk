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
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ScaCeremonyControllerTest {
    private val customTab = FakeLaunch(ScaLaunchPlan.CustomTab(BROWSER))
    private val authTab = FakeLaunch(ScaLaunchPlan.AuthTab.Https(BROWSER, "app.example.com", "/sca/callback"))

    @Test
    fun `the first resume opens the ceremony on the planned surface`() {
        val controller = controller()

        assertEquals(ScaAction.Launch(ScaLaunchPlan.CustomTab(BROWSER)), controller.onResume(T0, customTab))
        assertEquals(ScaSurfaceKind.CustomTab, controller.launched)
    }

    @Test
    fun `resuming from a Custom Tab without a callback is Cancelled`() {
        // The user closed the tab, or the page told them to return to the app because the
        // token had expired or was already used: neither can redirect.
        val controller = launched(customTab)

        assertSame(DaaScaResult.Cancelled, finished(controller.onResume(T0 + 1_000, customTab)))
    }

    @Test
    fun `resuming under an Auth Tab waits for the browser's own result`() {
        val controller = launched(authTab)

        assertSame(ScaAction.Wait, controller.onResume(T0 + 1_000, authTab))
    }

    @Test
    fun `a valid callback completes the ceremony with the exact payload`() {
        val controller = launched(customTab)

        val result = finished(controller.onCallback(T0, callback("kind=result&ceremony=challenge&payload=e30")))

        assertEquals("{}", assertInstanceOf(DaaScaResult.Completed::class.java, result).response)
    }

    @Test
    fun `a wrong-state callback is ignored and the ceremony keeps waiting`() {
        val controller = launched(customTab)

        val forged = "$REDIRECT#v=1&state=$OTHER_STATE&kind=error&code=Cancelled"
        assertSame(ScaAction.Wait, controller.onCallback(T0, forged))
        assertSame(ScaAction.Wait, controller.onCallback(T0, "$REDIRECT#v=1&kind=error&code=Cancelled"))

        // The real callback still lands afterwards.
        assertSame(DaaScaResult.Cancelled, finished(controller.onCallback(T0, callback("kind=error&code=Cancelled"))))
    }

    @Test
    fun `the timeout ends the ceremony as Expired`() {
        val controller = launched(customTab)

        assertSame(ScaAction.Wait, controller.onTimeout(T0 + TIMEOUT - 1))
        val result = finished(controller.onTimeout(T0 + TIMEOUT))

        assertEquals(DaaScaError.Expired, assertInstanceOf(DaaScaResult.Failed::class.java, result).error)
    }

    @Test
    fun `a resume after the deadline is Expired rather than Cancelled`() {
        val controller = launched(customTab)

        val result = finished(controller.onResume(T0 + TIMEOUT, customTab))

        assertEquals(DaaScaError.Expired, (result as DaaScaResult.Failed).error)
    }

    @Test
    fun `a callback just before the deadline is accepted, at or after it is Expired`() {
        val payload = callback("kind=result&ceremony=challenge&payload=e30")

        val before = finished(launched(customTab).onCallback(T0 + TIMEOUT - 1, payload))
        assertInstanceOf(DaaScaResult.Completed::class.java, before)

        assertExpired(finished(launched(customTab).onCallback(T0 + TIMEOUT, payload)))
        assertExpired(finished(launched(customTab).onCallback(T0 + TIMEOUT + 1, payload)))
    }

    @Test
    fun `an Auth Tab result just before the deadline is accepted, at or after it is Expired`() {
        val payload = callback("kind=result&ceremony=challenge&payload=e30")

        val before = finished(launched(authTab).onAuthTabResult(T0 + TIMEOUT - 1, ScaAuthTabResult.OK, payload))
        assertInstanceOf(DaaScaResult.Completed::class.java, before)

        assertExpired(finished(launched(authTab).onAuthTabResult(T0 + TIMEOUT, ScaAuthTabResult.OK, payload)))
        assertExpired(finished(launched(authTab).onAuthTabResult(T0 + TIMEOUT + 1, ScaAuthTabResult.OK, payload)))
        // Not only a success: a late cancel is the same expired ceremony.
        assertExpired(finished(launched(authTab).onAuthTabResult(T0 + TIMEOUT, ScaAuthTabResult.CANCELED, null)))
    }

    @Test
    fun `a restored ceremony past its deadline is Expired even when a result arrives before any resume`() {
        // After process death AndroidX redelivers a pending Auth Tab result as the recreated
        // activity starts, before onResume has had a chance to check the deadline.
        val payload = callback("kind=result&ceremony=challenge&payload=e30")
        val underAuthTab = ScaCeremonyController(request(), T0 + TIMEOUT, ScaSurfaceKind.AuthTab)
        val underCustomTab = ScaCeremonyController(request(), T0 + TIMEOUT, ScaSurfaceKind.CustomTab)

        assertExpired(finished(underAuthTab.onAuthTabResult(T0 + TIMEOUT + 60_000, ScaAuthTabResult.OK, payload)))
        assertExpired(finished(underCustomTab.onCallback(T0 + TIMEOUT + 60_000, payload)))
        assertSame(ScaAction.Wait, underAuthTab.onResume(T0 + TIMEOUT + 60_001, authTab))
    }

    @Test
    fun `a failed launch or a second launch past the deadline is Expired`() {
        assertExpired(finished(launched(customTab).onLaunchFailed(T0 + TIMEOUT)))
        assertExpired(finished(launched(customTab).onNewRequest(T0 + TIMEOUT)))
    }

    @Test
    fun `a restored ceremony keeps its original deadline`() {
        // After process death the activity rebuilds the controller from saved state.
        val restored = ScaCeremonyController(request(), T0 + TIMEOUT, ScaSurfaceKind.CustomTab)

        assertSame(ScaAction.Wait, restored.onTimeout(T0 + TIMEOUT - 1))
        assertEquals(DaaScaError.Expired, (finished(restored.onTimeout(T0 + TIMEOUT)) as DaaScaResult.Failed).error)
    }

    @Test
    fun `a deadline saturates instead of wrapping negative`() {
        val nearMax = Long.MAX_VALUE - 1_000
        val started = ScaCeremonyController.start(request(), nearMax)

        assertEquals(Long.MAX_VALUE, started.deadline)
        assertTrue(started.onResume(nearMax, customTab) is ScaAction.Launch)
        assertSame(ScaAction.Wait, started.onTimeout(nearMax + 1))

        // An oversized timeout that bypassed DaaScaConfig is still not an instant expiry.
        val huge = ScaCeremonyRequest(ScaCeremonyKind.Challenge, ORIGIN, REDIRECT, "tok-1", STATE, Long.MAX_VALUE)
        assertEquals(Long.MAX_VALUE, ScaCeremonyController.start(huge, T0).deadline)
        assertEquals(T0 + TIMEOUT, ScaCeremonyController.start(request(), T0).deadline)
    }

    @Test
    fun `step-up with a custom-scheme callback is Unsupported and opens nothing`() {
        val launch = FakeLaunch(ScaLaunchPlan.AuthTab.CustomScheme(BROWSER, "com.example.app"))
        val controller = controller(request(redirectUri = "com.example.app:/sca"))

        val result = finished(controller.onResume(T0, launch))

        assertUnsupported(DaaScaUnsupportedReason.InsecureRedirect, result)
        assertEquals(0, launch.plans)
    }

    @Test
    fun `enrollment with a custom-scheme callback opens`() {
        val launch = FakeLaunch(ScaLaunchPlan.AuthTab.CustomScheme(BROWSER, "com.example.app"))
        val controller = controller(request(kind = ScaCeremonyKind.Registration, redirectUri = "com.example.app:/sca"))

        assertTrue(controller.onResume(T0, launch) is ScaAction.Launch)
    }

    @Test
    fun `enrollment with a custom-scheme callback and no Auth Tab is Unsupported and opens nothing`() {
        // The real policy over a device whose only allowed browser lacks Auth Tab: it would
        // otherwise offer a Custom Tab, and the host has a callback route for the scheme.
        val launch = PolicyLaunch(FakeBrowser(authTab = false))
        val controller = controller(request(kind = ScaCeremonyKind.Registration, redirectUri = "com.example.app:/sca"))

        val result = finished(controller.onResume(T0, launch))

        assertUnsupported(DaaScaUnsupportedReason.InsecureRedirect, result)
        assertEquals(null, controller.launched)
    }

    @Test
    fun `enrollment with an https callback and no Auth Tab still opens a Custom Tab`() {
        val launch = PolicyLaunch(FakeBrowser(authTab = false))
        val controller = controller(request(kind = ScaCeremonyKind.Registration))

        assertEquals(ScaAction.Launch(ScaLaunchPlan.CustomTab(BROWSER)), controller.onResume(T0, launch))
        assertEquals(ScaSurfaceKind.CustomTab, controller.launched)
    }

    @Test
    fun `enrollment with a custom-scheme callback opens an Auth Tab when one is offered`() {
        val launch = PolicyLaunch(FakeBrowser(authTab = true))
        val controller = controller(request(kind = ScaCeremonyKind.Registration, redirectUri = "com.example.app:/sca"))

        assertEquals(
            ScaAction.Launch(ScaLaunchPlan.AuthTab.CustomScheme(BROWSER, "com.example.app")),
            controller.onResume(T0, launch),
        )
        assertEquals(ScaSurfaceKind.AuthTab, controller.launched)
    }

    @Test
    fun `a plan's Unsupported reason is the result's`() {
        val none = FakeLaunch(ScaLaunchPlan.Unsupported(DaaScaUnsupportedReason.NoAllowedBrowser, "none"))
        assertUnsupported(DaaScaUnsupportedReason.NoAllowedBrowser, finished(controller().onResume(T0, none)))

        val insecure = FakeLaunch(ScaLaunchPlan.Unsupported(DaaScaUnsupportedReason.InsecureRedirect, "no Auth Tab"))
        assertUnsupported(DaaScaUnsupportedReason.InsecureRedirect, finished(controller().onResume(T0, insecure)))
    }

    @Test
    fun `a Custom Tab without a registered callback is Unsupported, but an Auth Tab needs none`() {
        val unregistered = FakeLaunch(ScaLaunchPlan.CustomTab(BROWSER), callbackRegistered = false)
        assertUnsupported(
            DaaScaUnsupportedReason.CallbackNotRouted,
            finished(controller().onResume(T0, unregistered)),
        )

        val authTabOnly =
            FakeLaunch(ScaLaunchPlan.AuthTab.Https(BROWSER, "app.example.com", "/cb"), callbackRegistered = false)
        assertTrue(controller().onResume(T0, authTabOnly) is ScaAction.Launch)
    }

    @Test
    fun `a failed launch is Unsupported`() {
        val controller = launched(customTab)

        assertUnsupported(DaaScaUnsupportedReason.NoAllowedBrowser, finished(controller.onLaunchFailed(T0)))
    }

    @Test
    fun `Auth Tab results map to the outcome they report`() {
        assertSame(
            DaaScaResult.Cancelled,
            finished(launched(authTab).onAuthTabResult(T0, ScaAuthTabResult.CANCELED, null)),
        )
        assertEquals(
            "{}",
            (
                finished(
                    launched(
                        authTab,
                    ).onAuthTabResult(T0, ScaAuthTabResult.OK, callback("kind=result&ceremony=challenge&payload=e30")),
                ) as DaaScaResult.Completed
            ).response,
        )
        assertUnsupported(
            DaaScaUnsupportedReason.AppLinkNotVerified,
            finished(launched(authTab).onAuthTabResult(T0, ScaAuthTabResult.VERIFICATION_FAILED, null)),
        )
        assertEquals(
            DaaScaError.Transport,
            (
                finished(
                    launched(authTab).onAuthTabResult(T0, ScaAuthTabResult.VERIFICATION_TIMED_OUT, null),
                ) as DaaScaResult.Failed
            ).error,
        )
        assertEquals(
            DaaScaError.Protocol,
            (finished(launched(authTab).onAuthTabResult(T0, -2, null)) as DaaScaResult.Failed).error,
        )
        assertEquals(
            DaaScaError.Protocol,
            (finished(launched(authTab).onAuthTabResult(T0, ScaAuthTabResult.OK, null)) as DaaScaResult.Failed).error,
        )
    }

    @Test
    fun `an Auth Tab redirect with the wrong state cannot complete the ceremony`() {
        val forged = "$REDIRECT#v=1&state=$OTHER_STATE&kind=result&ceremony=challenge&payload=e30"

        val result = finished(launched(authTab).onAuthTabResult(T0, ScaAuthTabResult.OK, forged))

        assertEquals(DaaScaError.Protocol, (result as DaaScaResult.Failed).error)
    }

    @Test
    fun `a second launch over an open tab cancels the open ceremony and runs nothing else`() {
        // Android delivers the reused activity's result only to the first caller, so the
        // first caller must hear Cancelled, never the second ceremony's response.
        val controller = launched(customTab)

        assertSame(DaaScaResult.Cancelled, finished(controller.onNewRequest(T0)))

        // Nothing afterwards reopens a ceremony or produces a second result.
        assertSame(ScaAction.Wait, controller.onResume(T0 + 1, customTab))
        assertSame(ScaAction.Wait, controller.onCallback(T0, callback("kind=result&ceremony=challenge&payload=e30")))
        assertSame(ScaAction.Wait, controller.onTimeout(T0 + TIMEOUT))
    }

    @Test
    fun `a second launch before the first opened, or under an Auth Tab, is Cancelled too`() {
        val notYetOpen = controller()
        assertSame(DaaScaResult.Cancelled, finished(notYetOpen.onNewRequest(T0)))
        assertSame(ScaAction.Wait, notYetOpen.onResume(T0, customTab))
        assertEquals(0, customTab.plans)

        val underAuthTab = launched(authTab)
        assertSame(DaaScaResult.Cancelled, finished(underAuthTab.onNewRequest(T0)))
        // The cleared Auth Tab then reports its own cancel, which changes nothing.
        assertSame(ScaAction.Wait, underAuthTab.onAuthTabResult(T0, ScaAuthTabResult.CANCELED, null))
    }

    @Test
    fun `a second launch after the ceremony finished does nothing`() {
        val controller = launched(customTab)
        finished(controller.onCallback(T0, callback("kind=error&code=Cancelled")))

        assertSame(ScaAction.Wait, controller.onNewRequest(T0))
    }

    @Test
    fun `nothing happens after the ceremony finished`() {
        val controller = launched(customTab)
        finished(controller.onCallback(T0, callback("kind=error&code=Cancelled")))

        assertSame(ScaAction.Wait, controller.onResume(T0 + 1, customTab))
        assertSame(ScaAction.Wait, controller.onTimeout(T0 + TIMEOUT))
        assertSame(ScaAction.Wait, controller.onAuthTabResult(T0, ScaAuthTabResult.CANCELED, null))
        assertSame(ScaAction.Wait, controller.onCallback(T0, callback("kind=error&code=Expired")))
    }

    private fun assertExpired(result: DaaScaResult) {
        assertEquals(DaaScaError.Expired, assertInstanceOf(DaaScaResult.Failed::class.java, result).error)
    }

    private fun assertUnsupported(
        reason: DaaScaUnsupportedReason,
        result: DaaScaResult,
    ) {
        val failed = assertInstanceOf(DaaScaResult.Failed::class.java, result)
        assertEquals(DaaScaError.Unsupported, failed.error)
        assertEquals(reason, failed.unsupportedReason)
    }

    private class FakeLaunch(
        private val plan: ScaLaunchPlan,
        private val callbackRegistered: Boolean = true,
    ) : ScaLaunchEnvironment {
        var plans = 0

        override fun plan(redirectUri: String): ScaLaunchPlan = plan.also { plans++ }

        override fun isCallbackRegistered(redirectUri: String): Boolean = callbackRegistered
    }

    // One allowed browser, trusted on its allowlisted certificate.
    private class FakeBrowser(
        private val authTab: Boolean,
    ) : ScaBrowserEnvironment {
        override fun customTabsPackages(): List<String> = listOf(BROWSER)

        override fun defaultBrowserPackage(): String = BROWSER

        override fun signerDigests(packageName: String): Set<String> =
            setOf(ScaBrowserAllowlist.BROWSERS.getValue(BROWSER).first())

        override fun supportsAuthTab(packageName: String): Boolean = authTab
    }

    // The production policy, with a callback route declared for every redirect URI.
    private class PolicyLaunch(
        private val browsers: ScaBrowserEnvironment,
    ) : ScaLaunchEnvironment {
        override fun plan(redirectUri: String): ScaLaunchPlan = ScaBrowserPolicy.select(browsers, redirectUri)

        override fun isCallbackRegistered(redirectUri: String): Boolean = true
    }

    @Test
    fun `a fresh launch starts the ceremony from the launch request`() {
        val startup =
            ScaCeremonyController.startup(
                recreated = false,
                restored = null,
                launched = { request() },
                now = 1_000,
            )
        val run = assertInstanceOf(ScaStartup.Run::class.java, startup)
        assertEquals(1_000 + request().timeoutMillis, run.controller.deadline)
    }

    @Test
    fun `a launch with no request starts nothing`() {
        assertSame(
            ScaStartup.Nothing,
            ScaCeremonyController.startup(recreated = false, restored = null, launched = { null }, now = 0),
        )
    }

    @Test
    fun `a recreated activity resumes its saved ceremony and keeps the original deadline`() {
        val saved = ScaCeremonyController(request(), 5_000)
        val startup =
            ScaCeremonyController.startup(
                recreated = true,
                restored = saved,
                launched = { request() },
                now = 9_000,
            )
        assertSame(saved, assertInstanceOf(ScaStartup.Run::class.java, startup).controller)
    }

    @Test
    fun `a recreated activity whose state cannot be restored fails closed rather than re-arming the deadline`() {
        val startup =
            ScaCeremonyController.startup(
                recreated = true,
                restored = null,
                launched = { request() },
                now = 9_000,
            )
        val fail = assertInstanceOf(ScaStartup.Fail::class.java, startup)
        assertEquals(DaaScaError.Protocol, assertInstanceOf(DaaScaResult.Failed::class.java, fail.result).error)
    }

    private fun controller(request: ScaCeremonyRequest = request()) =
        ScaCeremonyController(
            request,
            T0 + request.timeoutMillis,
        )

    private fun launched(launch: FakeLaunch): ScaCeremonyController =
        controller().also { assertTrue(it.onResume(T0, launch) is ScaAction.Launch) }

    private fun finished(action: ScaAction): DaaScaResult =
        assertInstanceOf(
            ScaAction.Finish::class.java,
            action,
        ).result

    private fun callback(tail: String) = "$REDIRECT#v=1&state=$STATE&$tail"

    private companion object {
        const val T0 = 1_000_000L
        const val TIMEOUT = 300_000L
        const val BROWSER = "com.android.chrome"
        const val REDIRECT = "https://app.example.com/sca/callback"
        const val ORIGIN = "https://sca.example.circle.com"
        const val STATE = "k3Jx0Qp2V9mZsYbT7uWc1eFgHiLnOrAdEvGhIjKlMn0"
        const val OTHER_STATE = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

        fun request(
            kind: ScaCeremonyKind = ScaCeremonyKind.Challenge,
            redirectUri: String = REDIRECT,
            state: String = STATE,
        ) = ScaCeremonyRequest(kind, ORIGIN, redirectUri, "tok-1", state, TIMEOUT)
    }
}
