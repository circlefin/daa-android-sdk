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

package com.circle.daa.sdk.sca

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.util.Log
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.runner.lifecycle.ActivityLifecycleCallback
import androidx.test.runner.lifecycle.ActivityLifecycleMonitorRegistry
import androidx.test.runner.lifecycle.Stage
import com.circle.daa.sdk.sca.internal.AndroidScaEnvironment
import com.circle.daa.sdk.sca.internal.ScaAllowlistOverride
import com.circle.daa.sdk.sca.internal.ScaCeremonyActivity
import com.circle.daa.sdk.sca.internal.ScaCeremonyRequest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/**
 * Drives [ScaCeremonyActivity] against a real Custom Tab: launch, callback, dismissal, a
 * forged callback, and a second launch while a ceremony is open.
 *
 * What this proves is the ceremony and callback activities' behavior, not App Link
 * verification or a passkey end to end: callbacks are started by explicit component, which
 * bypasses App Link resolution, and no ceremony page loads.
 *
 * The ceremony opens a Circle test host that does not resolve, so the tab shows a
 * connection error and no ceremony page loads; the tests answer for the page by firing its
 * callback at [DaaScaCallbackActivity] through `am start`, as the browser would.
 *
 * Needs a Custom Tabs browser, so it is skipped on images without one (the ATD image the
 * managed-device profile uses has none). The production allowlist pins release-signed
 * browsers only, and an emulator image's browser need not be one, so the test replaces the
 * allowlist through the debug-only [ScaAllowlistOverride] with the signers the device's
 * Custom Tabs browsers actually have, read from the package manager here. This exercises the
 * ceremony, not the allowlist's contents, which ScaBrowserPolicyTest pins.
 */
@RunWith(AndroidJUnit4::class)
internal class ScaCeremonyActivityTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val ceremony = AtomicReference<ScaCeremonyActivity?>()
    private val stops = AtomicInteger()
    private val alive = AtomicInteger()

    private val monitor =
        ActivityLifecycleCallback { activity, stage ->
            if (activity !is ScaCeremonyActivity) return@ActivityLifecycleCallback
            when (stage) {
                Stage.CREATED -> {
                    ceremony.set(activity)
                    alive.incrementAndGet()
                }
                // The tab (or anything else full-screen) now covers the ceremony.
                Stage.STOPPED -> stops.incrementAndGet()
                Stage.DESTROYED -> alive.decrementAndGet()
                else -> Unit
            }
        }

    @Before
    fun setUp() {
        val environment = AndroidScaEnvironment(instrumentation.targetContext)
        ScaAllowlistOverride.browsers =
            environment
                .customTabsPackages()
                .associateWith(::signerDigests)
                .filterValues { it.isNotEmpty() }
        assumeTrue(
            "needs an allowed Custom Tabs browser",
            environment.surfaceFor(ScaTestHostActivity.REDIRECT_URI) ==
                DaaScaSurface.CustomTab,
        )
        // The test APK's default targetSdk would otherwise raise a compatibility dialog
        // and a notification prompt, which cover the ceremony and keep it from resuming.
        shell("setprop debug.wm.disable_deprecated_target_sdk_dialog 1")
        if (Build.VERSION.SDK_INT >= 33) {
            instrumentation.uiAutomation.grantRuntimePermission(
                instrumentation.targetContext.packageName,
                Manifest.permission.POST_NOTIFICATIONS,
            )
        }
        ScaTestHostActivity.results.clear()
        ActivityLifecycleMonitorRegistry.getInstance().addLifecycleCallback(monitor)
    }

    @After
    fun tearDown() {
        repeat(5) {
            if (alive.get() <= 0) return@repeat
            shell("input keyevent KEYCODE_BACK")
            SystemClock.sleep(1_000)
        }
        ActivityLifecycleMonitorRegistry.getInstance().removeLifecycleCallback(monitor)
        ScaAllowlistOverride.browsers = null
    }

    @Test
    fun validCallbackCompletesWithThePayloadText() =
        withHost { host ->
            host.onActivity { it.approve.launch("token-1") }
            awaitStops(1)

            answer(pending(), "kind=result&ceremony=challenge&payload=e30")

            val result = awaitSingleResult()
            assertTrue(result is DaaScaResult.Completed)
            assertEquals("{}", (result as DaaScaResult.Completed).response)
        }

    @Test
    fun closingTheTabIsCancelled() =
        withHost { host ->
            host.onActivity { it.approve.launch("token-1") }
            awaitStops(1)

            shell("input keyevent KEYCODE_BACK")

            assertEquals(DaaScaResult.Cancelled, awaitSingleResult())
        }

    @Test
    fun callbackWithAnotherStateIsIgnoredAndTheCeremonyContinues() =
        withHost { host ->
            host.onActivity { it.approve.launch("token-1") }
            awaitStops(1)

            fire("v=1&state=${"A".repeat(43)}&kind=result&ceremony=challenge&payload=e30")
            fire("v=1&kind=error&code=Cancelled")

            // Dropped by the callback activity: no result, and the tab is still up.
            SystemClock.sleep(SETTLE_MS)
            assertEquals(emptyList<DaaScaResult>(), ScaTestHostActivity.results.toList())
            assertEquals(1, stops.get())

            answer(pending(), "kind=result&ceremony=challenge&payload=e30")

            assertTrue(awaitSingleResult() is DaaScaResult.Completed)
        }

    @Test
    fun callbackWithTheRightStateButAnotherTargetIsIgnoredAndTheTabSurvives() =
        withHost { host ->
            host.onActivity { it.approve.launch("token-1") }
            awaitStops(1)

            // The pending ceremony's own state, delivered to a different path: dropped by the
            // callback activity before forwarding, so the tab is not cleared.
            fire(
                "v=1&state=${pending().state}&kind=error&code=Cancelled",
                target = "${ScaTestHostActivity.REDIRECT_URI}/other",
            )

            SystemClock.sleep(SETTLE_MS)
            assertEquals(emptyList<DaaScaResult>(), ScaTestHostActivity.results.toList())
            assertEquals(1, stops.get())

            answer(pending(), "kind=result&ceremony=challenge&payload=e30")

            assertTrue(awaitSingleResult() is DaaScaResult.Completed)
        }

    @Test
    fun secondLaunchOverAnOpenTabCancelsTheOpenCeremony() =
        withHost { host ->
            host.onActivity { it.approve.launch("token-1") }
            awaitStops(1)

            // Android clears tab 1 and hands the launch to the same ceremony activity, whose
            // result can only reach the first launch. That launch hears Cancelled, and the
            // second ceremony never opens.
            host.onActivity { it.approve.launch("token-2") }

            assertEquals(DaaScaResult.Cancelled, awaitSingleResult())
            await("the ceremony activity gone") { alive.get() == 0 }
        }

    @Test
    fun doubleLaunchBeforeTheTabOpensIsCancelled() =
        withHost { host ->
            host.onActivity {
                it.approve.launch("token-1")
                it.approve.launch("token-2")
            }

            assertEquals(DaaScaResult.Cancelled, awaitSingleResult())
            await("the ceremony activity gone") { alive.get() == 0 }
        }

    private fun withHost(body: (ActivityScenario<ScaTestHostActivity>) -> Unit) {
        ActivityScenario.launch(ScaTestHostActivity::class.java).use(body)
    }

    private fun pending(): ScaCeremonyRequest {
        var request: ScaCeremonyRequest? = null
        instrumentation.runOnMainSync { request = ceremony.get()?.pendingRequest }
        return checkNotNull(request) { "no ceremony in flight" }
    }

    /** Fires the callback the page would send for [request]. */
    private fun answer(
        request: ScaCeremonyRequest,
        fields: String,
    ) = fire("v=1&state=${request.state}&$fields")

    // By component, as the browser would after App Link verification, which example.com
    // cannot provide for this test APK.
    private fun fire(
        fragment: String,
        target: String = ScaTestHostActivity.REDIRECT_URI,
    ) {
        val component = "${instrumentation.targetContext.packageName}/${DaaScaCallbackActivity::class.java.name}"
        shell("am start -a android.intent.action.VIEW -n $component -d $target#$fragment")
    }

    private fun awaitStops(count: Int) = await("ceremony covered $count time(s)") { stops.get() >= count }

    private fun awaitSingleResult(): DaaScaResult {
        await("a result") { ScaTestHostActivity.results.isNotEmpty() }
        // Long enough for a second, spurious result to show up if there is one.
        SystemClock.sleep(SETTLE_MS)
        assertEquals(1, ScaTestHostActivity.results.size)
        return ScaTestHostActivity.results.first()
    }

    private fun await(
        what: String,
        condition: () -> Boolean,
    ) {
        val deadline = SystemClock.uptimeMillis() + TIMEOUT_MS
        while (!condition()) {
            check(SystemClock.uptimeMillis() < deadline) { "timed out waiting for $what" }
            SystemClock.sleep(100)
        }
    }

    // SHA-256 of each certificate [packageName] is signed with now, in the allowlist's form.
    private fun signerDigests(packageName: String): Set<String> {
        val packageManager = instrumentation.targetContext.packageManager
        val signatures =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                packageManager
                    .getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES)
                    .signingInfo
                    ?.apkContentsSigners
            } else {
                @Suppress("DEPRECATION")
                packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNATURES).signatures
            }
        return signatures.orEmpty().mapTo(mutableSetOf()) { signature ->
            MessageDigest
                .getInstance("SHA-256")
                .digest(signature.toByteArray())
                .joinToString(":") { "%02X".format(it.toInt() and 0xFF) }
                .also { Log.i(TAG, "Custom Tabs browser $packageName is signed with $it") }
        }
    }

    private fun shell(command: String): String =
        instrumentation.uiAutomation.executeShellCommand(command).use { fd ->
            ParcelFileDescriptor.AutoCloseInputStream(fd).bufferedReader().readText()
        }

    private companion object {
        const val TIMEOUT_MS = 15_000L
        const val SETTLE_MS = 2_000L
        const val TAG = "ScaCeremonyActivityTest"
    }
}
