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

/** The surface a launched ceremony is running in. */
internal enum class ScaSurfaceKind { AuthTab, CustomTab }

/** What the ceremony activity can learn about the device when it opens a ceremony. */
internal interface ScaLaunchEnvironment {
    fun plan(redirectUri: String): ScaLaunchPlan

    /** Whether the host manifest routes [redirectUri] to the SDK's callback activity. */
    fun isCallbackRegistered(redirectUri: String): Boolean
}

/** Result codes an Auth Tab reports; the same values as `AuthTabIntent.RESULT_*`. */
internal object ScaAuthTabResult {
    const val OK = -1
    const val CANCELED = 0
    const val VERIFICATION_FAILED = 2
    const val VERIFICATION_TIMED_OUT = 3
}

/** What the ceremony activity must do next. */
internal sealed class ScaAction {
    data class Launch(val plan: ScaLaunchPlan) : ScaAction()

    data class Finish(val result: DaaScaResult) : ScaAction()

    /** Nothing: the ceremony is still open. */
    data object Wait : ScaAction()
}

/**
 * The ceremony's lifecycle, as a plain state machine the activity drives.
 *
 * It holds no Android types, so every rule below is a JVM unit test:
 *
 * - Not yet launched: the next resume opens the ceremony, or fails it as Unsupported when a
 *   step-up has a custom-scheme callback, no allowed browser exists, an enrollment's
 *   custom-scheme callback finds no Auth Tab, or a Custom Tab would need a callback route
 *   the host never declared.
 * - Custom Tab: the tab reports nothing when it closes; the app simply resumes. Resumed with
 *   no callback therefore means the user came back without finishing — closed the tab, or
 *   followed the page's "return to the app" after an expired or already-used token, which
 *   cannot redirect. Both are [DaaScaResult.Cancelled].
 * - Auth Tab: the browser reports the outcome itself, so a resume alone decides nothing.
 * - A callback that is not provably this ceremony's is ignored (see [ScaCallback]).
 * - A second launch while one is open cancels the open one and does not run (see
 *   [onNewRequest]).
 * - The deadline ([ScaCeremonyRequest.timeoutMillis] from the first open) ends the ceremony
 *   as [DaaScaError.Expired]: the ceremony token is spent by then, so the advice that error
 *   carries — request a fresh one — is the right one.
 * - Every event that can end the ceremony takes `now` and, at or past the deadline, ends it
 *   as Expired whatever it carries. Events do not arrive in a fixed order: after process
 *   death AndroidX redelivers a pending Auth Tab result as the activity starts, before the
 *   resume that would otherwise notice the deadline.
 *
 * Times are a monotonic clock in milliseconds that survives process death
 * (`SystemClock.elapsedRealtime()` on Android).
 */
internal class ScaCeremonyController(
    val request: ScaCeremonyRequest,
    val deadline: Long,
    launched: ScaSurfaceKind? = null,
) {
    var launched: ScaSurfaceKind? = launched
        private set
    var finished: Boolean = false
        private set

    fun onResume(
        now: Long,
        environment: ScaLaunchEnvironment,
    ): ScaAction {
        if (finished) return ScaAction.Wait
        if (now >= deadline) return finish(timedOut())
        return when (launched) {
            null -> open(environment)
            ScaSurfaceKind.CustomTab -> finish(DaaScaResult.Cancelled)
            ScaSurfaceKind.AuthTab -> ScaAction.Wait
        }
    }

    /** A callback forwarded by the callback activity (the Custom Tab path). */
    fun onCallback(
        now: Long,
        callbackUri: String,
    ): ScaAction {
        if (finished) return ScaAction.Wait
        if (now >= deadline) return finish(timedOut())
        return when (val outcome = ScaCallback.parse(callbackUri, request)) {
            is ScaCallbackOutcome.Final -> finish(outcome.result)
            is ScaCallbackOutcome.Ignored -> ScaAction.Wait
        }
    }

    /** The Auth Tab closed with [resultCode]; [resultUri] is the redirect it caught, if any. */
    fun onAuthTabResult(
        now: Long,
        resultCode: Int,
        resultUri: String?,
    ): ScaAction {
        if (finished) return ScaAction.Wait
        if (now >= deadline) return finish(timedOut())
        val result =
            when (resultCode) {
                ScaAuthTabResult.OK -> authTabRedirect(resultUri)
                ScaAuthTabResult.CANCELED -> DaaScaResult.Cancelled
                ScaAuthTabResult.VERIFICATION_FAILED ->
                    scaUnsupported(
                        DaaScaUnsupportedReason.AppLinkNotVerified,
                        "The browser could not verify that this app owns the redirect URI's host",
                    )
                ScaAuthTabResult.VERIFICATION_TIMED_OUT ->
                    DaaScaResult.Failed(
                        DaaScaError.Transport,
                        "The browser timed out verifying the redirect URI's host",
                    )
                else -> DaaScaResult.Failed(DaaScaError.Protocol, "The browser returned an unknown Auth Tab result")
            }
        return finish(result)
    }

    /**
     * The open could not start any activity: the browser the policy chose was uninstalled or
     * disabled in between. To the caller that is the same as having no allowed browser.
     */
    fun onLaunchFailed(now: Long): ScaAction {
        if (finished) return ScaAction.Wait
        if (now >= deadline) return finish(timedOut())
        return finish(scaUnsupported(DaaScaUnsupportedReason.NoAllowedBrowser, "No browser can open the ceremony"))
    }

    fun onTimeout(now: Long): ScaAction = if (finished || now < deadline) ScaAction.Wait else finish(timedOut())

    /**
     * A second launch while this ceremony is open ends this one as [DaaScaResult.Cancelled]
     * and does not run the second.
     *
     * Android reuses the `singleTask` ceremony activity for the second launch and has
     * already cleared the browser tab above it, so this ceremony can no longer finish. But
     * the reused activity's result still goes only to whoever launched it first: Android
     * drops the second launch's result request. Running the second ceremony would hand its
     * response to the first caller — from a different launcher, an enrollment response to
     * an approve callback — so the one deterministic outcome is to cancel. Host apps should
     * not launch while a ceremony is open.
     */
    fun onNewRequest(now: Long): ScaAction {
        if (finished) return ScaAction.Wait
        if (now >= deadline) return finish(timedOut())
        return finish(DaaScaResult.Cancelled)
    }

    private fun open(environment: ScaLaunchEnvironment): ScaAction {
        if (request.kind == ScaCeremonyKind.Challenge && !ScaConfigRules.isHttps(request.redirectUri)) {
            return finish(
                scaUnsupported(
                    DaaScaUnsupportedReason.InsecureRedirect,
                    "Step-up requires an https redirect URI, not a custom scheme",
                ),
            )
        }
        val plan = environment.plan(request.redirectUri)
        return when (plan) {
            is ScaLaunchPlan.Unsupported -> finish(scaUnsupported(plan.reason, plan.message))
            is ScaLaunchPlan.AuthTab -> {
                launched = ScaSurfaceKind.AuthTab
                ScaAction.Launch(plan)
            }
            is ScaLaunchPlan.CustomTab -> {
                // Without a registered callback the page's redirect has nowhere to land,
                // and the user would finish verification in a tab that never returns.
                if (!environment.isCallbackRegistered(request.redirectUri)) {
                    return finish(
                        scaUnsupported(
                            DaaScaUnsupportedReason.CallbackNotRouted,
                            "redirectUri is not routed to DaaScaCallbackActivity",
                        ),
                    )
                }
                launched = ScaSurfaceKind.CustomTab
                ScaAction.Launch(plan)
            }
        }
    }

    // The Auth Tab belongs to this app's launch, so its redirect cannot be another app's
    // forgery. One that still fails the state or target check is a defect, and with the tab
    // gone there is nothing left to wait for.
    private fun authTabRedirect(resultUri: String?): DaaScaResult {
        if (resultUri == null) return DaaScaResult.Failed(DaaScaError.Protocol, "The Auth Tab returned no redirect")
        return when (val outcome = ScaCallback.parse(resultUri, request)) {
            is ScaCallbackOutcome.Final -> outcome.result
            is ScaCallbackOutcome.Ignored -> DaaScaResult.Failed(DaaScaError.Protocol, outcome.reason)
        }
    }

    private fun timedOut() =
        DaaScaResult.Failed(
            DaaScaError.Expired,
            "No result within ${request.timeoutMillis / 1000} s; the ceremony expired",
        )

    private fun finish(result: DaaScaResult): ScaAction {
        finished = true
        return ScaAction.Finish(result)
    }

    internal companion object {
        /**
         * A new ceremony opened at [now]. The deadline saturates at [Long.MAX_VALUE] rather
         * than wrapping negative — a wrapped deadline would expire the ceremony at once — so
         * it is safe even for a timeout [com.circle.daa.sdk.sca.DaaScaConfig] would refuse.
         */
        fun start(
            request: ScaCeremonyRequest,
            now: Long,
        ): ScaCeremonyController = ScaCeremonyController(request, saturatingAdd(now, request.timeoutMillis))

        /**
         * Chooses how the ceremony activity starts. A recreated activity ([recreated]) resumes
         * only from its own saved state ([restored]) and fails closed when that state cannot
         * be read: starting again from the launch intent would re-arm the deadline from now
         * and silently extend a ceremony that was already running.
         */
        fun startup(
            recreated: Boolean,
            restored: ScaCeremonyController?,
            launched: () -> ScaCeremonyRequest?,
            now: Long,
        ): ScaStartup =
            when {
                recreated && restored != null -> ScaStartup.Run(restored)
                recreated ->
                    ScaStartup.Fail(
                        DaaScaResult.Failed(
                            DaaScaError.Protocol,
                            "The ceremony could not be restored after the app was recreated",
                        ),
                    )
                else -> launched()?.let { ScaStartup.Run(start(it, now)) } ?: ScaStartup.Nothing
            }

        internal fun saturatingAdd(
            a: Long,
            b: Long,
        ): Long =
            try {
                Math.addExact(a, b)
            } catch (_: ArithmeticException) {
                if (b > 0) Long.MAX_VALUE else Long.MIN_VALUE
            }
    }
}

/** What the ceremony activity does when it is created. */
internal sealed interface ScaStartup {
    /** Run this ceremony. */
    data class Run(val controller: ScaCeremonyController) : ScaStartup

    /** End the recreated ceremony with this result: it could not be restored. */
    data class Fail(val result: DaaScaResult) : ScaStartup

    /** Nothing was launched, so nobody is waiting for a result. */
    data object Nothing : ScaStartup
}
