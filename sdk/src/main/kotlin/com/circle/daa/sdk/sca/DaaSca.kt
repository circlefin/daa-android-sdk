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

import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.activity.result.contract.ActivityResultContract
import com.circle.daa.sdk.sca.internal.AndroidScaEnvironment
import com.circle.daa.sdk.sca.internal.ScaCallback
import com.circle.daa.sdk.sca.internal.ScaCallbackChecks
import com.circle.daa.sdk.sca.internal.ScaCeremonyActivity
import com.circle.daa.sdk.sca.internal.ScaCeremonyKind
import com.circle.daa.sdk.sca.internal.ScaCeremonyRequest
import com.circle.daa.sdk.sca.internal.ScaConfigRules
import com.circle.daa.sdk.sca.internal.ScaResultIntent

/**
 * Strong customer authentication through Circle's hosted ceremony page.
 *
 * The client's part is small: present the ceremony for a `frameToken` your backend
 * obtained from Circle, and relay what comes back to your backend unchanged. The client never
 * holds API credentials and never sees the operation summary — the page reads that from
 * Circle, so what the user approves is drawn by Circle, not by the host app.
 *
 * The page runs in an Auth Tab when the browser supports one, otherwise in a Custom Tab, and
 * only in a browser on the SDK's allowlist (package name and signing certificate). It never
 * runs in a `WebView` or in a browser outside the app's task; with no allowed browser the
 * ceremony fails [DaaScaError.Unsupported] with [DaaScaUnsupportedReason.NoAllowedBrowser].
 * A Custom Tab is used only for an `https` redirect URI, and from one the result returns
 * through the host app's [DaaScaCallbackActivity].
 *
 * ```kotlin
 * private val sca = DaaScaConfig(DaaEnvironment.Production, "https://app.example.com/sca/callback")
 * private val approve = registerForActivityResult(DaaScaApproveContract(sca)) { result ->
 *     when (result) {
 *         is DaaScaResult.Completed -> backend.confirmTransfer(transferId, assertion = result.response)
 *         DaaScaResult.Cancelled -> offerRetry()
 *         is DaaScaResult.Failed -> showError(result.error, result.unsupportedReason)
 *     }
 * }
 * // later, with the frameToken your backend returned (it keeps the challengeId):
 * approve.launch(frameToken)
 * ```
 *
 * Launch through `registerForActivityResult`, not a callback held in memory: the browser
 * can outlive the app process, and the activity-result registry is what redelivers the
 * result to the recreated activity. Keep your own reference for what the result belongs to
 * (such as a transfer ID) in saved state for the same reason; your backend keeps the
 * challenge or registration ID.
 *
 * Run one ceremony at a time: disable the control that launches it until the result
 * arrives. Launching while a ceremony is open ends the open one as [DaaScaResult.Cancelled]
 * and does not start the new one.
 */
public object DaaSca {
    /** Version of the native redirect contract with the ceremony page. */
    public const val PROTOCOL_VERSION: Int = ScaCallback.PROTOCOL_VERSION

    /**
     * What this device and host app can do with [config]. Reads only the package manager;
     * safe to call before every ceremony, and in a debug build to check your manifest and
     * App Link setup.
     */
    public fun capabilities(
        context: Context,
        config: DaaScaConfig,
    ): DaaScaCapabilities {
        val environment = AndroidScaEnvironment(context)
        return DaaScaCapabilities(
            protocolVersion = PROTOCOL_VERSION,
            surface = environment.surfaceFor(config.redirectUri),
            callbackRegistered = environment.isCallbackRegistered(config.redirectUri),
            callbackVerified = ScaCallbackChecks.callbackVerified(config.redirectUri, environment),
            callbackTaskIsolated = ScaCallbackChecks.callbackTaskIsolated(environment),
            platformPasskeys = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P,
        )
    }

    internal fun createIntent(
        context: Context,
        config: DaaScaConfig,
        kind: ScaCeremonyKind,
        frameToken: String,
    ): Intent {
        // A blank token cannot name a ceremony; it is a caller bug, so it throws from
        // launch() rather than opening a sheet that can only show an error.
        require(frameToken.isNotBlank()) { "frameToken must not be blank" }
        require(frameToken.length <= ScaCeremonyRequest.MAX_FRAME_TOKEN_CHARS) { "frameToken is too long" }
        val request =
            ScaCeremonyRequest(
                kind = kind,
                circleOrigin = config.circleOrigin,
                redirectUri = config.redirectUri,
                frameToken = frameToken,
                state = ScaCeremonyRequest.newState(),
                timeoutMillis =
                    when (kind) {
                        ScaCeremonyKind.Challenge -> config.approveTimeoutMillis
                        ScaCeremonyKind.Registration -> config.enrollTimeoutMillis
                    },
            )
        return ScaCeremonyActivity.intent(context, request)
    }
}

/**
 * Runs a step-up ceremony for a challenge `frameToken`.
 *
 * [DaaScaResult.Completed.response] is the `X-Sca-Assertion` value. Send it to your backend,
 * which re-sends the gated request with it and the `X-Sca-Challenge-Id` it stored. The ceremony ends as
 * [DaaScaError.Expired] if it has no result within [DaaScaConfig.approveTimeoutMillis].
 * Launching while another ceremony is open cancels that one and does not start this one.
 *
 * Step-up requires [DaaScaConfig.redirectUri] to be an `https` App Link: any app can register
 * a custom scheme, and a step-up approves a specific payment. Construction throws
 * [IllegalArgumentException] for a custom scheme.
 */
public class DaaScaApproveContract(
    private val config: DaaScaConfig,
) : ActivityResultContract<String, DaaScaResult>() {
    init {
        require(ScaConfigRules.isHttps(config.redirectUri)) {
            "Step-up requires an https redirectUri (a verified App Link), not a custom scheme"
        }
    }

    override fun createIntent(
        context: Context,
        input: String,
    ): Intent = DaaSca.createIntent(context, config, ScaCeremonyKind.Challenge, input)

    override fun parseResult(
        resultCode: Int,
        intent: Intent?,
    ): DaaScaResult = ScaResultIntent.read(resultCode, intent)
}

/**
 * Runs an enrollment ceremony for a registration `frameToken`.
 *
 * [DaaScaResult.Completed.response] is the registration response JSON. Send it to your
 * backend, which parses it once and passes it to Circle as `attestationResponse` with the
 * registration ID it kept to complete enrollment. The ceremony ends as [DaaScaError.Expired] if it
 * has no result within [DaaScaConfig.enrollTimeoutMillis]. Launching while another ceremony
 * is open cancels that one and does not start this one.
 *
 * A custom-scheme [DaaScaConfig.redirectUri] is accepted here, but runs only in an Auth Tab,
 * where the browser returns the redirect to this app alone. Where no allowed browser offers an
 * Auth Tab, the ceremony fails [DaaScaError.Unsupported] with
 * [DaaScaUnsupportedReason.InsecureRedirect] before anything opens: in a Custom Tab any app
 * that declares the scheme could read the response or replace the result. Prefer an `https`
 * App Link, which can also fall back to a Custom Tab; that fallback is only as safe as the
 * App Link's verification for your app (see [DaaScaCallbackActivity]).
 */
public class DaaScaEnrollContract(
    private val config: DaaScaConfig,
) : ActivityResultContract<String, DaaScaResult>() {
    override fun createIntent(
        context: Context,
        input: String,
    ): Intent = DaaSca.createIntent(context, config, ScaCeremonyKind.Registration, input)

    override fun parseResult(
        resultCode: Int,
        intent: Intent?,
    ): DaaScaResult = ScaResultIntent.read(resultCode, intent)
}
