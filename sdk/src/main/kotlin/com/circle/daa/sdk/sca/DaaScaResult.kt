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

/**
 * Outcome of one SCA ceremony.
 *
 * [Cancelled] is its own case rather than a [DaaScaError], because a user closing the
 * sheet is a normal outcome to offer a retry for, not a failure to report.
 */
public sealed class DaaScaResult {
    /**
     * The ceremony completed.
     *
     * [response] is the exact JSON text the ceremony page produced. Relay it to your
     * backend unchanged — do not parse and re-serialize it:
     * - from [DaaScaApproveContract] it is the `X-Sca-Assertion` header value;
     * - from [DaaScaEnrollContract] it is the registration response your backend passes to
     *   Circle, with its registration ID, to complete enrollment.
     *
     * It is single-use, bound to one ceremony, and useless without your backend's API
     * credentials, but it is still kept out of [toString] so it does not end up in logs.
     */
    public class Completed internal constructor(public val response: String) : DaaScaResult() {
        override fun toString(): String = "DaaScaResult.Completed(response=<redacted>)"
    }

    /**
     * The ceremony ended without a result: the user closed the sheet or declined
     * verification, returned to the app without finishing, or the app launched another
     * ceremony while this one was open.
     *
     * The ceremony token may already be spent. To retry, have your backend open a new
     * registration or challenge and launch with the new `frameToken`.
     */
    public data object Cancelled : DaaScaResult()

    /**
     * The ceremony failed.
     *
     * @property error What went wrong; see [DaaScaError] for what to do about each.
     * @property unsupportedReason Why, when [error] is [DaaScaError.Unsupported]; null
     *   for every other error.
     * @property message Diagnostic text for logs. It never contains the ceremony token or a
     *   response. Do not show it to users or branch on it.
     */
    public class Failed internal constructor(
        public val error: DaaScaError,
        public val message: String?,
        public val unsupportedReason: DaaScaUnsupportedReason? = null,
    ) : DaaScaResult() {
        override fun toString(): String =
            "DaaScaResult.Failed(error=$error, unsupportedReason=$unsupportedReason, message=$message)"
    }
}

/**
 * Why a ceremony failed. The same codes as Circle's web, iOS, and React Native SCA SDKs, less
 * `NotEnrolled`: a ceremony is only ever opened for a registration or challenge your backend
 * already created, so "this user has no passkey" is something your backend learns (by listing
 * the user's passkeys) before it opens a challenge, never something a ceremony reports.
 */
public enum class DaaScaError {
    /**
     * The ceremony token was used or expired, or the ceremony had no result within
     * [DaaScaConfig.approveTimeoutMillis] or [DaaScaConfig.enrollTimeoutMillis].
     *
     * Produced by Circle's ceremony page when the ceremony expires while the user is in it,
     * or by the SDK when its timeout fires. (A token that is already expired or used when
     * the page opens cannot be redirected back; the user closes the page and the result is
     * [DaaScaResult.Cancelled].) Have your backend open a new registration or challenge and
     * launch again with the new `frameToken`. Never reuse a `frameToken`.
     */
    Expired,

    /**
     * This device or app cannot run the ceremony. [DaaScaResult.Failed.unsupportedReason]
     * says why, and whether it is your configuration or the user's device.
     */
    Unsupported,

    /**
     * The user already has a passkey for this account, so the authenticator refused to
     * create a second one.
     *
     * Produced by Circle's ceremony page during enrollment only. Treat the user as enrolled
     * and use [DaaScaApproveContract] for the operation.
     */
    AlreadyEnrolled,

    /**
     * The browser could not confirm, in time, that this app owns the redirect URI's domain.
     *
     * Produced by the SDK when an Auth Tab reports that verifying the App Link timed out,
     * usually because the device is offline. Retry once with a new `frameToken` from your
     * backend; if it persists, check the device's connection.
     */
    Transport,

    /**
     * The ceremony page and this SDK did not understand each other: an off-contract
     * callback, or an Auth Tab result the SDK does not know.
     *
     * Produced by the SDK. Retrying will not help. Update to the latest SDK version, and
     * contact Circle if it persists.
     */
    Protocol,
}

/**
 * Why a ceremony ended [DaaScaError.Unsupported]. Each reason is one the SDK can tell apart;
 * where it cannot, the reason says so.
 */
public enum class DaaScaUnsupportedReason {
    /**
     * No browser on the SDK's allowlist, with Custom Tabs support, is installed and enabled,
     * or the one chosen could not be opened.
     *
     * Produced by the SDK before anything opens. This is the user's device, not your
     * configuration: ask the user to install or enable a supported browser.
     * [DaaScaCapabilities.surface] is [DaaScaSurface.None] in this state.
     */
    NoAllowedBrowser,

    /**
     * The ceremony needs a Custom Tab, and your manifest does not route
     * [DaaScaConfig.redirectUri] to [DaaScaCallbackActivity].
     *
     * Produced by the SDK before anything opens. A configuration bug: fix the manifest.
     * [DaaScaCapabilities.callbackRegistered] is false in this state.
     */
    CallbackNotRouted,

    /**
     * The browser's Auth Tab could not verify that this app owns the redirect URI's domain.
     *
     * Produced by the SDK from the Auth Tab's result, after the user saw the sheet. A
     * configuration bug: check the `assetlinks.json` on that domain lists this app's package
     * and signing certificate, and that the callback intent filter has `autoVerify`.
     * [DaaScaCapabilities.callbackVerified] is false in this state on Android 12 and later.
     */
    AppLinkNotVerified,

    /**
     * The redirect URI is a custom scheme, and this ceremony cannot keep it from other apps:
     * - a step-up ceremony, on any surface. [DaaScaApproveContract] already refuses such a
     *   configuration at construction, so this is only reachable by a hand-built intent;
     * - an enrollment ceremony on a device where no allowed browser offers an Auth Tab. A
     *   Custom Tab would hand the redirect to any app that declares the scheme.
     *
     * Produced by the SDK before anything opens. [DaaScaCapabilities.surface] is
     * [DaaScaSurface.None] for an enrollment in this state. Use an `https` App Link.
     */
    InsecureRedirect,

    /**
     * Circle's ceremony page reported that the browser could not run the passkey operation:
     * the device has no usable authenticator or screen lock, or the browser refused or
     * failed the passkey request. The page reports all of these the same way, so the SDK
     * cannot tell them apart.
     *
     * Offer your fallback, or ask the user to set a screen lock and try another supported
     * browser.
     */
    PasskeyUnavailable,
}

/** Which surface a ceremony would run in on this device, best first. */
public enum class DaaScaSurface {
    /** An Auth Tab: the browser returns the redirect to the app directly. */
    AuthTab,

    /** A Custom Tab in the host app's task; the redirect returns through [DaaScaCallbackActivity]. */
    CustomTab,

    /**
     * No surface can run a ceremony for this redirect URI, and every ceremony fails
     * [DaaScaError.Unsupported]: with [DaaScaUnsupportedReason.NoAllowedBrowser] when no
     * allowed browser is installed, or with [DaaScaUnsupportedReason.InsecureRedirect] when the
     * redirect URI is a custom scheme and no allowed browser offers an Auth Tab.
     */
    None,
}

/**
 * What this device and host app can do, for choosing copy and for checking support before a
 * transfer is attempted rather than discovering a gap mid-ceremony.
 *
 * @property protocolVersion Version of the native redirect contract this SDK speaks.
 * @property surface The surface [DaaScaApproveContract] and [DaaScaEnrollContract] will use.
 * @property callbackRegistered Whether the host manifest routes the configured redirect URI to
 *   [DaaScaCallbackActivity], declared `exported="true"` so the browser can start it. When
 *   false, a ceremony that needs a Custom Tab fails
 *   [DaaScaError.Unsupported] with [DaaScaUnsupportedReason.CallbackNotRouted].
 * @property callbackVerified Whether Android has verified this app as the App Link handler for
 *   the redirect URI's host. Null when it cannot be determined: before Android 12, for a
 *   custom-scheme redirect URI, or when the system does not report it. False means the
 *   `assetlinks.json` check has not passed (yet, or at all): an Auth Tab ceremony fails
 *   [DaaScaUnsupportedReason.AppLinkNotVerified], and a Custom Tab redirect may open in the
 *   browser instead of returning to the app. Verification runs after install and can take a
 *   while on a fresh install.
 * @property callbackTaskIsolated Whether [DaaScaCallbackActivity] is declared with
 *   `android:taskAffinity=""`. Null when the activity is not declared. When false, a stray
 *   callback can bring the app to the front and end the ceremony in progress as
 *   [DaaScaResult.Cancelled].
 * @property platformPasskeys Whether the OS is recent enough for browser passkeys (Android 9+).
 *   A heuristic: the browser and credential provider make the final decision.
 */
public data class DaaScaCapabilities(
    public val protocolVersion: Int,
    public val surface: DaaScaSurface,
    public val callbackRegistered: Boolean,
    public val callbackVerified: Boolean?,
    public val callbackTaskIsolated: Boolean?,
    public val platformPasskeys: Boolean,
)
