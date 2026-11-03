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

import com.circle.daa.sdk.sca.DaaScaUnsupportedReason
import java.net.URI
import java.net.URISyntaxException

/**
 * What the device offers, as the browser policy needs it. The Android implementation reads
 * the package manager; tests supply a fake, so the policy runs as a plain JVM test.
 */
internal interface ScaBrowserEnvironment {
    /** Installed packages that handle `https` VIEW intents and expose a Custom Tabs service. */
    fun customTabsPackages(): List<String>

    /** The package the user chose as default browser, if one is set. */
    fun defaultBrowserPackage(): String?

    /** SHA-256 digests of the certificates [packageName] is currently signed with; empty if unreadable. */
    fun signerDigests(packageName: String): Set<String>

    /** Whether [packageName] advertises Auth Tab support. */
    fun supportsAuthTab(packageName: String): Boolean
}

/** How a ceremony will be opened. */
internal sealed class ScaLaunchPlan {
    /** An Auth Tab: the browser itself catches the redirect and returns it as an activity result. */
    sealed class AuthTab : ScaLaunchPlan() {
        abstract val packageName: String

        data class CustomScheme(override val packageName: String, val scheme: String) : AuthTab()

        data class Https(override val packageName: String, val host: String, val path: String) : AuthTab()
    }

    /** A Custom Tab in the app's task; the redirect returns through the app's callback activity. */
    data class CustomTab(val packageName: String) : ScaLaunchPlan()

    /**
     * No surface can run the ceremony safely: no browser the SDK trusts is installed, or the
     * redirect is a custom scheme and no allowed browser offers an Auth Tab.
     */
    data class Unsupported(val reason: DaaScaUnsupportedReason, val message: String) : ScaLaunchPlan()
}

/**
 * Chooses the surface for a ceremony, best first:
 *
 * 1. an **Auth Tab** in an allowed browser, which delivers the redirect to this app as an
 *    activity result, so no other app can intercept it and no exported component is involved;
 * 2. a **Custom Tab** in an allowed browser, returning through the host's callback activity,
 *    for an `https` redirect only;
 * 3. otherwise **Unsupported**.
 *
 * "Allowed" means [ScaBrowserAllowlist]: package name and signing certificates. There is no
 * step 4. The SDK never opens the ceremony in a browser outside the app's task: there the
 * redirect is an ordinary intent any app can register for, and the user would leave the app
 * mid-approval.
 *
 * A custom-scheme redirect never gets a Custom Tab. From a Custom Tab the redirect is an
 * ordinary intent, and Android hands a custom scheme to any app that declares it: that app
 * would read the response and its `state`, and could then send the SDK's exported callback
 * activity a replacement result. Only an `https` App Link, verified for the host app, keeps
 * that redirect from other apps, so the Custom Tab path is for `https` alone.
 *
 * Among allowed browsers the user's default comes first, then the allowlist's order.
 */
internal object ScaBrowserPolicy {
    internal fun select(
        environment: ScaBrowserEnvironment,
        redirectUri: String,
    ): ScaLaunchPlan {
        val candidates = allowedBrowsers(environment)
        if (candidates.isEmpty()) {
            return ScaLaunchPlan.Unsupported(
                DaaScaUnsupportedReason.NoAllowedBrowser,
                "No allowed browser with Custom Tabs is installed",
            )
        }
        for (packageName in candidates) {
            if (environment.supportsAuthTab(packageName)) {
                authTabPlan(packageName, redirectUri)?.let { return it }
            }
        }
        if (!ScaConfigRules.isHttps(redirectUri)) {
            return ScaLaunchPlan.Unsupported(
                DaaScaUnsupportedReason.InsecureRedirect,
                "A custom-scheme redirect URI needs a browser with Auth Tab support",
            )
        }
        return ScaLaunchPlan.CustomTab(candidates.first())
    }

    private fun allowedBrowsers(environment: ScaBrowserEnvironment): List<String> {
        val installed = environment.customTabsPackages().toSet()
        val allowed =
            ScaBrowserAllowlist.effective().keys.filter { packageName ->
                packageName in installed &&
                    ScaBrowserAllowlist.isAllowed(packageName, environment.signerDigests(packageName))
            }
        val preferred = environment.defaultBrowserPackage()?.takeIf { it in allowed }
        return listOfNotNull(preferred) + allowed.filter { it != preferred }
    }

    // An Auth Tab names the redirect it waits for by scheme, or for https by host and path.
    // An https redirect with an explicit port cannot be expressed that way, so it uses the
    // Custom Tab path instead.
    private fun authTabPlan(
        packageName: String,
        redirectUri: String,
    ): ScaLaunchPlan.AuthTab? {
        val uri =
            try {
                URI(redirectUri)
            } catch (_: URISyntaxException) {
                return null
            }
        val scheme = uri.scheme ?: return null
        if (scheme != "https") return ScaLaunchPlan.AuthTab.CustomScheme(packageName, scheme)
        val host = uri.host ?: return null
        if (uri.port != -1) return null
        return ScaLaunchPlan.AuthTab.Https(packageName, host, uri.rawPath.ifEmpty { "/" })
    }
}
