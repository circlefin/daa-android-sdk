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

import java.net.URI
import java.net.URISyntaxException

/** How the host app declared its callback, as [ScaCallbackChecks] needs it. Tests supply a fake. */
internal interface ScaCallbackEnvironment {
    /** The device's API level. */
    val sdkInt: Int

    /**
     * This package's App Link verification state per host (`DomainVerificationUserState`'s
     * `hostToStateMap`), or null when the system does not report it. Read only on API 31+.
     */
    fun hostVerificationStates(): Map<String, Int>?

    /**
     * The task affinity of the host's `DaaScaCallbackActivity`: [ScaCallbackDeclaration]
     * with the affinity Android resolved, or null when the activity is not declared.
     */
    fun callbackDeclaration(): ScaCallbackDeclaration?
}

/**
 * The host's callback activity as the package manager resolved it. Android resolves
 * `android:taskAffinity=""` to a null affinity, and an omitted one to the app's own.
 */
internal class ScaCallbackDeclaration(
    val taskAffinity: String?,
)

/** An activity in this app that the redirect URI's VIEW intent resolves to. */
internal class ScaCallbackHandler(
    val activityName: String,
    val exported: Boolean,
)

/**
 * Checks behind [com.circle.daa.sdk.sca.DaaScaCapabilities]'s callback fields, kept free of
 * Android types so they run as plain JVM tests.
 */
internal object ScaCallbackChecks {
    /** Android 12, where `DomainVerificationManager` first reports per-host state. */
    internal const val DOMAIN_VERIFICATION_API = 31

    /** `DomainVerificationUserState.DOMAIN_STATE_VERIFIED`. */
    internal const val DOMAIN_STATE_VERIFIED = 2

    /**
     * Whether this app is the verified App Link handler for [redirectUri]'s host, or null
     * when that cannot be known: before API 31, for a custom scheme, or when the system
     * does not report a state. A host the app does not declare for verification at all is
     * false, as is one the user merely selected: an Auth Tab requires verification.
     */
    internal fun callbackVerified(
        redirectUri: String,
        environment: ScaCallbackEnvironment,
    ): Boolean? {
        if (environment.sdkInt < DOMAIN_VERIFICATION_API) return null
        if (!ScaConfigRules.isHttps(redirectUri)) return null
        val host = hostOf(redirectUri) ?: return null
        val states = environment.hostVerificationStates() ?: return null
        return states.entries.any {
                (key, state) ->
            key.equals(host, ignoreCase = true) && state == DOMAIN_STATE_VERIFIED
        }
    }

    /**
     * Whether the callback activity runs outside the app's task (`taskAffinity=""`), or null
     * when it is not declared.
     */
    internal fun callbackTaskIsolated(environment: ScaCallbackEnvironment): Boolean? =
        environment.callbackDeclaration()?.let { it.taskAffinity.isNullOrEmpty() }

    /**
     * Whether the redirect URI reaches the SDK's callback activity from outside the app. A
     * query scoped to this package also returns activities declared `exported="false"`, but the
     * browser is another app and cannot start one, so the user would finish the ceremony and
     * never return. Such a declaration counts as not routed.
     */
    internal fun isRouted(
        handlers: List<ScaCallbackHandler>,
        callbackActivity: String,
    ): Boolean = handlers.any { it.activityName == callbackActivity && it.exported }

    private fun hostOf(uri: String): String? =
        try {
            URI(uri).host
        } catch (_: URISyntaxException) {
            null
        }
}
