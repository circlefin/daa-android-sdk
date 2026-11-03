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

import com.circle.daa.sdk.DaaEnvironment
import com.circle.daa.sdk.sca.internal.ScaConfigRules

/**
 * Where the SCA ceremony runs, where its result comes back, and how long the SDK waits.
 *
 * Validated at construction, so a misconfiguration fails when the host app builds
 * its launcher rather than halfway through a ceremony the user has already started.
 *
 * @property environment [DaaEnvironment.Sandbox] or [DaaEnvironment.Production]. It selects
 *   Circle's ceremony origin, which must equal the origin Circle validates
 *   `clientDataJSON.origin` against, so it is not free-form.
 * @property redirectUri The callback the ceremony page navigates to on completion. Circle
 *   registers your exact redirect URIs per environment, and your backend must send this same
 *   URI as `redirectUri` when it opens each registration or challenge. The page takes its
 *   return target from Circle, never from this value. A URI Circle has not registered for
 *   you is rejected by that backend call (error code 420068), before any `frameToken`
 *   exists, so the app is never launched with it. Without `redirectUri`, Circle opens a web
 *   ceremony that never returns to the app. The match is by exact string, so this value,
 *   the backend's, and the registered URI must be identical. [DaaScaApproveContract]
 *   requires an `https` App Link; a custom scheme is accepted for enrollment only, because
 *   any app can claim one, and that enrollment runs only where a browser offers an Auth Tab.
 *   At most 2048 characters, the longest Circle accepts.
 * @property circleOrigin The ceremony origin. Defaults to the [environment]'s. An explicit
 *   value reaches another Circle host: it must be a bare `https` origin (no port, path, query,
 *   fragment, or credentials) on `circle.com` or a subdomain of it, written exactly as Circle
 *   compares it: lowercase DNS labels of 1 to 63 characters, a host of at most 253 characters,
 *   and no trailing dot or whitespace. It is never normalized. Any value is rejected with
 *   [DaaEnvironment.Production] so an override left in a debug configuration fails when the
 *   config is built instead of sending production ceremonies elsewhere.
 * @property approveTimeoutMillis How long a step-up ceremony may stay open without a result
 *   before it ends as [DaaScaError.Expired]. Defaults to the challenge lifetime. From
 *   [MINIMUM_TIMEOUT_MILLIS] to [MAXIMUM_TIMEOUT_MILLIS].
 * @property enrollTimeoutMillis The same for an enrollment ceremony. Defaults to the
 *   registration lifetime.
 */
public class DaaScaConfig(
    public val environment: DaaEnvironment,
    public val redirectUri: String,
    circleOrigin: String? = null,
    public val approveTimeoutMillis: Long = DEFAULT_APPROVE_TIMEOUT_MILLIS,
    public val enrollTimeoutMillis: Long = DEFAULT_ENROLL_TIMEOUT_MILLIS,
) {
    public val circleOrigin: String

    init {
        require(environment != DaaEnvironment.Production || circleOrigin == null) {
            "circleOrigin is a development override and cannot be set for Production"
        }
        require(circleOrigin == null || ScaConfigRules.isValidOriginOverride(circleOrigin)) {
            "circleOrigin must be a bare https origin on circle.com or a subdomain of it"
        }
        this.circleOrigin = circleOrigin ?: ScaConfigRules.originFor(environment)
        require(ScaConfigRules.isValidRedirectUri(redirectUri)) {
            "redirectUri must be an https URI or a custom scheme of at most " +
                "${ScaConfigRules.MAX_REDIRECT_URI_CHARS} characters, with no fragment, credentials, whitespace, " +
                "dot segments, or (for https) apostrophe in the query"
        }
        require(isValidTimeout(approveTimeoutMillis) && isValidTimeout(enrollTimeoutMillis)) {
            "ceremony timeouts must be from $MINIMUM_TIMEOUT_MILLIS to $MAXIMUM_TIMEOUT_MILLIS ms"
        }
    }

    override fun toString(): String =
        "DaaScaConfig(environment=$environment, circleOrigin=$circleOrigin, " +
            "approveTimeoutMillis=$approveTimeoutMillis, enrollTimeoutMillis=$enrollTimeoutMillis)"

    public companion object {
        /** Default step-up timeout: 300 s, the lifetime of a challenge's ceremony token. */
        public const val DEFAULT_APPROVE_TIMEOUT_MILLIS: Long = 300_000L

        /** Default enrollment timeout: 600 s, the lifetime of a registration's ceremony token. */
        public const val DEFAULT_ENROLL_TIMEOUT_MILLIS: Long = 600_000L

        /** The shortest timeout either ceremony accepts: 30 s. */
        public const val MINIMUM_TIMEOUT_MILLIS: Long = 30_000L

        /** The longest timeout either ceremony accepts: one hour. */
        public const val MAXIMUM_TIMEOUT_MILLIS: Long = 3_600_000L

        private fun isValidTimeout(millis: Long): Boolean = millis in MINIMUM_TIMEOUT_MILLIS..MAXIMUM_TIMEOUT_MILLIS
    }
}
