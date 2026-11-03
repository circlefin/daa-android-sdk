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

/**
 * The browsers the SCA ceremony may run in, each pinned to its signing certificates.
 *
 * This is a security decision, kept here as reviewed constants and nowhere else. A browser
 * runs the ceremony page, so it sees what the user approves and carries the result back to
 * the app; a package name alone proves nothing, because any app can be installed under a
 * name another vendor never published on this device. A browser is used only if its package
 * name is listed **and** every certificate it is currently signed with is listed for that
 * package. Nothing matching means the ceremony fails as Unsupported; the SDK never falls back
 * to an unlisted browser or to opening the page outside the app's task.
 *
 * Source of the digests: Google's list of browsers privileged to make passkey calls for web
 * origins, https://www.gstatic.com/gpm-passkeys-privileged-apps/apps.json, retrieved
 * 2026-10-06. Only stable, consumer channels are listed: no beta, dev, canary or nightly
 * channels, no enterprise-managed browsers, and no OS components. Release-signed builds
 * only; Google's list also contains userdebug certificates, which are excluded. A listed
 * browser that does not offer Custom Tabs on a device is skipped there. Each value is the
 * SHA-256 of the DER signing certificate, uppercase hex with colons, exactly as that list and
 * `apksigner verify --print-certs` print it.
 *
 * Release builds of the SDK have no way to widen this list. Debug builds carry a test-only
 * replacement, [ScaAllowlistOverride], so instrumented tests can trust the signer of an
 * emulator's browser; the release variant's override is a constant `null`.
 *
 * To change it: take the package and `cert_fingerprint_sha256` values of `"build": "release"`
 * entries from a fresh copy of that list (or from `apksigner` on the vendor's APK), edit
 * [BROWSERS], update the pinned expectations in ScaBrowserPolicyTest, and have the change
 * reviewed as a security change. Order matters only as a tie-break when the user's default
 * browser is not listed.
 */
internal object ScaBrowserAllowlist {
    internal val BROWSERS: Map<String, Set<String>> =
        linkedMapOf(
            "com.android.chrome" to
                setOf(
                    "F0:FD:6C:5B:41:0F:25:CB:25:C3:B5:33:46:C8:97:2F:AE:30:F8:EE:74:11:DF:91:04:80:AD:6B:2D:60:DB:83",
                ),
            "com.sec.android.app.sbrowser" to
                setOf(
                    "34:DF:0E:7A:9F:1C:F1:89:2E:45:C0:56:B4:97:3C:D8:1C:CF:14:8A:40:50:D1:1A:EA:4A:C5:A6:5F:90:0A:42",
                ),
            "org.mozilla.firefox" to
                setOf(
                    "A7:8B:62:A5:16:5B:44:94:B2:FE:AD:9E:76:A2:80:D2:2D:93:7F:EE:62:51:AE:CE:59:94:46:B2:EA:31:9B:04",
                ),
            "com.microsoft.emmx" to
                setOf(
                    "01:E1:99:97:10:A8:2C:27:49:B4:D5:0C:44:5D:C8:5D:67:0B:61:36:08:9D:0A:76:6A:73:82:7C:82:A1:EA:C9",
                ),
            "com.brave.browser" to
                setOf(
                    "9C:2D:B7:05:13:51:5F:DB:FB:BC:58:5B:3E:DF:3D:71:23:D4:DC:67:C9:4F:FD:30:63:61:C1:D7:9B:BF:18:AC",
                ),
            "com.duckduckgo.mobile.android" to
                setOf(
                    "BB:7B:B3:1C:57:3C:46:A1:DA:7F:C5:C5:28:A6:AC:F4:32:10:84:56:FE:EC:50:81:0C:7F:33:69:4E:B3:D2:D4",
                ),
            "com.opera.browser" to
                setOf(
                    "5D:6A:FB:F8:7F:65:2A:F0:46:47:AD:A0:DF:63:4C:F2:23:70:90:0B:16:4B:09:D5:0B:D2:3A:A2:CB:52:85:B8",
                ),
            "com.opera.mini.native" to
                setOf(
                    "57:AC:BC:52:5F:1B:2E:BD:19:19:6C:D6:F0:14:39:7C:C9:10:FD:18:84:1E:0A:E8:50:FE:BC:3E:1E:59:3F:F2",
                ),
            "com.vivaldi.browser" to
                setOf(
                    "E8:A7:85:44:65:5B:A8:C0:98:17:F7:32:76:8F:56:89:B1:66:2E:C4:B2:BC:5A:0B:C0:EC:13:8D:33:CA:3D:1E",
                ),
            "org.mozilla.focus" to
                setOf(
                    "62:03:A4:73:BE:36:D6:4E:E3:7F:87:FA:50:0E:DB:C7:9E:AB:93:06:10:AB:9B:9F:A4:CA:7D:5C:1F:1B:4F:FC",
                ),
            "org.mozilla.klar" to
                setOf(
                    "62:03:A4:73:BE:36:D6:4E:E3:7F:87:FA:50:0E:DB:C7:9E:AB:93:06:10:AB:9B:9F:A4:CA:7D:5C:1F:1B:4F:FC",
                ),
            "cz.seznam.sbrowser" to
                setOf(
                    "DB:95:40:66:10:78:83:6E:4E:B1:66:F6:9E:F4:07:30:9E:8D:AE:33:34:68:5E:C8:F6:FA:2F:13:81:B9:AC:F6",
                ),
        )

    /**
     * The list in force: [BROWSERS], unless a debug build's test override replaces it.
     */
    internal fun effective(): Map<String, Set<String>> = ScaAllowlistOverride.browsers ?: BROWSERS

    /**
     * Whether [packageName], signed with exactly [signerDigests], is an allowed browser.
     *
     * Every current signer must be listed: an APK with several signers is trusted only if
     * none of them is unknown. No signers at all — unreadable, or an unsigned package — is
     * not trusted.
     */
    internal fun isAllowed(
        packageName: String,
        signerDigests: Set<String>,
    ): Boolean {
        val pinned = effective()[packageName] ?: return false
        return signerDigests.isNotEmpty() && signerDigests.all { normalize(it) in pinned }
    }

    /** SHA-256 digest bytes as uppercase, colon-separated hex — the form [BROWSERS] uses. */
    internal fun format(digest: ByteArray): String = digest.joinToString(":") { "%02X".format(it.toInt() and 0xFF) }

    private fun normalize(digest: String): String = digest.uppercase()
}
