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

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.content.pm.verify.domain.DomainVerificationManager
import android.net.Uri
import android.os.Build
import android.util.Log
import androidx.activity.result.ActivityResultLauncher
import androidx.annotation.RequiresApi
import androidx.browser.auth.AuthTabIntent
import androidx.browser.customtabs.CustomTabsClient
import androidx.browser.customtabs.CustomTabsIntent
import androidx.browser.customtabs.CustomTabsService
import androidx.core.net.toUri
import androidx.core.util.AtomicFile
import com.circle.daa.sdk.sca.DaaScaCallbackActivity
import com.circle.daa.sdk.sca.DaaScaSurface
import java.io.File
import java.io.FileNotFoundException
import java.io.IOException
import java.security.MessageDigest

private const val TAG = "DaaSca"

/**
 * The device side of the ceremony: which browsers exist, how they are signed, and how to open
 * one. The decisions live in [ScaBrowserPolicy] and [ScaCeremonyController]; this only reads
 * the package manager and starts activities.
 *
 * Never a `WebView`. The ceremony's guarantee is that the host app cannot read or rewrite
 * what the user is approving; a `WebView` makes the host app the page's script host, which
 * voids that. An Auth Tab or Custom Tab runs in the browser's process, which the app cannot
 * script, and WebAuthn there runs against Circle's origin — the origin Circle verifies.
 */
internal class AndroidScaEnvironment(
    context: Context,
) : ScaBrowserEnvironment,
    ScaLaunchEnvironment,
    ScaCallbackEnvironment {
    private val context = context.applicationContext
    private val packageManager = context.packageManager

    override fun customTabsPackages(): List<String> {
        @Suppress("DEPRECATION")
        val browsers =
            packageManager.queryIntentActivities(browserIntent(PROBE_URL.toUri()), PackageManager.MATCH_ALL)
        return browsers
            .mapNotNull { it.activityInfo?.packageName }
            .distinct()
            .filter(::hasCustomTabsService)
    }

    override fun defaultBrowserPackage(): String? {
        @Suppress("DEPRECATION")
        val resolved =
            packageManager.resolveActivity(
                browserIntent(PROBE_URL.toUri()),
                PackageManager.MATCH_DEFAULT_ONLY,
            )
        // With no default chosen this resolves to the system chooser, which is not a browser.
        return resolved?.activityInfo?.packageName?.takeIf { it != "android" }
    }

    override fun signerDigests(packageName: String): Set<String> =
        try {
            signaturesOf(packageName).map { ScaBrowserAllowlist.format(sha256(it.toByteArray())) }.toSet()
        } catch (_: PackageManager.NameNotFoundException) {
            emptySet()
        }

    override fun supportsAuthTab(packageName: String): Boolean =
        CustomTabsClient.isAuthTabSupported(
            context,
            packageName,
        )

    override fun plan(redirectUri: String): ScaLaunchPlan = ScaBrowserPolicy.select(this, redirectUri)

    /**
     * Whether the host manifest routes [redirectUri] to an exported [DaaScaCallbackActivity] in
     * this app, so the browser can deliver the callback.
     */
    override fun isCallbackRegistered(redirectUri: String): Boolean {
        val probe = browserIntent(redirectUri.toUri()).setPackage(context.packageName)

        @Suppress("DEPRECATION")
        val handlers =
            packageManager.queryIntentActivities(probe, PackageManager.MATCH_DEFAULT_ONLY).mapNotNull { resolved ->
                resolved.activityInfo?.let { ScaCallbackHandler(it.name, it.exported) }
            }
        return ScaCallbackChecks.isRouted(handlers, DaaScaCallbackActivity::class.java.name)
    }

    override val sdkInt: Int get() = Build.VERSION.SDK_INT

    override fun hostVerificationStates(): Map<String, Int>? =
        if (Build.VERSION.SDK_INT >= ScaCallbackChecks.DOMAIN_VERIFICATION_API) domainStates() else null

    override fun callbackDeclaration(): ScaCallbackDeclaration? =
        try {
            val component = ComponentName(context, DaaScaCallbackActivity::class.java)

            @Suppress("DEPRECATION")
            val info = packageManager.getActivityInfo(component, 0)
            ScaCallbackDeclaration(info.taskAffinity)
        } catch (_: PackageManager.NameNotFoundException) {
            null
        }

    @RequiresApi(ScaCallbackChecks.DOMAIN_VERIFICATION_API)
    private fun domainStates(): Map<String, Int>? =
        try {
            context
                .getSystemService(DomainVerificationManager::class.java)
                ?.getDomainVerificationUserState(context.packageName)
                ?.hostToStateMap
        } catch (_: PackageManager.NameNotFoundException) {
            null
        }

    /** The surface [ScaBrowserPolicy] would pick for [redirectUri], for capabilities. */
    fun surfaceFor(redirectUri: String): DaaScaSurface =
        when (plan(redirectUri)) {
            is ScaLaunchPlan.AuthTab -> DaaScaSurface.AuthTab
            is ScaLaunchPlan.CustomTab -> DaaScaSurface.CustomTab
            is ScaLaunchPlan.Unsupported -> DaaScaSurface.None
        }

    // The certificates the package is signed with now. A rotated key's history is not
    // consulted: the allowlist pins each browser's current certificates.
    private fun signaturesOf(packageName: String): Array<Signature> {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val info: PackageInfo = packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES)
            return info.signingInfo?.apkContentsSigners ?: emptyArray()
        }
        @Suppress("DEPRECATION")
        val info: PackageInfo = packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNATURES)
        @Suppress("DEPRECATION")
        return info.signatures ?: emptyArray()
    }

    private fun hasCustomTabsService(packageName: String): Boolean {
        val service = Intent(CustomTabsService.ACTION_CUSTOM_TABS_CONNECTION).setPackage(packageName)
        return packageManager.resolveService(service, 0) != null
    }

    private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

    private companion object {
        const val PROBE_URL = "https://www.circle.com/"

        fun browserIntent(uri: Uri): Intent = Intent(Intent.ACTION_VIEW, uri).addCategory(Intent.CATEGORY_BROWSABLE)
    }
}

/** Opens a ceremony on the surface the policy chose. */
internal object ScaLauncher {
    /** Returns false only when no activity could be started. */
    fun launch(
        activity: Activity,
        authTabLauncher: ActivityResultLauncher<Intent>,
        plan: ScaLaunchPlan,
        url: String,
    ): Boolean {
        val uri = url.toUri()
        return try {
            when (plan) {
                is ScaLaunchPlan.AuthTab -> {
                    val tab = AuthTabIntent.Builder().build()
                    // Pin the browser the policy verified; left unset, the system could
                    // hand the URL to another app with a matching filter.
                    tab.intent.setPackage(plan.packageName)
                    when (plan) {
                        is ScaLaunchPlan.AuthTab.CustomScheme -> tab.launch(authTabLauncher, uri, plan.scheme)
                        is ScaLaunchPlan.AuthTab.Https -> tab.launch(authTabLauncher, uri, plan.host, plan.path)
                    }
                }
                is ScaLaunchPlan.CustomTab -> {
                    val tab =
                        CustomTabsIntent
                            .Builder()
                            .setShowTitle(true)
                            .setShareState(CustomTabsIntent.SHARE_STATE_OFF)
                            .build()
                    tab.intent.setPackage(plan.packageName)
                    tab.launchUrl(activity, uri)
                }
                is ScaLaunchPlan.Unsupported -> return false
            }
            true
        } catch (_: ActivityNotFoundException) {
            false
        }
    }
}

/**
 * [ScaPendingStore] in a file under [Context.noBackupFilesDir], written atomically, so the
 * pending ceremony is recognized after process death and never restored from a backup.
 */
internal class ScaPendingStoreFile(
    context: Context,
) : ScaPendingStore {
    private val file = AtomicFile(File(context.noBackupFilesDir, FILE_NAME))

    override fun read(): String? =
        try {
            file.readFully().toString(Charsets.US_ASCII).takeIf { it.isNotEmpty() }
        } catch (_: FileNotFoundException) {
            null
        } catch (error: IOException) {
            Log.w(TAG, "Could not read the pending SCA ceremony", error)
            null
        }

    override fun write(value: String) {
        val output =
            try {
                file.startWrite()
            } catch (error: IOException) {
                Log.w(TAG, "Could not record the pending SCA ceremony", error)
                return
            }
        try {
            output.write(value.toByteArray(Charsets.US_ASCII))
            file.finishWrite(output)
        } catch (error: IOException) {
            file.failWrite(output)
            Log.w(TAG, "Could not record the pending SCA ceremony", error)
        }
    }

    override fun clear() {
        file.delete()
    }

    internal companion object {
        private const val FILE_NAME = "com.circle.daa.sca.pending"

        @Volatile
        private var instance: ScaPendingCeremony? = null

        /** The process-wide pending ceremony. */
        fun pending(context: Context): ScaPendingCeremony =
            instance ?: synchronized(this) {
                instance ?: ScaPendingCeremony(ScaPendingStoreFile(context.applicationContext)).also { instance = it }
            }
    }
}
