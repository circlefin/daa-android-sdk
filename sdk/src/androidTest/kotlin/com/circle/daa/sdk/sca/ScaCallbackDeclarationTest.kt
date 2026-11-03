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

import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The test manifest's callback declaration, as a host app would write it, resolved the way
 * the system resolves a browser's redirect: by intent filter, not by component. No browser
 * and no App Link verification are needed, so this runs on any image and catches a filter
 * that does not match the redirect URI.
 */
@RunWith(AndroidJUnit4::class)
internal class ScaCallbackDeclarationTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @Test
    fun theRedirectUriResolvesToTheCallbackActivityByIntentFilter() {
        val redirect =
            Intent(Intent.ACTION_VIEW, Uri.parse("${ScaTestHostActivity.REDIRECT_URI}#v=1"))
                .addCategory(Intent.CATEGORY_BROWSABLE)
                .setPackage(context.packageName)

        @Suppress("DEPRECATION")
        val handlers = context.packageManager.queryIntentActivities(redirect, PackageManager.MATCH_DEFAULT_ONLY)

        assertEquals(listOf(DaaScaCallbackActivity::class.java.name), handlers.map { it.activityInfo.name })
    }

    @Test
    fun capabilitiesReportTheDeclaredCallback() {
        val capabilities = DaaSca.capabilities(context, ScaTestHostActivity.CONFIG)

        assertEquals(true, capabilities.callbackRegistered)
        // Declared with taskAffinity="", which Android resolves to no affinity.
        assertEquals(true, capabilities.callbackTaskIsolated)
        // The filter has no autoVerify, so Android 12+ reports the host unverified.
        assertEquals(if (Build.VERSION.SDK_INT >= 31) false else null, capabilities.callbackVerified)
    }

    @Test
    fun anotherPathIsNotRoutedToTheCallback() {
        val config = DaaScaConfig(ScaTestHostActivity.CONFIG.environment, "https://app.example.com/elsewhere")

        assertEquals(false, DaaSca.capabilities(context, config).callbackRegistered)
    }
}
