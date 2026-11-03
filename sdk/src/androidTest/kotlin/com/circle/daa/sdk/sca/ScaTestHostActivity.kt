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

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.result.ActivityResultLauncher
import com.circle.daa.sdk.DaaEnvironment
import java.util.concurrent.CopyOnWriteArrayList

/** Stands in for a host app: registers the approve contract and records every result. */
internal class ScaTestHostActivity : ComponentActivity() {
    lateinit var approve: ActivityResultLauncher<String>

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        approve = registerForActivityResult(DaaScaApproveContract(CONFIG)) { results.add(it) }
    }

    companion object {
        // https, as step-up requires, and without a port, which the config refuses. Where the
        // browser offers an Auth Tab (which could not verify example.com) the policy picks
        // that instead of a Custom Tab, and ScaCeremonyActivityTest skips.
        const val REDIRECT_URI = "https://app.example.com/sca/callback"

        // A Circle host that does not resolve (an override may not carry a port), so the tab
        // opens but no ceremony page loads.
        val CONFIG = DaaScaConfig(DaaEnvironment.Sandbox, REDIRECT_URI, circleOrigin = "https://sca-test.circle.com")

        val results = CopyOnWriteArrayList<DaaScaResult>()
    }
}
