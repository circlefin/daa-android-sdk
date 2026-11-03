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

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import androidx.activity.ComponentActivity
import androidx.browser.auth.AuthTabIntent
import com.circle.daa.sdk.sca.DaaScaResult

/**
 * Invisible activity that owns one ceremony from launch to result.
 *
 * It sits directly beneath the browser tab, which is how it learns that a Custom Tab closed:
 * the tab reports nothing, the app simply resumes. Every decision is made by
 * [ScaCeremonyController]; this class only feeds it lifecycle events and carries out what it
 * returns.
 *
 * It is `singleTask`, so the callback activity's `CLEAR_TOP | SINGLE_TOP` start lands in
 * [onNewIntent] on this instance and removes the tab above it. Its request, surface and
 * deadline are saved in instance state, so the ceremony continues if the app process was
 * killed while the tab was open; the caller's `ActivityResultRegistry` then redelivers the
 * result to the recreated host activity.
 */
internal class ScaCeremonyActivity : ComponentActivity() {
    private var controller: ScaCeremonyController? = null
    private val handler = Handler(Looper.getMainLooper())
    private val timeout = Runnable { controller?.let { act(it.onTimeout(now())) } }

    // Registered unconditionally, before STARTED, as the activity-result API requires; it
    // is only launched for an Auth Tab plan. After process death the registry redelivers
    // the Auth Tab's result here.
    private val authTab =
        AuthTabIntent.registerActivityResultLauncher(this) { result ->
            controller?.let { act(it.onAuthTabResult(now(), result.resultCode, result.resultUri?.toString())) }
        }

    /** The ceremony in flight, for instrumented tests that must answer its `state`. */
    internal val pendingRequest: ScaCeremonyRequest? get() = controller?.request

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val startup =
            ScaCeremonyController.startup(
                recreated = savedInstanceState != null,
                restored = savedInstanceState?.let(::restore),
                launched = { intent.extras?.let(::readRequest) },
                now = now(),
            )
        when (startup) {
            is ScaStartup.Run -> controller = startup.controller
            is ScaStartup.Fail -> finishWith(startup.result)
            // Started with no ceremony: nobody is waiting for a result.
            ScaStartup.Nothing -> finish()
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        val controller = controller ?: return
        val callback = intent.data
        if (callback != null) {
            act(controller.onCallback(now(), callback.toString()))
            return
        }
        // A second launch while this ceremony is open. Its request is not read: the
        // ceremony ends Cancelled and the second one never runs (see onNewRequest).
        if (intent.extras?.let(::readRequest) != null) act(controller.onNewRequest(now()))
    }

    override fun onResume() {
        super.onResume()
        val controller = controller ?: return
        act(controller.onResume(now(), AndroidScaEnvironment(this)))
        scheduleTimeout()
    }

    override fun onDestroy() {
        handler.removeCallbacks(timeout)
        super.onDestroy()
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        val controller = controller ?: return
        writeRequest(controller.request, outState)
        outState.putLong(KEY_DEADLINE, controller.deadline)
        outState.putString(KEY_LAUNCHED, controller.launched?.name)
    }

    private fun act(action: ScaAction) {
        when (action) {
            is ScaAction.Launch -> {
                val request = controller?.request ?: return
                ScaPendingStoreFile.pending(this).remember(request.state, request.redirectUri)
                if (!ScaLauncher.launch(this, authTab, action.plan, request.ceremonyUrl())) {
                    controller?.let { act(it.onLaunchFailed(now())) }
                }
            }
            is ScaAction.Finish -> finishWith(action.result)
            ScaAction.Wait -> Unit
        }
    }

    // The timer only runs while the process does; after process death the deadline is
    // still checked on the next resume, because it is saved with the request.
    private fun scheduleTimeout() {
        handler.removeCallbacks(timeout)
        val controller = controller ?: return
        if (controller.finished) return
        handler.postDelayed(timeout, (controller.deadline - now()).coerceAtLeast(0))
    }

    private fun finishWith(result: DaaScaResult) {
        handler.removeCallbacks(timeout)
        ScaPendingStoreFile.pending(this).forget()
        setResult(RESULT_OK, ScaResultIntent.write(result))
        controller = null
        finish()
    }

    private fun now(): Long = SystemClock.elapsedRealtime()

    private fun restore(bundle: Bundle): ScaCeremonyController? {
        val request = readRequest(bundle) ?: return null
        if (!bundle.containsKey(KEY_DEADLINE)) return null
        val launched =
            bundle.getString(KEY_LAUNCHED)?.let {
                    name ->
                ScaSurfaceKind.entries.firstOrNull { it.name == name }
            }
        return ScaCeremonyController(request, bundle.getLong(KEY_DEADLINE), launched)
    }

    internal companion object {
        private const val KEY_KIND = "com.circle.daa.sca.kind"
        private const val KEY_ORIGIN = "com.circle.daa.sca.origin"
        private const val KEY_REDIRECT = "com.circle.daa.sca.redirect"
        private const val KEY_TOKEN = "com.circle.daa.sca.token"
        private const val KEY_STATE = "com.circle.daa.sca.state"
        private const val KEY_TIMEOUT = "com.circle.daa.sca.timeout"
        private const val KEY_DEADLINE = "com.circle.daa.sca.deadline"
        private const val KEY_LAUNCHED = "com.circle.daa.sca.launched"

        fun intent(
            context: Context,
            request: ScaCeremonyRequest,
        ): Intent =
            Intent(context, ScaCeremonyActivity::class.java).also { intent ->
                intent.putExtras(Bundle().also { writeRequest(request, it) })
            }

        private fun writeRequest(
            request: ScaCeremonyRequest,
            bundle: Bundle,
        ) {
            bundle.putString(KEY_KIND, request.kind.name)
            bundle.putString(KEY_ORIGIN, request.circleOrigin)
            bundle.putString(KEY_REDIRECT, request.redirectUri)
            bundle.putString(KEY_TOKEN, request.frameToken)
            bundle.putString(KEY_STATE, request.state)
            bundle.putLong(KEY_TIMEOUT, request.timeoutMillis)
        }

        private fun readRequest(bundle: Bundle): ScaCeremonyRequest? {
            val kind = ScaCeremonyKind.entries.firstOrNull { it.name == bundle.getString(KEY_KIND) } ?: return null
            val timeout = bundle.getLong(KEY_TIMEOUT, 0L).takeIf { it > 0 } ?: return null
            return ScaCeremonyRequest(
                kind = kind,
                circleOrigin = bundle.getString(KEY_ORIGIN) ?: return null,
                redirectUri = bundle.getString(KEY_REDIRECT) ?: return null,
                frameToken = bundle.getString(KEY_TOKEN) ?: return null,
                state = bundle.getString(KEY_STATE) ?: return null,
                timeoutMillis = timeout,
            )
        }
    }
}
