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

import android.content.pm.verify.domain.DomainVerificationUserState
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ScaCallbackChecksTest {
    @Test
    fun `a verified host is verified, matched case-insensitively`() {
        val environment = FakeCallback(states = mapOf("app.example.com" to VERIFIED))

        assertEquals(true, ScaCallbackChecks.callbackVerified(REDIRECT, environment))
        assertEquals(true, ScaCallbackChecks.callbackVerified("https://App.Example.com/sca/callback", environment))
    }

    @Test
    fun `a host that is unverified, only user-selected, or not declared is not verified`() {
        assertEquals(false, verified(mapOf("app.example.com" to NONE)))
        assertEquals(false, verified(mapOf("app.example.com" to SELECTED)))
        assertEquals(false, verified(mapOf("other.example.com" to VERIFIED)))
        assertEquals(false, verified(emptyMap()))
    }

    @Test
    fun `verification is unknown before Android 12, for a custom scheme, or when the system does not say`() {
        val verifiedHost = mapOf("app.example.com" to VERIFIED)

        assertNull(ScaCallbackChecks.callbackVerified(REDIRECT, FakeCallback(sdkInt = 30, states = verifiedHost)))
        assertNull(ScaCallbackChecks.callbackVerified("com.example.app:/sca", FakeCallback(states = verifiedHost)))
        assertNull(ScaCallbackChecks.callbackVerified(REDIRECT, FakeCallback(states = null)))
    }

    @Test
    fun `the states are not read before Android 12`() {
        val environment = FakeCallback(sdkInt = 30, states = mapOf("app.example.com" to VERIFIED))

        ScaCallbackChecks.callbackVerified(REDIRECT, environment)

        assertEquals(0, environment.stateReads)
    }

    @Test
    fun `an empty task affinity is isolated, the app default affinity is not`() {
        // Android resolves android:taskAffinity="" to null; an omitted one to the package name.
        assertEquals(true, isolated(ScaCallbackDeclaration(taskAffinity = null)))
        assertEquals(true, isolated(ScaCallbackDeclaration(taskAffinity = "")))
        assertEquals(false, isolated(ScaCallbackDeclaration(taskAffinity = "com.example.app")))
    }

    @Test
    fun `task isolation is unknown when the callback activity is not declared`() {
        assertNull(isolated(null))
    }

    @Test
    fun `the verified state equals the platform's constant`() {
        assertEquals(DomainVerificationUserState.DOMAIN_STATE_VERIFIED, ScaCallbackChecks.DOMAIN_STATE_VERIFIED)
        assertTrue(DomainVerificationUserState.DOMAIN_STATE_SELECTED != VERIFIED)
        assertFalse(DomainVerificationUserState.DOMAIN_STATE_NONE == VERIFIED)
    }

    private fun verified(states: Map<String, Int>) =
        ScaCallbackChecks.callbackVerified(
            REDIRECT,
            FakeCallback(states = states),
        )

    private fun isolated(declaration: ScaCallbackDeclaration?) =
        ScaCallbackChecks.callbackTaskIsolated(FakeCallback(declaration = declaration))

    @Test
    fun `a callback activity that is not exported is not routed`() {
        val callback = "com.circle.daa.sdk.sca.DaaScaCallbackActivity"

        assertTrue(ScaCallbackChecks.isRouted(listOf(ScaCallbackHandler(callback, exported = true)), callback))
        assertFalse(ScaCallbackChecks.isRouted(listOf(ScaCallbackHandler(callback, exported = false)), callback))
        assertFalse(
            ScaCallbackChecks.isRouted(listOf(ScaCallbackHandler("com.example.Other", exported = true)), callback),
        )
        assertFalse(ScaCallbackChecks.isRouted(emptyList(), callback))
    }

    private class FakeCallback(
        override val sdkInt: Int = 34,
        private val states: Map<String, Int>? = emptyMap(),
        private val declaration: ScaCallbackDeclaration? = ScaCallbackDeclaration(null),
    ) : ScaCallbackEnvironment {
        var stateReads = 0

        override fun hostVerificationStates(): Map<String, Int>? = states.also { stateReads++ }

        override fun callbackDeclaration(): ScaCallbackDeclaration? = declaration
    }

    private companion object {
        const val REDIRECT = "https://app.example.com/sca/callback"
        const val NONE = DomainVerificationUserState.DOMAIN_STATE_NONE
        const val SELECTED = DomainVerificationUserState.DOMAIN_STATE_SELECTED
        const val VERIFIED = DomainVerificationUserState.DOMAIN_STATE_VERIFIED
    }
}
