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

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ScaPendingCeremonyTest {
    private val store = MemoryStore()

    @Test
    fun `accepts only a callback carrying the pending state`() {
        val pending = ScaPendingCeremony(store)
        pending.remember(STATE, REDIRECT)

        assertTrue(pending.accepts(callback(STATE)))
        assertFalse(pending.accepts(callback(OTHER_STATE)))
        assertFalse(pending.accepts("$REDIRECT#v=1&kind=error&code=Cancelled"))
        assertFalse(pending.accepts(REDIRECT))
        assertFalse(pending.accepts("$REDIRECT#v=1&state=$STATE&state=$STATE"))
    }

    @Test
    fun `a custom-scheme ceremony accepts only a callback carrying the pending state`() {
        // Another app that declares the scheme can fire callbacks at the exported callback
        // activity, but it never sees the state, so none of them is forwarded.
        val pending = ScaPendingCeremony(store)
        pending.remember(STATE, CUSTOM_SCHEME_REDIRECT)

        assertTrue(pending.accepts("$CUSTOM_SCHEME_REDIRECT#v=1&state=$STATE&kind=error&code=Cancelled"))
        assertFalse(pending.accepts("$CUSTOM_SCHEME_REDIRECT#v=1&state=$OTHER_STATE&kind=error&code=Cancelled"))
        assertFalse(pending.accepts("$CUSTOM_SCHEME_REDIRECT#v=1&kind=error&code=Cancelled"))
        assertFalse(pending.accepts("$CUSTOM_SCHEME_REDIRECT#v=1&kind=result&ceremony=registration&payload=e30"))
    }

    @Test
    fun `accepts nothing when no ceremony is pending`() {
        assertFalse(ScaPendingCeremony(store).accepts(callback(STATE)))
    }

    @Test
    fun `forgetting the ceremony stops it accepting callbacks`() {
        val pending = ScaPendingCeremony(store)
        pending.remember(STATE, REDIRECT)
        pending.forget()

        assertFalse(pending.accepts(callback(STATE)))
        assertNull(store.value)
    }

    @Test
    fun `a new process recognizes the pending ceremony from the store`() {
        ScaPendingCeremony(store).remember(STATE, REDIRECT)

        val afterProcessDeath = ScaPendingCeremony(store)

        assertTrue(afterProcessDeath.accepts(callback(STATE)))
        assertFalse(afterProcessDeath.accepts(callback(OTHER_STATE)))
    }

    @Test
    fun `only a digest of the state is stored`() {
        ScaPendingCeremony(store).remember(STATE, REDIRECT)

        assertFalse(store.value.orEmpty().contains(STATE))
        assertTrue(Regex("[0-9a-f]{64}\n" + Regex.escape(REDIRECT)).matches(store.value.orEmpty()))
    }

    @Test
    fun `a callback with the pending state but another target is not accepted`() {
        val pending = ScaPendingCeremony(store)
        pending.remember(STATE, REDIRECT)

        assertFalse(
            pending.accepts("https://other.example.com/sca/callback#v=1&state=$STATE&kind=error&code=Cancelled"),
        )
        assertFalse(pending.accepts("https://app.example.com/elsewhere#v=1&state=$STATE&kind=error&code=Cancelled"))
        assertFalse(pending.accepts("$REDIRECT?x=1#v=1&state=$STATE&kind=error&code=Cancelled"))
        assertTrue(pending.accepts(callback(STATE)))
    }

    @Test
    fun `a stored record without a redirect URI accepts nothing`() {
        store.write("0".repeat(64))

        assertFalse(ScaPendingCeremony(store).accepts(callback(STATE)))
    }

    private class MemoryStore : ScaPendingStore {
        var value: String? = null

        override fun read(): String? = value

        override fun write(value: String) {
            this.value = value
        }

        override fun clear() {
            value = null
        }
    }

    private fun callback(state: String) = "$REDIRECT#v=1&state=$state&kind=error&code=Cancelled"

    private companion object {
        const val REDIRECT = "https://app.example.com/sca/callback"
        const val CUSTOM_SCHEME_REDIRECT = "com.example.app:/sca"
        const val STATE = "k3Jx0Qp2V9mZsYbT7uWc1eFgHiLnOrAdEvGhIjKlMn0"
        const val OTHER_STATE = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    }
}
