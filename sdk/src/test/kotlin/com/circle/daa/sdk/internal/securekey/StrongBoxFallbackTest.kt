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

package com.circle.daa.sdk.internal.securekey

import android.security.keystore.StrongBoxUnavailableException
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.mockito.Mockito.mock

/**
 * The StrongBox retry is separated from the key generation it wraps so it can be tested on a JVM at all —
 * minting a Keystore key needs a live secure element, but the branch that decides whether to fall back to TEE
 * does not, and that branch is the only control flow StrongBox support adds. `KeyPairGenerator` is
 * instantiated directly inside `resolveOrCreate`, so this is the seam that gives the fallback path direct
 * coverage rather than leaving it to incidental device hardware. `StrongBoxUnavailableException` cannot be
 * constructed under the stub `android.jar`, so a Mockito instance stands in for the one the platform throws.
 */
class StrongBoxFallbackTest {
    @Test
    fun `retries with strongbox off when the platform reports it unavailable`() {
        val attempts = mutableListOf<Boolean>()
        generateWithStrongBoxFallback(strongBoxRequested = true) { strongBox ->
            attempts.add(strongBox)
            if (strongBox) throw mock(StrongBoxUnavailableException::class.java)
        }
        // First attempt requests StrongBox; the fallback reruns with it off, against the same alias upstream.
        assertEquals(listOf(true, false), attempts)
    }

    @Test
    fun `does not retry when the strongbox attempt succeeds`() {
        val attempts = mutableListOf<Boolean>()
        generateWithStrongBoxFallback(strongBoxRequested = true) { strongBox ->
            attempts.add(strongBox)
        }
        assertEquals(listOf(true), attempts)
    }

    @Test
    fun `never requests strongbox when the caller gates it off below API 28`() {
        val attempts = mutableListOf<Boolean>()
        generateWithStrongBoxFallback(strongBoxRequested = false) { strongBox ->
            attempts.add(strongBox)
        }
        // The single attempt runs with StrongBox off and the exception handler is never reached.
        assertEquals(listOf(false), attempts)
    }
}
