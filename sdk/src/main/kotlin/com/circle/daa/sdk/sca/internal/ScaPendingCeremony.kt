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

import java.security.MessageDigest

/** Where the pending ceremony's state digest survives process death. */
internal interface ScaPendingStore {
    fun read(): String?

    fun write(value: String)

    fun clear()
}

/**
 * Which ceremony, if any, may receive a callback.
 *
 * The callback activity is exported, and forwarding anything to the ceremony activity clears
 * the browser tab above it. So it forwards a callback only if the callback's `state` is the
 * pending ceremony's; anything else is dropped and the tab, with the user in it, is left
 * alone.
 *
 * Only a SHA-256 digest of the state is kept — enough to recognize it, useless for forging
 * it. It is held in memory and, because the browser can outlive the app process, in a file
 * under the app's no-backup directory: it is per-installation, per-ceremony state that a
 * backup must never restore. The Android side keeps one instance per process (there is one
 * ceremony activity), in ScaPendingStoreFile.
 */
internal class ScaPendingCeremony(
    private val store: ScaPendingStore,
) {
    private val lock = Any()

    @Volatile
    private var memory: String? = null

    fun remember(
        state: String,
        redirectUri: String,
    ) {
        // A redirect URI never contains whitespace (the configuration refuses it), so a
        // newline separates the two unambiguously. The URI is not secret; the state is
        // stored only as a digest.
        val record = digestOf(state) + SEPARATOR + redirectUri
        synchronized(lock) {
            memory = record
            store.write(record)
        }
    }

    fun forget() {
        synchronized(lock) {
            memory = null
            store.clear()
        }
    }

    /**
     * Whether [callbackUri] carries the pending ceremony's state **and** arrived at its
     * redirect URI. Both are checked before forwarding: forwarding ends the browser tab, so a
     * callback that the ceremony would then ignore must not be forwarded at all.
     */
    fun accepts(callbackUri: String): Boolean {
        val state = ScaCallback.stateOf(callbackUri) ?: return false
        val record = synchronized(lock) { memory ?: store.read() } ?: return false
        val separator = record.indexOf(SEPARATOR)
        // A record without a redirect URI cannot be checked, so it accepts nothing.
        if (separator < 0) return false
        val expected = record.substring(0, separator)
        val redirectUri = record.substring(separator + 1)
        return MessageDigest.isEqual(digestOf(state).toByteArray(), expected.toByteArray()) &&
            ScaCallback.arrivedAt(callbackUri, redirectUri)
    }

    private companion object {
        const val SEPARATOR = '\n'
    }

    private fun digestOf(state: String): String =
        MessageDigest.getInstance("SHA-256").digest(state.toByteArray()).joinToString("") { "%02x".format(it) }
}
