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

import android.content.Context
import android.util.Log
import androidx.core.util.AtomicFile
import java.io.File
import java.io.FileNotFoundException
import java.util.Properties
import java.util.concurrent.ConcurrentHashMap

private const val TAG = "NoBackupMetadataStore"

/**
 * Durable string metadata rooted in [Context.noBackupFilesDir].
 *
 * AuthKey metadata is not secret, but it is security state: restoring it without the
 * corresponding Android Keystore key must not make a restored installation appear to have
 * a previously configured key. The store therefore shares the Keystore key's backup boundary.
 */
internal class NoBackupMetadataStore(
    context: Context,
    private val name: String,
) {
    private val file = File(context.noBackupFilesDir, name)
    private val atomicFile = AtomicFile(file)
    private val lock =
        synchronized(locks) {
            locks[file.absolutePath] ?: Any().also { locks[file.absolutePath] = it }
        }
    val all: Map<String, String>
        get() = synchronized(lock) { load() }

    fun contains(key: String): Boolean = synchronized(lock) { load().containsKey(key) }

    fun edit(): Editor = Editor()

    inner class Editor {
        private val changes = linkedMapOf<String, String?>()

        fun putString(
            key: String,
            value: String,
        ): Editor = apply { changes[key] = value }

        fun remove(key: String): Editor = apply { changes[key] = null }

        fun commit(): Boolean =
            synchronized(lock) {
                if (changes.isEmpty()) return@synchronized true
                val values = load()
                changes.forEach { (key, value) ->
                    if (value == null) values.remove(key) else values[key] = value
                }
                try {
                    persist(values)
                    true
                } catch (error: Exception) {
                    Log.w(TAG, "Failed to persist AuthKey metadata", error)
                    false
                }
            }
    }

    private fun load(): MutableMap<String, String> {
        return try {
            val properties = Properties()
            atomicFile.openRead().use(properties::load)
            properties.stringPropertyNames().associateWith(properties::getProperty).toMutableMap()
        } catch (_: FileNotFoundException) {
            linkedMapOf()
        } catch (error: Exception) {
            throw IllegalStateException("Unable to read AuthKey metadata", error)
        }
    }

    private fun persist(values: Map<String, String>) {
        val output = atomicFile.startWrite()
        try {
            Properties().apply {
                values.forEach { (key, value) -> setProperty(key, value) }
            }.store(output, null)
            output.fd.sync()
            atomicFile.finishWrite(output)
        } catch (error: Exception) {
            atomicFile.failWrite(output)
            throw error
        }
    }

    private companion object {
        val locks = ConcurrentHashMap<String, Any>()
    }
}
