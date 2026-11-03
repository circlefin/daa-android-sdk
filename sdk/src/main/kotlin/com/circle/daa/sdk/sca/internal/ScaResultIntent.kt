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
import android.content.Intent
import com.circle.daa.sdk.sca.DaaScaError
import com.circle.daa.sdk.sca.DaaScaResult
import com.circle.daa.sdk.sca.DaaScaUnsupportedReason

/** Carries a [DaaScaResult] from [ScaCeremonyActivity] back through `setResult`. */
internal object ScaResultIntent {
    private const val KEY_OUTCOME = "com.circle.daa.sca.outcome"
    private const val KEY_RESPONSE = "com.circle.daa.sca.response"
    private const val KEY_ERROR = "com.circle.daa.sca.error"
    private const val KEY_MESSAGE = "com.circle.daa.sca.message"
    private const val KEY_REASON = "com.circle.daa.sca.reason"

    private const val COMPLETED = "completed"
    private const val CANCELLED = "cancelled"
    private const val FAILED = "failed"

    internal fun write(result: DaaScaResult): Intent =
        Intent().also { intent ->
            when (result) {
                is DaaScaResult.Completed ->
                    intent.putExtra(KEY_OUTCOME, COMPLETED).putExtra(KEY_RESPONSE, result.response)
                DaaScaResult.Cancelled -> intent.putExtra(KEY_OUTCOME, CANCELLED)
                is DaaScaResult.Failed ->
                    intent
                        .putExtra(KEY_OUTCOME, FAILED)
                        .putExtra(KEY_ERROR, result.error.name)
                        .putExtra(KEY_MESSAGE, result.message)
                        .putExtra(KEY_REASON, result.unsupportedReason?.name)
            }
        }

    internal fun read(
        resultCode: Int,
        intent: Intent?,
    ): DaaScaResult {
        // No result intent means the ceremony activity went away without finishing — the
        // system tore it down, or the user backed out before the sheet opened. Neither is a
        // failure the user needs to hear about.
        if (resultCode != Activity.RESULT_OK || intent == null) return DaaScaResult.Cancelled
        return when (intent.getStringExtra(KEY_OUTCOME)) {
            COMPLETED ->
                intent.getStringExtra(KEY_RESPONSE)?.let { DaaScaResult.Completed(it) }
                    ?: DaaScaResult.Failed(DaaScaError.Protocol, "Result carried no response")
            CANCELLED -> DaaScaResult.Cancelled
            FAILED -> {
                val error = DaaScaError.entries.firstOrNull { it.name == intent.getStringExtra(KEY_ERROR) }
                val reason =
                    DaaScaUnsupportedReason.entries
                        .firstOrNull { it.name == intent.getStringExtra(KEY_REASON) }
                        ?.takeIf { error == DaaScaError.Unsupported }
                DaaScaResult.Failed(error ?: DaaScaError.Protocol, intent.getStringExtra(KEY_MESSAGE), reason)
            }
            else -> DaaScaResult.Failed(DaaScaError.Protocol, "Result carried no outcome")
        }
    }
}
