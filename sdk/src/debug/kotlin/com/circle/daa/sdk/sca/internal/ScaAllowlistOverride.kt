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

import androidx.annotation.VisibleForTesting

/**
 * Debug variant only: a test seam that replaces [ScaBrowserAllowlist.BROWSERS] while set.
 *
 * Instrumented tests run against the debug variant on whatever emulator image is at hand,
 * and an image's browser is not necessarily release-signed. So they set this to the signer
 * the device's browser actually has, read at runtime, and reset it to `null` afterwards.
 *
 * The release variant (src/release) declares [browsers] as a constant `null`, so no
 * published artifact can widen the list.
 */
internal object ScaAllowlistOverride {
    @VisibleForTesting
    @Volatile
    internal var browsers: Map<String, Set<String>>? = null
}
