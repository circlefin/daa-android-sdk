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

/**
 * Release variant: no override. [browsers] is a constant `null`, so a release build always
 * uses [ScaBrowserAllowlist.BROWSERS] and has nothing that could widen it.
 *
 * The debug variant (src/debug) declares the same object with a settable value for
 * instrumented tests. Keep the two declarations' names and types in step.
 */
internal object ScaAllowlistOverride {
    internal val browsers: Map<String, Set<String>>? = null
}
