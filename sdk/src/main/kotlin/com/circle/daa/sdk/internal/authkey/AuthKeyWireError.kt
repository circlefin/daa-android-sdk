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

package com.circle.daa.sdk.internal.authkey

internal sealed class AuthKeyWireError(message: String) : IllegalArgumentException(message) {
    // Singleton errors cannot carry an accurate per-throw stack trace.
    override fun fillInStackTrace(): Throwable = this

    data object MalformedP256PublicKey : AuthKeyWireError("Malformed P-256 public key")

    data object MalformedEcdsaSignature : AuthKeyWireError("Malformed ECDSA signature")
}
