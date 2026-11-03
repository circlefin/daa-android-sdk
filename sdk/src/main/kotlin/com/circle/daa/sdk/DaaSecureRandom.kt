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

package com.circle.daa.sdk

import java.security.SecureRandom

/**
 * Cryptographically strong bytes from the platform CSPRNG.
 *
 * This object generates and constructs nothing else. Its one caller-visible job
 * is the high-entropy registration code verifier the login contract requires
 * before Prepare. The verifier is 32 bytes of this, Base64URL-encoded;
 * the verifier value itself, its S256 challenge, and where they are held for the
 * life of one login attempt belong to the login orchestration and are not this
 * object's business.
 *
 * **Why the primitive is native.** A TypeScript version in
 * `daa-react-native-sdk` would run in the one layer with no platform CSPRNG:
 * Hermes ships neither `crypto.subtle` nor `crypto.getRandomValues`, so that
 * TypeScript version would depend on an integrator-installed WebCrypto polyfill the
 * SDK cannot validate, and `globalThis.crypto` stays patchable at runtime by
 * any JavaScript in the app — including a transitive npm dependency.
 * Generating here takes the host app's JavaScript dependency tree out of the
 * trust boundary for enrollment integrity. Native-app integrators need the
 * same primitive, which is why it lives in this SDK rather than behind a
 * React Native bridge.
 *
 * **[SecureRandom] with no seeding, and not `getInstanceStrong()`.** The
 * no-argument constructor takes the highest-priority installed provider, which
 * on Android is the platform CSPRNG seeded from the kernel. It is never given a
 * caller seed: `setSeed` on some providers replaces rather than supplements the
 * seed, and there is no input here worth mixing in. `getInstanceStrong()` is
 * avoided deliberately: it resolves through the `securerandom.strongAlgorithms`
 * security property, whose configured algorithm can be a blocking entropy
 * source, and it buys nothing over the platform default here. There is no
 * lower-quality fallback path: the verifier is the secret binding Prepare to
 * Device Registration Complete, and a predictable one defeats the handoff.
 *
 * Thread-safe: [SecureRandom.nextBytes] is synchronized, and one shared instance
 * avoids re-seeding a fresh generator per call.
 *
 * Nothing here logs. A returned buffer is key-adjacent secret material, and
 * neither it nor its length reaches a log, an exception message, or a
 * `toString`.
 */
public object DaaSecureRandom {
    private val generator: SecureRandom = SecureRandom()

    /**
     * A fresh buffer of exactly [count] cryptographically strong random bytes.
     *
     * [count] must be positive. That is a caller programming error rather than a
     * runtime security condition, so it throws [IllegalArgumentException] — the
     * Kotlin contract for an argument the callee would never accept — instead of
     * adding a typed DAA error case a caller could not act on differently. No
     * upper bound is imposed: picking one would invent an arbitrary limit, and an
     * allocation a caller cannot afford already fails as an allocation.
     */
    public fun bytes(count: Int): ByteArray {
        require(count > 0) { "random byte count must be positive" }
        return ByteArray(count).also(generator::nextBytes)
    }
}
