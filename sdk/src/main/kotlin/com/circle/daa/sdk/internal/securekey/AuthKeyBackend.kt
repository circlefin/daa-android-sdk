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

import androidx.fragment.app.FragmentActivity
import com.circle.daa.sdk.DaaAuthKeyIdentity
import com.circle.daa.sdk.DaaAuthKeyResolution

/**
 * The full protection domain the Keystore backend implements. [DeviceUnlocked] has no prompt and
 * is not part of the public [com.circle.daa.sdk.DaaAuthKeyProtection] surface: application code
 * cannot request it, because DAA requires `userVerification` = `REQUIRED_FOR_EACH_SIGNATURE`
 * and does not permit a caller-selected bypass. It stays reachable here, module-internal,
 * because instrumentation tests cannot drive
 * `BiometricPrompt` on an emulator and needs a no-prompt profile to exercise the rest of the
 * Keystore lifecycle (creation, metadata, registration-state reads) end to end.
 */
internal enum class AuthKeyProtectionMode { UserPresence, DeviceUnlocked }

/**
 * A registration [record] read back together with the DER SPKI of the key it was verified against,
 * both from one read of the Keystore entry.
 */
internal class AuthKeyRegisteredKey(
    val record: AuthKeyRegistrationRecord,
    publicKeySpki: ByteArray,
) {
    private val spki = publicKeySpki.copyOf()

    val publicKeySpki: ByteArray get() = spki.copyOf()
}

/**
 * A registration state together with the DER SPKI of the exact key it describes, both from one
 * read of the Keystore entry, so a caller can cache the key it was told about rather than whatever
 * a second read would return.
 */
internal class AuthKeyState(
    val resolution: DaaAuthKeyResolution,
    publicKeySpki: ByteArray,
) {
    private val spki = publicKeySpki.copyOf()

    val publicKeySpki: ByteArray get() = spki.copyOf()
}

internal interface AuthKeyBackend {
    /** Resolve or create the key; the result names the exact key it resolved. */
    suspend fun resolveOrCreate(
        identity: DaaAuthKeyIdentity,
        protection: AuthKeyProtectionMode,
    ): AuthKeyState

    suspend fun publicKeySpki(identity: DaaAuthKeyIdentity): ByteArray

    /**
     * Read registration state without creating, deleting, or replacing key material. The result
     * names the exact key the state was read for.
     */
    suspend fun registrationState(
        identity: DaaAuthKeyIdentity,
        protection: AuthKeyProtectionMode,
    ): AuthKeyState

    /**
     * Persist a local, key-bound acknowledgement that records no identifiers; this does not
     * contact Circle. An acknowledgement already present for the same key is left as it is.
     * Throws [com.circle.daa.sdk.DaaSecureKeyError.ResolutionRequired] without writing when the key
     * under the alias is no longer [expectedPublicKeySpki].
     */
    suspend fun acknowledgeRegistration(
        identity: DaaAuthKeyIdentity,
        protection: AuthKeyProtectionMode,
        expectedPublicKeySpki: ByteArray,
    )

    /**
     * Persist a local, key-bound acknowledgement carrying [record], replacing whatever
     * acknowledgement was stored before; this does not contact Circle. The key is validated
     * exactly as [registrationState] validates it before anything is written, and the write is
     * refused with [com.circle.daa.sdk.DaaSecureKeyError.ResolutionRequired] when the key under the
     * alias is no longer [expectedPublicKeySpki].
     */
    suspend fun recordRegistration(
        identity: DaaAuthKeyIdentity,
        protection: AuthKeyProtectionMode,
        record: AuthKeyRegistrationRecord,
        expectedPublicKeySpki: ByteArray,
    )

    /**
     * Read the identifiers recorded for the current key without creating, deleting, or replacing
     * key material and without user authentication. Returns `null` when there is no key, when the
     * key has no acknowledgement, when the acknowledgement records no identifiers, or when the
     * protection record or the acknowledgement is missing or cannot be trusted for this exact key.
     * An existing key is still validated exactly as [registrationState] validates it, and that
     * validation failing throws; so does a failure to read the metadata or the certificate. See
     * [restorableRegistration].
     *
     * The result carries the public key material the acknowledgement was verified against, so a
     * caller caches exactly that key rather than whatever a second read would return.
     */
    suspend fun registeredAuthKey(
        identity: DaaAuthKeyIdentity,
        protection: AuthKeyProtectionMode,
    ): AuthKeyRegisteredKey?

    /**
     * Sign exact validated compact-JWS bytes, rechecking malformed and expired input immediately
     * before signing. [operation] is the already-validated operation discriminator (e.g.
     * `transfer`, `register_device_key`); a prompting backend shows its consent prompt over
     * [activity] and derives all of the prompt text from [operation].
     *
     * Signs only with the key whose DER SPKI is [expectedPublicKeySpki] -- the key the caller
     * authorized. The private key that signs and the certificate compared against the expected
     * value come from one read of the Keystore entry, so a key replaced after authorization fails
     * with [com.circle.daa.sdk.DaaSecureKeyError.ResolutionRequired] before any signing operation
     * is initialized.
     */
    suspend fun signDer(
        identity: DaaAuthKeyIdentity,
        protection: AuthKeyProtectionMode,
        message: ByteArray,
        activity: FragmentActivity,
        operation: String,
        expectedPublicKeySpki: ByteArray,
    ): ByteArray
}
