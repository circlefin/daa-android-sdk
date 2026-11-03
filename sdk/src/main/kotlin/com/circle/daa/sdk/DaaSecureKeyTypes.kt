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

import java.util.UUID

/**
 * The DAA environment an AuthKey belongs to: `sandbox` (testnet) or `production` (mainnet).
 *
 * It namespaces the AuthKey, so each environment has its own key on the installation. It
 * selects no host: the app sends its own requests, and only the SCA ceremony maps it to a
 * Circle origin. These are the only two environments.
 */
public enum class DaaEnvironment(public val wireValue: String) {
    Sandbox("sandbox"),
    Production("production"),
}

/**
 * DAA requires `userVerification` = `REQUIRED_FOR_EACH_SIGNATURE`: application code
 * cannot request a no-prompt AuthKey, so `UserPresence` is the only value this public
 * surface exposes.
 */
public enum class DaaAuthKeyProtection { UserPresence, }

public enum class DaaAuthKeyResolution { Created, Existing }

/**
 * The registration recorded for this installation's AuthKey, as returned by
 * [DaaSecureKey.resolveExisting].
 *
 * @property authKeyId The identifier Circle assigned to the key at registration. It is the `kid` of
 *   every device authorization the key signs.
 * @property ownerBindingId The identifier of the owner binding Circle created at registration.
 * @property registeredAtEpochMillis When this device recorded the registration, in milliseconds since
 *   the Unix epoch. It is local bookkeeping, not a time Circle reported.
 */
public data class DaaRegisteredAuthKey(
    public val authKeyId: String,
    public val ownerBindingId: String,
    public val registeredAtEpochMillis: Long,
)

/**
 * Local key namespace; it contains no active Owner or profile identifier. Select a distinct
 * identity per application profile. For the same [appId] and [environment], persist a separate
 * [installationId] per profile. Reusing an identity shares the key and registration record.
 */
public data class DaaAuthKeyIdentity(
    public val appId: String,
    public val environment: DaaEnvironment,
    public val installationId: UUID,
) {
    init {
        if (!APP_ID.matches(appId)) throw DaaSecureKeyException(DaaSecureKeyError.InvalidAppId)
    }

    internal val alias: String
        get() = "com.circle.daa.authkey.v1.$appId.${environment.wireValue}.${installationId.toString().lowercase()}"

    override fun toString(): String =
        "DaaAuthKeyIdentity(appId=<redacted>, environment=$environment, installationId=<redacted>)"

    private companion object {
        private val APP_ID = Regex("[A-Za-z0-9._-]{1,64}")
    }
}

public enum class DaaSecureKeyError {
    InvalidAppId,

    /**
     * A signing input failed validation (structure, claims, or a future `iat`), or an identifier
     * passed to [DaaSecureKey.acknowledgeRegistration] is not a 36-character hyphenated UUID. The
     * second use matches the iOS SDK, and keeps this enum's entries stable for callers that match
     * on them exhaustively.
     */
    InvalidSigningInput,
    ResolutionRequired,
    AuthKeyRegistrationRequired,
    SecureHardwareUnavailable,
    KeyCreationFailed,
    KeyNotFound,
    KeyInvalidated,
    KeyAccessFailed,
    KeyMetadataUnavailable,
    KeyMetadataVersionUnsupported,
    ProtectionMismatch,
    ProtectionUnavailable,
    PublicKeyUnavailable,
    AuthenticationFailed,
    UserCancelled,
    DeviceCredentialNotSet,
    SigningAlgorithmUnavailable,
    SigningFailed,
    SigningInputExpired,

    /**
     * A device-proof [DaaRegistrationAuthorizationSigningInput]'s embedded header
     * `jwk` is not the signing key: its RFC 7638 thumbprint did not equal the
     * signing key's own. Thrown before any Keystore signing call.
     */
    AuthKeyThumbprintMismatch,
}

public class DaaSecureKeyException internal constructor(
    public val error: DaaSecureKeyError,
    cause: Throwable? = null,
) : Exception("DAA secure-key operation failed: ${error.name}", cause)
