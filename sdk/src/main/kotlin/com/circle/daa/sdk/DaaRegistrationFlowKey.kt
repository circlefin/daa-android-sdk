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

import com.circle.daa.sdk.internal.authkey.AuthKeyWireError
import com.circle.daa.sdk.internal.authkey.Base64Url
import com.circle.daa.sdk.internal.authkey.EcdsaSignatureJose
import com.circle.daa.sdk.internal.authkey.P256PublicKeyEncoding
import java.security.GeneralSecurityException
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.ProviderException
import java.security.Signature
import java.security.spec.ECGenParameterSpec

// The ephemeral registration-flow key.
//
// ============================================================================
// THIS IS NOT AN AuthKey. Do not treat it as one. It never enters the Android
// Keystore, never reaches DaaSecureKey, DaaAuthKeyIdentity, or an AuthKey
// alias, and is never persisted anywhere.
// ============================================================================
//
// The login contract involves two different P-256 keys, and confusing them is
// the failure this file's naming exists to prevent:
//
// |            | AuthKey (DaaSecureKey)                    | flow key (this file) |
// | ---------- | ----------------------------------------- | -------------------- |
// | Lifetime   | durable, survives the app                 | one login attempt    |
// | Scope      | environment, app, installation            | none; anonymous      |
// | Storage    | Android Keystore, hardware-backed         | process memory only  |
// | Exported   | at Device Registration Complete           | at Prepare           |
// | Selected   | after the Social Session response         | before Prepare       |
// | Authorizes | DAA operations (X-Device-Authorization)   | Complete flow-key JWS  |
//
// The contrast in the "Storage" row is the whole design, in both directions. The
// AuthKey lives in the Keystore precisely because it is durable and must be
// hardware-backed and non-exportable: it authorizes DAA operations for as long as
// the installation exists. This key is in-memory by design for the mirror-image
// reason. A key in the Keystore is a key that outlives the attempt and acquires
// an alias, a namespace, and a lifecycle — exactly the three things a per-attempt
// anonymous key must not have. The single line of code that separates them is the
// provider argument to `KeyPairGenerator.getInstance`: `AndroidAuthKeyBackend`
// names "AndroidKeyStore"; `generate()` below deliberately names nothing.
//
// Its whole job is to prove, at Device Registration Complete, that the caller
// completing the registration is the caller that prepared it — the flow-key JWS
// among the two fresh proofs required over that exact byte sequence.
//
// **Typed Complete-only sign.** `signRegistrationAuthorization` signs a validated
// `DaaRegistrationAuthorizationSigningInput` with the retained in-memory P-256
// key and returns 64-byte JOSE `R||S`. There is no generic `sign(bytes)`,
// by design. The private key
// stays behind a `private` property — Kotlin `internal` compiles to a public JVM
// member under a `$sdk_release` name, so a reachable `PrivateKey` would be a key
// that can sign arbitrary bytes. `apiCheck` (`sdk/api/sdk.api`) is the build gate
// on that; a test also asserts by reflection that the only signing-shaped member
// is `signRegistrationAuthorization`.
//
// **Why the primitive is native.** See `DaaSecureRandom`; the same reasoning
// applies to key generation, and more sharply — a TypeScript version would need
// `crypto.subtle.generateKey`, which Hermes does not provide at all.
//
// **What it shares with the AuthKey, and what it does not.** It reuses
// `internal/authkey/Base64Url` and `P256PublicKeyEncoding`, which are
// deterministic encoders: they neither generate, store, nor sign with private key
// material, and reusing them means the flow key's exported bytes are validated by
// the same 91-byte SPKI encoding as the AuthKey's rather than by a
// second implementation. It touches no other part of `internal/securekey`.

/**
 * One login attempt's registration-flow key. **Not an AuthKey** — see the file
 * header.
 *
 * Prepare exports the public key; Complete signs a validated registration
 * authorization input. There is no generic `sign(bytes)`.
 */
public class DaaRegistrationFlowKey private constructor() {
    /**
     * Retained for the Complete-only typed sign. Never exposed: Kotlin `internal`
     * compiles to a public JVM member under a `$sdk_release` name, so a reachable
     * [PrivateKey] would be a key that can sign arbitrary bytes.
     *
     * `private`, not `internal`, and the distinction matters. Kotlin's `internal`
     * is API hygiene rather than a security boundary. Kotlin `private` compiles
     * to a private JVM field, which is the same bar iOS's `private let` and the
     * TypeScript `#` field clear.
     */
    private val privateKey: PrivateKey

    private val encodedPublicKey: String

    /**
     * The keypair is minted here rather than passed in so that no constructor
     * parameter of this class mentions a [PrivateKey]. A private constructor
     * called from the companion compiles to a synthetic constructor that Kotlin
     * publishes in the ABI, which would put `PrivateKey` into
     * `sdk/api/sdk.api` — the one file a reviewer reads to check that this key
     * exposes nothing. [generate] remains the verb; this is not a public
     * constructor.
     */
    init {
        val keyPair =
            try {
                // No provider argument, and no "AndroidKeyStore": this key is
                // in-memory by design. See the file header.
                KeyPairGenerator.getInstance("EC").run {
                    initialize(ECGenParameterSpec("secp256r1"))
                    generateKeyPair()
                }
            } catch (error: GeneralSecurityException) {
                throw DaaRegistrationFlowKeyException(DaaRegistrationFlowKeyError.KeyGenerationFailed, error)
            } catch (error: ProviderException) {
                throw DaaRegistrationFlowKeyException(DaaRegistrationFlowKeyError.KeyGenerationFailed, error)
            }

        // `Key.encoded` is documented as returning null for a key that does not
        // support encoding. It cannot happen for a JCA EC public key, but the
        // declared contract allows it and the alternative is a bare
        // NullPointerException from Kotlin's platform-type check.
        val spki =
            keyPair.public.encoded
                ?: throw DaaRegistrationFlowKeyException(DaaRegistrationFlowKeyError.PublicKeyUnavailable)
        encodedPublicKey =
            try {
                // Validated for its throw, not its return value: this rejects
                // anything that is not a canonical 91-byte P-256 SPKI.
                P256PublicKeyEncoding.x963Representation(spki)
                Base64Url.encode(spki)
            } catch (error: AuthKeyWireError) {
                // Narrow to the encoder's own sealed error rather than
                // RuntimeException. A malformed encoding is an expected
                // fail-closed outcome; an unrelated bug inside the encoder is
                // not, and must not be reclassified as one.
                throw DaaRegistrationFlowKeyException(DaaRegistrationFlowKeyError.PublicKeyUnavailable, error)
            }
        privateKey = keyPair.private
    }

    /**
     * Unpadded Base64URL of the DER SubjectPublicKeyInfo, the form Prepare's
     * `registrationFlowPublicKey` takes.
     *
     * Cannot fail: the encoding is validated once at construction, so a
     * `DaaRegistrationFlowKey` that exists has already proven it exports a
     * canonical 91-byte P-256 SPKI. Named to match [DaaSecureKey]'s export of
     * the same wire form, so the two read alike where they are compared.
     */
    public fun publicKeySpkiBase64Url(): String = encodedPublicKey

    /**
     * Sign validated Device Registration Complete bytes with the retained
     * in-memory P-256 key. Returns 64-byte JOSE `R||S`. No biometric prompt.
     *
     * Only `daa-registration-flow-authorization+jws` is accepted. A
     * device-authorization `typ` fails closed so this key cannot mint an
     * AuthKey-possession proof.
     *
     * @throws DaaSecureKeyException if the input is malformed, expired, or the
     *   wrong `typ`
     * @throws DaaRegistrationFlowKeyException if the platform cannot produce a
     *   JOSE signature over those exact bytes
     */
    public fun signRegistrationAuthorization(signingInput: DaaRegistrationAuthorizationSigningInput): ByteArray {
        val exactBytes =
            signingInput.signingBytes(DaaRegistrationAuthorizationSigningInputValidator.FLOW_TYP)
        val der =
            try {
                Signature.getInstance("SHA256withECDSA").run {
                    initSign(privateKey)
                    update(exactBytes)
                    sign()
                }
            } catch (error: GeneralSecurityException) {
                throw DaaRegistrationFlowKeyException(DaaRegistrationFlowKeyError.SigningFailed, error)
            } catch (error: ProviderException) {
                throw DaaRegistrationFlowKeyException(DaaRegistrationFlowKeyError.SigningFailed, error)
            }
        return try {
            EcdsaSignatureJose.rawRepresentation(der)
        } catch (error: AuthKeyWireError) {
            throw DaaRegistrationFlowKeyException(DaaRegistrationFlowKeyError.SigningFailed, error)
        }
    }

    /**
     * Redacted. Nothing about a per-attempt key is diagnostic enough to be worth
     * printing, and the public key is one half of a keypair whose other half is
     * in this object.
     */
    override fun toString(): String = "DaaRegistrationFlowKey(publicKey=<redacted>)"

    public companion object {
        /**
         * Mint a fresh in-memory P-256 (secp256r1) keypair for one login attempt.
         *
         * Two calls return two independent keys; there is no caching, no reuse
         * across attempts, and no identity to look one up by.
         *
         * The public encoding is validated during construction rather than at
         * export, so a key that cannot produce a conforming SPKI never becomes an
         * object a caller holds. [P256PublicKeyEncoding] checks the DER prefix, the
         * curve parameters, that the point is on the curve, and that the encoding
         * round-trips — the same checks the AuthKey export runs.
         *
         * @throws DaaRegistrationFlowKeyException if the platform will not produce
         *   a conforming P-256 keypair. Neither case is recoverable; the login
         *   attempt fails closed.
         */
        public fun generate(): DaaRegistrationFlowKey = DaaRegistrationFlowKey()
    }
}

/**
 * Why a registration-flow key operation failed.
 *
 * Generation and signing are both fail-closed. The taxonomy stays typed rather
 * than message-only so a consumer can tell the cases apart without parsing a
 * string. It does not split "no provider" from "the provider refused" the way
 * [DaaSecureKeyError] splits `SigningAlgorithmUnavailable` from `SigningFailed`.
 *
 * In practice generation failures should not be reachable: `EC`/`secp256r1` is
 * mandatory on every supported Android API level. They exist because the JCA is
 * provider-based and every step of it is declared as failing.
 */
public enum class DaaRegistrationFlowKeyError {
    /** The platform would not generate a P-256 keypair. */
    KeyGenerationFailed,

    /** A generated key did not export a canonical 91-byte P-256 SPKI. */
    PublicKeyUnavailable,

    /** The retained key could not produce a JOSE signature over the exact bytes. */
    SigningFailed,
}

/**
 * Thrown when a registration-flow key operation failed.
 *
 * Deliberately not [DaaSecureKeyException]: reusing the AuthKey's error type
 * would put this key inside the AuthKey's boundary in every stack trace and
 * `catch` block that a reader of this SDK will ever see. Invalid signing input
 * still uses [DaaSecureKeyException], because that error belongs to the shared
 * validated-input type rather than to this key.
 *
 * The message names the case and nothing else. No key material, no encoded
 * public key, and no verifier appears in it.
 */
public class DaaRegistrationFlowKeyException internal constructor(
    public val error: DaaRegistrationFlowKeyError,
    cause: Throwable? = null,
) : Exception("DAA registration-flow key operation failed: ${error.name}", cause)
