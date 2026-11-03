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

import android.content.Context
import androidx.fragment.app.FragmentActivity
import com.circle.daa.sdk.internal.authkey.Base64Url
import com.circle.daa.sdk.internal.authkey.EcdsaSignatureJose
import com.circle.daa.sdk.internal.authkey.P256PublicKeyEncoding
import com.circle.daa.sdk.internal.securekey.AndroidAuthKeyBackend
import com.circle.daa.sdk.internal.securekey.AuthKeyBackend
import com.circle.daa.sdk.internal.securekey.AuthKeyProtectionMode
import com.circle.daa.sdk.internal.securekey.AuthKeyRegistrationRecord
import com.circle.daa.sdk.internal.securekey.AuthKeyState
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.util.concurrent.ConcurrentHashMap

/**
 * Own all [DaaSecureKey] operations for an application in one process. The SDK's locks do not
 * coordinate processes, and its metadata files are shared across key identities. A host with
 * multiple processes must route these operations through one owning process, for example via IPC.
 */
public class DaaSecureKey internal constructor(
    private val identity: DaaAuthKeyIdentity,
    private val protection: AuthKeyProtectionMode,
    private val backend: AuthKeyBackend,
) {
    public constructor(
        context: Context,
        identity: DaaAuthKeyIdentity,
        protection: DaaAuthKeyProtection = DaaAuthKeyProtection.UserPresence,
    ) : this(identity, protection.toBackendMode(), AndroidAuthKeyBackend(context.applicationContext))

    /**
     * Guards every read-decide-write of this identity's durable state: resolution, the
     * acknowledgement check and write, and restoration. Shared by every instance in the
     * process for the same Keystore alias, not owned by this instance, so a check made under it
     * (that the key this instance resolved is still the key under the alias) still holds when the
     * write that depends on it runs, even if another instance would replace the key.
     * The backend additionally checks the expected key material before writing, detecting a
     * replacement visible at that check. This is not an interprocess transaction.
     * (`ConcurrentMap.getOrPut` is atomic through `putIfAbsent`,
     * which, unlike `computeIfAbsent`, exists at this module's minimum API level.)
     */
    private val resolutionLock = aliasLocks.getOrPut(identity.alias) { Mutex() }
    private val signingLock = Mutex()

    /**
     * Last observed durable state. Only an `Existing` observation is authoritative,
     * because nothing can undo an acknowledgement: both the acknowledgement check and
     * [resolveLocked] act on it. A cached `Created` is never trusted in place of a fresh
     * read.
     *
     * Bound to no key identity by itself -- see [resolvedKeyMaterial].
     */
    @Volatile
    private var resolution: DaaAuthKeyResolution? = null

    /**
     * The exact public key material [resolution] (when `Existing`) and [explicitlyResolved] were
     * last observed against. The key under this identity's alias can be replaced -- a migration or
     * a re-creation driven by another live instance for the same identity -- without this instance
     * being told, and neither cached flag says anything about *which* key it describes on its own.
     * Every place that would otherwise trust the cache instead of asking the backend again
     * re-checks this first, via [cachedStateIsCurrent]; a mismatch is treated the same as never
     * having observed anything.
     */
    @Volatile
    private var resolvedKeyMaterial: ByteArray? = null

    /**
     * Set once [resolveOrCreate], or a [resolveExisting] that found a registration, has
     * succeeded on this instance, and never cleared. Kept apart from
     * [resolution] so reading durable state can populate the cache without standing in
     * for the caller's own explicit resolution.
     */
    @Volatile
    private var explicitlyResolved: Boolean = false

    /**
     * Resolve the installation key. `Created` means Circle registration is still
     * required; `Existing` is returned only after registration was acknowledged.
     */
    public suspend fun resolveOrCreate(): DaaAuthKeyResolution =
        resolutionLock.withLock {
            resolveLocked().also { explicitlyResolved = true }
        }

    /**
     * Look up the registration recorded for this installation's key without creating a key
     * and without user authentication: only the Keystore entry, its `KeyInfo`, and the SDK's
     * local metadata are read, so no biometric prompt is shown.
     *
     * Returns `null` when there is no key, when the key was never acknowledged, when it was
     * acknowledged by [acknowledgeRegistration] without identifiers, or when the SDK's local
     * metadata for the key is missing or cannot be trusted: a protection record that is missing
     * or unparsable, or a registration marker that is malformed, from an unknown version, or
     * bound to a different key. A `null` result changes nothing; the caller signs in again, and
     * [resolveOrCreate] decides whether a key is minted or reports the metadata problem as
     * [DaaSecureKeyError.KeyMetadataUnavailable]. A failure to read that metadata is not
     * mistaken for nothing to restore: it throws [DaaSecureKeyError.KeyAccessFailed].
     *
     * A non-null result counts as an explicit resolution of that key, so [thumbprint],
     * [publicKeySpkiBase64Url], and [signDeviceAuthorization] work without a prior
     * [resolveOrCreate]. The key is validated exactly as [resolveOrCreate] validates an
     * existing key -- protection profile and hardware backing included -- and a key that fails
     * that validation throws rather than returning `null`.
     *
     * The local wall-clock timestamp and Keystore HMAC do not detect replay of an older valid
     * record. Use the identifiers as candidates for the signed restore request; accept its
     * context only after the server accepts the request and returns matching identifiers.
     * The host must select a distinct identity per profile and check the intended application
     * account itself. The server does not validate this local profile selection.
     */
    public suspend fun resolveExisting(): DaaRegisteredAuthKey? =
        resolutionLock.withLock {
            val registered = backend.registeredAuthKey(identity, protection) ?: return@withLock null
            // Cache the exact material the acknowledgement was verified against, not a second read:
            // a key re-minted under the alias in between must never be cached as this registration.
            // If it was, the material differs and cachedStateIsCurrent sends every later use back
            // to the backend.
            resolution = DaaAuthKeyResolution.Existing
            resolvedKeyMaterial = registered.publicKeySpki
            explicitlyResolved = true
            val record = registered.record
            DaaRegisteredAuthKey(record.authKeyId, record.ownerBindingId, record.registeredAtEpochMillis)
        }

    /**
     * Record successful Circle registration for the explicitly resolved key, together with
     * the identifiers Circle assigned to it. This method performs no network
     * call. SDK orchestration must invoke it only after authoritative enrollment succeeds.
     *
     * [authKeyId] and [ownerBindingId] must be 36-character hyphenated UUID strings; anything
     * else throws [DaaSecureKeyError.InvalidSigningInput] before anything is read or written.
     * The iOS SDK reports the same failure the same way. No dedicated error code is used,
     * because adding an enum entry breaks callers that match on it exhaustively. The
     * identifiers are stored exactly as given, with no case change.
     *
     * Unlike the no-argument form, this always writes: a registration recorded earlier for
     * this key, with or without identifiers, is replaced, and the recorded time is the time
     * of this call. [resolveExisting] then reads the last locally written acknowledgement.
     * The host must serialize enrollment attempts and ignore superseded responses; local
     * write order and timestamps do not establish server registration order or freshness.
     */
    public suspend fun acknowledgeRegistration(
        authKeyId: String,
        ownerBindingId: String,
    ) {
        if (!AuthKeyRegistrationRecord.isRegistrationId(authKeyId) ||
            !AuthKeyRegistrationRecord.isRegistrationId(ownerBindingId)
        ) {
            throw DaaSecureKeyException(DaaSecureKeyError.InvalidSigningInput)
        }
        resolutionLock.withLock {
            // Checked under the same lock as the write: the key this instance resolved must still be
            // the key under the alias when the acknowledgement is written, or the identifiers of one
            // registration would be bound to whatever key replaced it.
            val expected = requireResolvedKeyMaterial()
            backend.recordRegistration(
                identity,
                protection,
                AuthKeyRegistrationRecord(authKeyId, ownerBindingId, System.currentTimeMillis()),
                expected,
            )
            resolution = DaaAuthKeyResolution.Existing
        }
    }

    /**
     * Record successful Circle registration for the explicitly resolved key, without
     * identifiers. This method performs no network call. SDK orchestration must
     * invoke it only after authoritative enrollment succeeds.
     *
     * Deprecated: use the overload that records the identifiers Circle assigned. An
     * acknowledgement written here cannot be restored by [resolveExisting], and a key that is
     * already acknowledged is left as it is. Kept, without a compiler deprecation, so existing
     * callers keep building warning-free.
     */
    public suspend fun acknowledgeRegistration() {
        resolutionLock.withLock {
            val expected = requireResolvedKeyMaterial()
            if (resolution == DaaAuthKeyResolution.Existing) return
            backend.acknowledgeRegistration(identity, protection, expected)
            resolution = DaaAuthKeyResolution.Existing
        }
    }

    /** Export the canonical DER SPKI. Requires a prior explicit [resolveOrCreate]. */
    public suspend fun publicKeySpkiBase64Url(): String {
        return Base64Url.encode(validatedPublicKeySpki())
    }

    /** Compute the RFC 7638 thumbprint. Requires a prior explicit [resolveOrCreate]. */
    public suspend fun thumbprint(): String {
        val spki = validatedPublicKeySpki()
        return try {
            P256PublicKeyEncoding.jwkThumbprint(spki)
        } catch (error: RuntimeException) {
            throw DaaSecureKeyException(DaaSecureKeyError.PublicKeyUnavailable, error)
        }
    }

    /**
     * Sign a validated request with this exact key. A key with a durable registration
     * acknowledgement signs every validated operation, so a returning user is not asked
     * to resolve it again after a relaunch. A key that exists without that
     * acknowledgement signs only enrollment operations that prove possession:
     * Device Registration Complete (`register_device_key`) and
     * `complete_social_login`, and only after this instance resolved it
     * explicitly.
     *
     * The biometric prompt is shown over [activity]. The SDK sets all of its text from the
     * validated operation; the caller supplies none.
     */
    public suspend fun signDeviceAuthorization(
        signingInput: DaaDeviceAuthorizationSigningInput,
        activity: FragmentActivity,
    ): ByteArray {
        val authorizedKey = requireSigningAuthorized(signingInput.permitsPendingRegistration)
        requireProtectionSufficientFor(signingInput.operation)
        return signExactBytes(signingInput.signingBytes(), activity, signingInput.operation, authorizedKey)
    }

    /**
     * Sign a validated Device Registration Complete request with this exact key.
     * Complete runs before [acknowledgeRegistration], so a created/unacknowledged
     * key may sign after this instance resolved it. Routed through the same
     * [requireSigningAuthorized] gate [signDeviceAuthorization] uses, always as an
     * operation that permits pending registration -- proving possession at Complete
     * is the point of this path -- so the backend re-validates the key here exactly as
     * it does there, rather than trusting a bare resolved flag. The biometric prompt
     * is shown over [activity] with SDK-set text, as for [signDeviceAuthorization].
     *
     * Only `daa-device-authorization+jws` is accepted. A flow-key
     * `typ` fails closed so this AuthKey cannot mint the other Complete proof.
     *
     * The device proof's payload carries no key claim: it holds only the
     * request-binding claims, and the verifier checks the signature against the
     * public key embedded in the header `jwk`. The `typ` check alone would still
     * let this key sign an input whose header `jwk` names a different key --
     * [DaaRegistrationAuthorizationSigningInput] validates only that the `jwk` is
     * a well-formed P-256 point, never that it is *this* key. This method closes
     * that gap by comparing the `jwk`'s RFC 7638 thumbprint against the thumbprint
     * of the exact key the signing gate authorized -- the key [signExactBytes] then
     * requires the backend to sign with -- and throwing
     * [DaaSecureKeyError.AuthKeyThumbprintMismatch] before [signExactBytes] ever
     * reaches the Keystore signing call for that input.
     *
     * This comparison requires [thumbprint] to succeed, which in turn requires
     * this instance to have already called [resolveOrCreate] explicitly in this
     * process, this session. That is a real, intentional constraint on top of
     * what [requireSigningAuthorized] alone requires above:
     * [requireSigningAuthorized] gives a durably-acknowledged key (backend state
     * `Existing`) a shortcut to sign even from a freshly relaunched instance that
     * never called [resolveOrCreate] -- that is how a returning user
     * re-authenticates after relaunch without resolving first. [thumbprint] has
     * no equivalent shortcut: it always requires [explicitlyResolved] regardless
     * of durable backend state. So a fresh instance that relies only on a
     * durable acknowledgement gets [DaaSecureKeyError.ResolutionRequired] from
     * [thumbprint] here instead of signing, even though
     * [requireSigningAuthorized]'s own gate would have let it through. Device
     * Registration Complete always resolves the key it is about to use in the
     * same instance, in the same call, before [acknowledgeRegistration], so it
     * never relies on that shortcut. This tradeoff -- failing closed with
     * `ResolutionRequired` rather than replicating [requireSigningAuthorized]'s
     * durable-state shortcut here -- is deliberate: the failure mode is an
     * erroneous rejection, not a security gap. See the relaunch test in `DaaSecureKeyTest` for the pinned behavior.
     */
    public suspend fun signRegistrationDeviceAuthorization(
        signingInput: DaaRegistrationAuthorizationSigningInput,
        activity: FragmentActivity,
    ): ByteArray {
        val authorizedKey = requireSigningAuthorized(permitsPendingRegistration = true)
        val exactBytes =
            signingInput.signingBytes(DaaRegistrationAuthorizationSigningInputValidator.DEVICE_TYP)
        // Requires this instance's own explicit resolution, as [thumbprint] does (see above).
        requireResolved()
        val authorizedThumbprint =
            try {
                P256PublicKeyEncoding.jwkThumbprint(authorizedKey)
            } catch (error: RuntimeException) {
                throw DaaSecureKeyException(DaaSecureKeyError.PublicKeyUnavailable, error)
            }
        if (authorizedThumbprint != signingInput.headerJwkThumbprint) {
            throw DaaSecureKeyException(DaaSecureKeyError.AuthKeyThumbprintMismatch)
        }
        return signExactBytes(
            exactBytes,
            activity,
            // Device Registration Complete is the route for `register_device_key`; the
            // consent prompt names it the same way a `signDeviceAuthorization` call for that
            // operation would.
            DaaDeviceAuthorizationSigningInputValidator.REGISTER_DEVICE_KEY,
            authorizedKey,
        )
    }

    /**
     * Signs with exactly [authorizedKey], the SPKI the signing gate authorized. The gate and the
     * signature are not one critical section -- a biometric prompt sits between them -- so the
     * backend re-checks that key against the one it actually signs with, and a key replaced under
     * the alias in between fails with [DaaSecureKeyError.ResolutionRequired] instead of signing.
     */
    private suspend fun signExactBytes(
        exactBytes: ByteArray,
        activity: FragmentActivity,
        operation: String,
        authorizedKey: ByteArray,
    ): ByteArray =
        signingLock.withLock {
            try {
                EcdsaSignatureJose.rawRepresentation(
                    backend.signDer(identity, protection, exactBytes, activity, operation, authorizedKey),
                )
            } catch (error: DaaSecureKeyException) {
                throw error
            } catch (error: RuntimeException) {
                throw DaaSecureKeyException(DaaSecureKeyError.SigningFailed, error)
            }
        }

    /**
     * Bind operation class to minimum protection profile inside the SDK rather than leaving it
     * to the integrator. `AuthKeyProtectionMode.DeviceUnlocked` signs with no per-signature
     * user verification, so it may sign only an operation in
     * [DaaDeviceAuthorizationSigningInputValidator.DEVICE_UNLOCKED_PERMITTED_OPERATIONS]; this
     * throws for anything else before [signExactBytes] ever reaches the Keystore signing call.
     * Checked as an allowlist, not a denylist of consequential operations: an operation this
     * check has never been taught about fails closed rather than inheriting a pass. `DeviceUnlocked`
     * is unreachable from application code (see [AuthKeyProtectionMode]), so this only guards the
     * module-internal profile that on-device instrumentation tests use.
     */
    private fun requireProtectionSufficientFor(operation: String) {
        if (protection == AuthKeyProtectionMode.DeviceUnlocked &&
            operation !in DaaDeviceAuthorizationSigningInputValidator.DEVICE_UNLOCKED_PERMITTED_OPERATIONS
        ) {
            throw DaaSecureKeyException(DaaSecureKeyError.ProtectionUnavailable)
        }
    }

    /**
     * The exact key material [requireResolvedKeyMaterial] verified, never a second read: a second
     * read could return a key another instance or process replaced after the verification, and
     * this instance would export a key it never resolved.
     */
    private suspend fun validatedPublicKeySpki(): ByteArray {
        val spki = requireResolvedKeyMaterial()
        return try {
            P256PublicKeyEncoding.x963Representation(spki)
            spki
        } catch (error: RuntimeException) {
            throw DaaSecureKeyException(DaaSecureKeyError.PublicKeyUnavailable, error)
        }
    }

    private suspend fun requireResolved() {
        requireResolvedKeyMaterial()
    }

    /**
     * [requireResolved], returning the exact key material that resolution was made against, so a
     * caller can hand the backend the key it expects to act on.
     */
    private suspend fun requireResolvedKeyMaterial(): ByteArray {
        val expected = resolvedKeyMaterial
        if (!explicitlyResolved || expected == null || !cachedStateIsCurrent()) {
            throw DaaSecureKeyException(DaaSecureKeyError.ResolutionRequired)
        }
        return expected.copyOf()
    }

    /** The exact public key material the backend reports for [identity] right now. */
    private suspend fun currentKeyMaterial(): ByteArray = backend.publicKeySpki(identity)

    /**
     * True only when [resolvedKeyMaterial] was recorded for the exact key material the backend
     * reports right now. False whenever nothing has been recorded yet, or when reading the
     * backend's current key material fails -- either way there is nothing to trust a cache
     * against, so the caller falls back to asking the backend directly instead of assuming the
     * cache still applies.
     */
    private suspend fun cachedStateIsCurrent(): Boolean {
        val observed = resolvedKeyMaterial ?: return false
        return try {
            observed.contentEquals(currentKeyMaterial())
        } catch (error: DaaSecureKeyException) {
            false
        }
    }

    /**
     * Authorizes signing and returns the DER SPKI of the exact key authorized, which the caller
     * must hand to the backend's signing call so nothing but that key signs.
     */
    private suspend fun requireSigningAuthorized(permitsPendingRegistration: Boolean): ByteArray {
        acknowledgedKeyMaterial()?.let { return it }
        // Without a durable acknowledgement the key is trusted no further than the
        // caller's own resolution: login completion may prove possession of the pending
        // key, and every other operation waits for Circle to register it.
        val resolvedKey = requireResolvedKeyMaterial()
        if (!permitsPendingRegistration) {
            throw DaaSecureKeyException(DaaSecureKeyError.AuthKeyRegistrationRequired)
        }
        return resolvedKey
    }

    /**
     * Read durable registration state without creating, deleting, or replacing key
     * material, so an acknowledgement written before this process started, or by another
     * live instance, is observed. An observed acknowledgement is cached because nothing
     * can undo it; anything else is re-read on the next call, so an acknowledgement
     * written elsewhere is never missed.
     *
     * The cache short-circuit is gated by [cachedStateIsCurrent]: a `resolution` of `Existing`
     * observed for a key that has since been replaced under this identity's alias must not
     * authorize signing by whatever key the alias names now -- that observation gets treated as
     * absent, falling through to a fresh backend read instead.
     */
    private suspend fun acknowledgedKeyMaterial(): ByteArray? =
        resolutionLock.withLock {
            val cached = resolvedKeyMaterial
            if (resolution == DaaAuthKeyResolution.Existing && cached != null && cachedStateIsCurrent()) {
                return@withLock cached.copyOf()
            }
            val durable = durableRegistrationState()
            if (durable.resolution != DaaAuthKeyResolution.Existing) return@withLock null
            // Cache the key the acknowledgement was read for, from that same backend read -- never a
            // second read, which could name a key re-created in between.
            resolution = DaaAuthKeyResolution.Existing
            resolvedKeyMaterial = durable.publicKeySpki
            durable.publicKeySpki
        }

    private suspend fun durableRegistrationState(): AuthKeyState =
        try {
            backend.registrationState(identity, protection)
        } catch (error: DaaSecureKeyException) {
            // Only resolveOrCreate() may mint a key, so a caller who never resolved is
            // told to resolve rather than handed a fresh one. A key that disappeared
            // after an explicit resolution is a wiped credential, and reporting it as
            // missing keeps recovery on the authorized re-registration path.
            if (error.error == DaaSecureKeyError.KeyNotFound && !explicitlyResolved) {
                throw DaaSecureKeyException(DaaSecureKeyError.ResolutionRequired, error)
            }
            throw error
        }

    private suspend fun resolveLocked(): DaaAuthKeyResolution {
        val cached = resolution
        if (cached == DaaAuthKeyResolution.Existing && cachedStateIsCurrent()) return cached
        val resolved = backend.resolveOrCreate(identity, protection)
        // The key the backend resolved, from that same read -- not a second read.
        resolution = resolved.resolution
        resolvedKeyMaterial = resolved.publicKeySpki
        return resolved.resolution
    }
}

/** One [Mutex] per Keystore alias, shared by every [DaaSecureKey] instance in the process. */
private val aliasLocks = ConcurrentHashMap<String, Mutex>()

/**
 * Maps the public, closed-set protection choice onto the backend's full internal domain. The
 * public constructor can only ever produce [AuthKeyProtectionMode.UserPresence] here: the no-prompt
 * [AuthKeyProtectionMode.DeviceUnlocked] mode is reachable only through the internal constructor
 * this module's own tests use, never through application code.
 */
private fun DaaAuthKeyProtection.toBackendMode(): AuthKeyProtectionMode =
    when (this) {
        DaaAuthKeyProtection.UserPresence -> AuthKeyProtectionMode.UserPresence
    }
