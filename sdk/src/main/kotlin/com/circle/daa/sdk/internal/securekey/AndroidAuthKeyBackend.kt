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

import android.annotation.SuppressLint
import android.app.KeyguardManager
import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.circle.daa.sdk.DaaAuthKeyIdentity
import com.circle.daa.sdk.DaaAuthKeyResolution
import com.circle.daa.sdk.DaaDeviceAuthorizationSigningInputValidator
import com.circle.daa.sdk.DaaDeviceAuthorizationValidation
import com.circle.daa.sdk.DaaRegistrationAuthorizationSigningInputValidator
import com.circle.daa.sdk.DaaSecureKeyError
import com.circle.daa.sdk.DaaSecureKeyException
import com.circle.daa.sdk.internal.EpochSeconds
import com.circle.daa.sdk.internal.authkey.Base64Url
import com.circle.daa.sdk.internal.authkey.P256PublicKeyEncoding
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.ProviderException
import java.security.Signature
import java.security.UnrecoverableEntryException
import java.security.UnrecoverableKeyException
import java.security.spec.ECGenParameterSpec
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

private const val REGISTRATION_MAC_KEYSTORE_PROVIDER = "AndroidKeyStore"
private const val REGISTRATION_MAC_ALGORITHM = "HmacSHA256"

/**
 * Non-exportable Keystore alias for [alias]'s registration-marker authenticator. Stable across
 * every AuthKey minted under the same alias: the marker's own key-binding field, not this MAC key,
 * ties a tag to one specific key generation (see [registrationMac]), so this key is never
 * recreated or deleted when the AuthKey it accompanies is replaced.
 */
internal fun registrationMacAlias(alias: String): String = "$alias.registration-mac"

private fun registrationMacKey(alias: String): SecretKey {
    existingRegistrationMacKey(alias)?.let { return it }
    val macAlias = registrationMacAlias(alias)
    val generator =
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, REGISTRATION_MAC_KEYSTORE_PROVIDER)
    generator.init(KeyGenParameterSpec.Builder(macAlias, KeyProperties.PURPOSE_SIGN).build())
    return generator.generateKey()
}

private fun existingRegistrationMacKey(alias: String): SecretKey? {
    val store = KeyStore.getInstance(REGISTRATION_MAC_KEYSTORE_PROVIDER).apply { load(null) }
    return store.getKey(registrationMacAlias(alias), null) as? SecretKey
}

/**
 * Authenticates [keyBinding] (an input [AuthKeyRegistrationMetadata] derives from the current
 * key's RFC 7638 thumbprint) under a dedicated, non-exportable Keystore key so that
 * [AuthKeyRegistrationMetadata]'s marker cannot be forged by anything that can merely write
 * app-private storage -- producing a value that matches requires an actual Keystore Sign operation
 * against a key this function never exports. Output is 43-character unpadded Base64URL, the same
 * shape a thumbprint has, so [AuthKeyRegistrationMetadata]'s format check applies unchanged.
 */
internal fun registrationMac(
    alias: String,
    keyBinding: String,
): String = registrationMacWith(registrationMacKey(alias), keyBinding)

/**
 * [registrationMac] for a read-only caller: never generates the authenticator key. A marker can only
 * have been written after that key existed, so its absence means no marker can verify, and the
 * caller treats that the same as a marker that does not match.
 */
internal fun existingRegistrationMac(
    alias: String,
    keyBinding: String,
): String =
    registrationMacWith(
        existingRegistrationMacKey(alias)
            ?: throw DaaSecureKeyException(DaaSecureKeyError.KeyMetadataUnavailable),
        keyBinding,
    )

private fun registrationMacWith(
    key: SecretKey,
    keyBinding: String,
): String {
    val mac = Mac.getInstance(REGISTRATION_MAC_ALGORITHM)
    mac.init(key)
    return Base64Url.encode(mac.doFinal(keyBinding.toByteArray(Charsets.US_ASCII)))
}

/**
 * The protection mode a stored protection record names, or `null` when the record is missing or
 * is not a record this SDK wrote (`v2:<mode>`).
 */
internal fun recordedProtection(record: Any?): AuthKeyProtectionMode? =
    AuthKeyProtectionMode.entries.firstOrNull { "v2:${it.name}" == record }

/**
 * The protection mode of a key that exists, for every path that acts on it: resolution, the
 * registration-state read, acknowledgement, and signing. A missing or unparsable record fails
 * closed with [DaaSecureKeyError.KeyMetadataUnavailable]; the key is never re-minted for it.
 */
internal fun requireRecordedProtection(record: Any?): AuthKeyProtectionMode =
    recordedProtection(record) ?: throw DaaSecureKeyException(DaaSecureKeyError.KeyMetadataUnavailable)

/**
 * The read-only restore decision behind `resolveExisting`, shared with the iOS SDK: metadata that
 * is missing or cannot be trusted means there is nothing to restore (`null`), and
 * `resolveOrCreate` is the one place that reports it as [DaaSecureKeyError.KeyMetadataUnavailable].
 * A failure to *read* is never mistaken for that: it throws [DaaSecureKeyError.KeyAccessFailed].
 *
 * - [protectionRecord] reads the stored protection record. Missing or unparsable is `null`.
 * - [validateExisting] runs the same `KeyInfo` checks resolution runs on an existing key; its
 *   failures (protection mismatch, no secure hardware, an unreadable key) throw unchanged.
 * - [marker] reads the registration marker. Missing is `null`.
 * - [certificate] reads the key's DER SPKI. A failure throws unchanged: a key without a readable
 *   certificate is not a missing record.
 * - [decode] checks the marker against that SPKI. A marker that is malformed, from an unknown
 *   version, or bound to another key is `null`; any other failure (for example the HMAC) throws
 *   [DaaSecureKeyError.KeyAccessFailed].
 */
internal fun <T : Any> restorableRegistration(
    protectionRecord: () -> Any?,
    validateExisting: (AuthKeyProtectionMode) -> Unit,
    marker: () -> String?,
    certificate: () -> ByteArray,
    decode: (marker: String, spki: ByteArray) -> T?,
): T? {
    val recorded = recordedProtection(restoreRead(protectionRecord)) ?: return null
    validateExisting(recorded)
    val storedMarker = restoreRead(marker) ?: return null
    val spki = certificate()
    return try {
        decode(storedMarker, spki)
    } catch (error: DaaSecureKeyException) {
        if (error.error == DaaSecureKeyError.KeyMetadataUnavailable ||
            error.error == DaaSecureKeyError.KeyMetadataVersionUnsupported
        ) {
            null
        } else {
            throw error
        }
    } catch (error: Exception) {
        throw DaaSecureKeyException(DaaSecureKeyError.KeyAccessFailed, error)
    }
}

/** A storage read on the restore path: a failure to read throws [DaaSecureKeyError.KeyAccessFailed]. */
private fun <T> restoreRead(read: () -> T): T =
    try {
        read()
    } catch (error: DaaSecureKeyException) {
        throw error
    } catch (error: Exception) {
        throw DaaSecureKeyException(DaaSecureKeyError.KeyAccessFailed, error)
    }

/**
 * Durable state for a replaced key must be cleared before its replacement exists. A surviving
 * registration marker would outlive the key it was bound to and fail closed as a mismatch on
 * every later resolution and acknowledgement, so a failed clear stops key creation instead.
 */
internal fun requireClearedForReplacement(cleared: Boolean) {
    if (!cleared) throw DaaSecureKeyException(DaaSecureKeyError.KeyCreationFailed)
}

internal fun requireValidSigningInputAtSignatureTime(
    message: ByteArray,
    nowEpochSeconds: Long,
) {
    when (val device = DaaDeviceAuthorizationSigningInputValidator.validate(message, nowEpochSeconds)) {
        is DaaDeviceAuthorizationValidation.Accepted -> return
        is DaaDeviceAuthorizationValidation.Rejected -> {
            if (device.error == DaaSecureKeyError.SigningInputExpired) {
                throw DaaSecureKeyException(device.error)
            }
        }
    }
    DaaRegistrationAuthorizationSigningInputValidator.error(message, nowEpochSeconds)?.let {
        throw DaaSecureKeyException(it)
    }
}

internal fun signInitialized(
    signature: Signature,
    message: ByteArray,
): ByteArray = signInitializedAt(signature, message, EpochSeconds.now())

/** Clock seam for deterministic tests; production signing calls [signInitialized]. */
internal fun signInitializedAt(
    signature: Signature,
    message: ByteArray,
    nowEpochSeconds: Long,
): ByteArray {
    requireValidSigningInputAtSignatureTime(message, nowEpochSeconds)
    return try {
        signature.update(message)
        signature.sign()
    } catch (error: KeyPermanentlyInvalidatedException) {
        throw DaaSecureKeyException(DaaSecureKeyError.KeyInvalidated, error)
    } catch (error: Exception) {
        throw DaaSecureKeyException(DaaSecureKeyError.SigningFailed, error)
    }
}

internal fun startBiometricAuthentication(
    isActivityStateSaved: Boolean,
    authenticate: () -> Unit,
) {
    try {
        if (isActivityStateSaved) {
            throw DaaSecureKeyException(DaaSecureKeyError.AuthenticationFailed)
        }
        authenticate()
    } catch (error: DaaSecureKeyException) {
        throw error
    } catch (error: Exception) {
        throw DaaSecureKeyException(DaaSecureKeyError.AuthenticationFailed, error)
    }
}

internal interface BiometricAuthenticationSession {
    fun authenticate(signature: Signature)

    fun cancel()
}

internal fun interface BiometricAuthenticationSessionFactory {
    fun create(
        activity: FragmentActivity,
        onError: (Int) -> Unit,
        onSuccess: (Signature?) -> Unit,
    ): BiometricAuthenticationSession
}

internal suspend fun authenticateAndSignWithBiometric(
    signature: Signature,
    message: ByteArray,
    activity: FragmentActivity,
    sessionFactory: BiometricAuthenticationSessionFactory,
    postToUi: ((() -> Unit) -> Unit),
    isActivityStateSaved: () -> Boolean,
    signingExecutor: Executor,
): ByteArray =
    suspendCancellableCoroutine { continuation ->
        val session =
            try {
                sessionFactory.create(
                    activity,
                    { errorCode ->
                        val error =
                            when (errorCode) {
                                BiometricPrompt.ERROR_USER_CANCELED, BiometricPrompt.ERROR_CANCELED,
                                BiometricPrompt.ERROR_NEGATIVE_BUTTON,
                                -> DaaSecureKeyError.UserCancelled
                                else -> DaaSecureKeyError.AuthenticationFailed
                            }
                        if (continuation.isActive) {
                            continuation.resumeWithException(DaaSecureKeyException(error))
                        }
                    },
                    { authenticated ->
                        if (authenticated == null) {
                            if (continuation.isActive) {
                                continuation.resumeWithException(
                                    DaaSecureKeyException(DaaSecureKeyError.AuthenticationFailed),
                                )
                            }
                        } else {
                            try {
                                signingExecutor.execute {
                                    // Checked again here, not just on the eventual resume: a
                                    // cancellation between biometric success and this dispatch
                                    // must stop the work itself, not just discard its result --
                                    // otherwise a cancelled caller's coroutine still consumes the
                                    // auth-per-use authorization and produces a signature nothing
                                    // reads.
                                    if (!continuation.isActive) return@execute
                                    try {
                                        val signed = signInitialized(authenticated, message)
                                        if (continuation.isActive) continuation.resume(signed)
                                    } catch (error: DaaSecureKeyException) {
                                        if (continuation.isActive) continuation.resumeWithException(error)
                                    } catch (error: Exception) {
                                        if (continuation.isActive) {
                                            continuation.resumeWithException(
                                                DaaSecureKeyException(DaaSecureKeyError.SigningFailed, error),
                                            )
                                        }
                                    }
                                }
                            } catch (error: Exception) {
                                if (continuation.isActive) {
                                    continuation.resumeWithException(
                                        DaaSecureKeyException(DaaSecureKeyError.SigningFailed, error),
                                    )
                                }
                            }
                        }
                    },
                )
            } catch (error: Exception) {
                continuation.resumeWithException(
                    DaaSecureKeyException(DaaSecureKeyError.AuthenticationFailed, error),
                )
                return@suspendCancellableCoroutine
            }
        continuation.invokeOnCancellation {
            try {
                session.cancel()
            } catch (_: Exception) {
                // Cancellation is already terminal; cleanup must not replace it.
            }
        }
        try {
            postToUi {
                if (!continuation.isActive) return@postToUi
                try {
                    startBiometricAuthentication(isActivityStateSaved()) {
                        session.authenticate(signature)
                    }
                } catch (error: DaaSecureKeyException) {
                    if (continuation.isActive) continuation.resumeWithException(error)
                }
            }
        } catch (error: Exception) {
            if (continuation.isActive) {
                continuation.resumeWithException(
                    DaaSecureKeyException(DaaSecureKeyError.AuthenticationFailed, error),
                )
            }
        }
    }

/**
 * The authenticator class a UserPresence key is pinned to at creation (API 30+): a strong biometric only, the same
 * class the signing path demands through `canAuthenticate(BIOMETRIC_STRONG)` and a `BiometricPrompt` that offers no
 * device-credential fallback. Creation and [isAuthenticatorPolicyPinned] both read this, so the policy that is set is
 * the policy that is asserted.
 *
 * The device credential is deliberately excluded. The SDK's own prompt never offers it, so allowing it at the key
 * would serve only a caller that bypasses that prompt — exactly the caller the key-level pin exists to stop.
 */
internal const val USER_PRESENCE_AUTHENTICATORS = KeyProperties.AUTH_BIOMETRIC_STRONG

/**
 * Whether `KeyInfo.userAuthenticationType` is exactly [USER_PRESENCE_AUTHENTICATORS].
 *
 * One value covers every key this SDK creates. A per-use key created below API 30 carries the platform's biometric
 * auth type (`HW_AUTH_BIOMETRIC`, the same bit as `AUTH_BIOMETRIC_STRONG`), so after the device upgrades to API 30+
 * it reports the same mask the pin sets and passes without re-registration.
 *
 * Exact equality, not a subset test: a mask that admits the device credential is weaker than the pin, and a mask
 * carrying a class this SDK never grants is unknown; both are refused. Separated from `KeyInfo` for the same reason as
 * [isAuthenticationPerUse].
 */
internal fun isAuthenticatorPolicyPinned(userAuthenticationType: Int): Boolean =
    userAuthenticationType == USER_PRESENCE_AUTHENTICATORS

/**
 * Maps a `BiometricManager.canAuthenticate(BIOMETRIC_STRONG)` status to the error a UserPresence operation fails with,
 * or `null` when a strong biometric is ready. Key creation and signing both use it, so a device without a strong
 * biometric fails identically at either step. Separated from `BiometricManager` for the same reason as
 * [isAuthenticationPerUse].
 */
internal fun strongBiometricUnavailableError(status: Int): DaaSecureKeyError? =
    when (status) {
        BiometricManager.BIOMETRIC_SUCCESS -> null
        BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE,
        BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE,
        -> DaaSecureKeyError.SecureHardwareUnavailable
        else -> DaaSecureKeyError.AuthenticationFailed
    }

/**
 * Whether the key demands authentication for **every** signature rather than trusting a window of time after one.
 *
 * That distinction is the point of [AuthKeyProtectionMode.UserPresence], so it is checked rather than assumed: a
 * key carrying a positive validity duration stays usable for that many seconds after a single unlock, which is a
 * materially weaker guarantee than the one an Owner AuthKey is supposed to make.
 *
 * Per-use has two spellings, and which one the platform reports depends on the API level rather than on anything
 * this SDK chose. From API 30 these keys pass `setUserAuthenticationParameters(0, ...)` — an explicit per-use
 * timeout of zero — so `KeyInfo` reports `0`. Below API 30 that method does not exist, so the key carries only
 * `setUserAuthenticationRequired(true)` and the validity duration defaults to `-1`, which is what
 * `setUserAuthenticationValidityDurationSeconds(-1)` also produced and what those releases report. Both mean
 * per-use; anything greater than zero is a time window and is refused.
 *
 * Accepting only `-1` would reject every key this SDK creates on an API 30+ device — creation would succeed and
 * nothing could ever use the key again.
 */
internal fun isAuthenticationPerUse(validityDurationSeconds: Int): Boolean = validityDurationSeconds <= 0

/**
 * Whether a `KeyInfo.securityLevel` value satisfies the "hardware-backed,
 * non-exportable" requirement for an AuthKey. Taking the reported level as a plain `Int` rather than a
 * `KeyInfo` is what makes this testable on a JVM at all: `KeyInfo` is an Android class and `securityLevel`
 * only exists from API 31, so the interpretation is pulled out here the same way [isAuthenticationPerUse]
 * pulls the per-use interpretation out of the duration it is handed.
 *
 * [KeyProperties.SECURITY_LEVEL_UNKNOWN] and [KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE] read as near
 * synonyms but are handled oppositely on purpose. `UNKNOWN` means the Keymaster implementation could not
 * report a level at all, so the one guarantee this check exists to make cannot be confirmed and it fails
 * closed. `UNKNOWN_SECURE` is a distinct, documented contract: the platform would not report it unless the
 * key is at least as strong as [KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT] — it withholds only
 * which exact tier (TEE or StrongBox) produced the key, not whether hardware was involved — so it passes.
 *
 * Written as an allowlist rather than as "anything that is not software or unknown". A level this code
 * has never been taught about is not evidence of hardware backing, so a value added to the platform
 * after this was written must fail closed and force a deliberate decision here, not inherit a pass.
 */
internal fun isHardwareBackedSecurityLevel(securityLevel: Int): Boolean =
    securityLevel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ||
        securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX ||
        securityLevel == KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE

/**
 * Requests StrongBox on the first attempt and, if the platform reports the secure element unavailable, runs
 * [generate] once more with StrongBox off. This retry is the only control flow StrongBox support adds, so
 * it is pulled out here — the same way [isAuthenticationPerUse] and [isHardwareBackedSecurityLevel] are — to be
 * exercised on a JVM: minting a Keystore key needs a live secure element, but the branch that decides whether to
 * fall back does not.
 *
 * [generate] receives `true` when [strongBoxRequested] and `false` on the fallback. The caller passes
 * `strongBoxRequested = false` below API 28, so on those releases the single attempt runs with StrongBox off and
 * the `StrongBoxUnavailableException` handler is never reached — which is why referencing that API-28 type here is
 * safe down to `minSdk`: the catch clause is resolved only when an instance actually propagates through it.
 *
 * `NewApi` is suppressed for that reason. Lint's heuristic cannot see the guard once the catch sits outside the
 * guarded StrongBox call, so the guarantee is stated here explicitly instead.
 */
@SuppressLint("NewApi")
internal fun generateWithStrongBoxFallback(
    strongBoxRequested: Boolean,
    generate: (strongBox: Boolean) -> Unit,
) {
    try {
        generate(strongBoxRequested)
    } catch (error: StrongBoxUnavailableException) {
        generate(false)
    }
}

/**
 * Human-readable label naming the operation being authorized, keyed by the validated wire
 * discriminator. The consent prompt shows this label, never the raw discriminator. The wording is
 * a cross-platform table and must stay byte-for-byte identical to the iOS SDK's.
 */
private val OPERATION_LABELS: Map<String, String> =
    mapOf(
        DaaDeviceAuthorizationSigningInputValidator.TRANSFER to "transfer",
        DaaDeviceAuthorizationSigningInputValidator.WITHDRAWAL to "withdrawal",
        DaaDeviceAuthorizationSigningInputValidator.CREATE_ACCOUNT to "account creation",
        DaaDeviceAuthorizationSigningInputValidator.REGISTER_DEVICE_KEY to "device registration",
        DaaDeviceAuthorizationSigningInputValidator.COMPLETE_SOCIAL_LOGIN to "sign-in",
        DaaDeviceAuthorizationSigningInputValidator.GET_DEVICE_CONTEXT to "device verification",
    )

/**
 * The complete consent-prompt title for [operation]. The SDK sets all prompt text; a caller
 * supplies none, so nothing an integrator passes can mislead the user about what is being signed.
 * The operation is shown through [OPERATION_LABELS] as a human-readable label, never as the raw
 * wire discriminator. An operation absent from the table -- unreachable, since the signing input
 * is validated against the fixed set of operations before it reaches here -- falls back to a bare
 * "Authorizing" rather than ever surfacing the raw string. English only; any further language
 * would be bundled with the SDK and chosen from the device locale, never by the caller.
 */
internal fun operationAuthorizationPrompt(operation: String): String {
    val label = OPERATION_LABELS[operation]
    return if (label != null) "Authorizing: $label" else "Authorizing"
}

/** Negative-button text of the consent prompt. SDK-set, like the title. */
internal const val PROMPT_NEGATIVE_BUTTON_TEXT = "Cancel"

/**
 * Builds the `BiometricPrompt.PromptInfo` shown for [operation]. Pulled out of
 * [AndroidAuthKeyBackend.authenticateAndSign] as a standalone function, callable directly by an
 * instrumentation test without needing to drive an actual biometric authentication: constructing
 * a `PromptInfo` requires the real Android `BiometricPrompt` class (unavailable on a plain JVM
 * unit test) but not real biometric hardware.
 */
internal fun biometricPromptInfo(operation: String): BiometricPrompt.PromptInfo =
    BiometricPrompt.PromptInfo.Builder()
        .setTitle(operationAuthorizationPrompt(operation))
        .setNegativeButtonText(PROMPT_NEGATIVE_BUTTON_TEXT)
        .build()

@SuppressLint("ApplySharedPref")
internal class AndroidAuthKeyBackend(
    context: Context,
    private val mainDispatcher: CoroutineDispatcher = Dispatchers.Main.immediate,
) : AuthKeyBackend {
    private val appContext = context.applicationContext
    private val metadata = NoBackupMetadataStore(appContext, METADATA_FILE)
    private val legacyMetadata = NoBackupMetadataStore(appContext, LEGACY_METADATA_FILE)
    private val registration = NoBackupMetadataStore(appContext, REGISTRATION_FILE)

    override suspend fun resolveOrCreate(
        identity: DaaAuthKeyIdentity,
        protection: AuthKeyProtectionMode,
    ): AuthKeyState =
        withContext(dispatcher) {
            try {
                val store = keyStore()
                if (store.containsAlias(identity.alias)) {
                    val recorded = requireRecordedProtection(metadata.all[identity.alias])
                    validateExisting(store, identity, protection, recorded)
                    return@withContext registrationResolution(store, identity)
                }
                requireClearedForReplacement(metadata.edit().remove(identity.alias).commit())
                requireClearedForReplacement(registration.edit().remove(identity.alias).commit())
                if (legacyMetadata.contains(identity.alias)) {
                    requireClearedForReplacement(legacyMetadata.edit().remove(identity.alias).commit())
                }
                requireDeviceCredential()
                // The key is bound to a strong biometric, so without one enrolled the platform refuses to create
                // it and the failure would surface as a generic KeyCreationFailed. Check first and fail the same
                // way signing does.
                if (protection == AuthKeyProtectionMode.UserPresence) requireStrongBiometric(appContext)
                val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)

                fun spec(strongBox: Boolean): KeyGenParameterSpec {
                    val builder =
                        KeyGenParameterSpec.Builder(identity.alias, KeyProperties.PURPOSE_SIGN)
                            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                            .setDigests(KeyProperties.DIGEST_SHA256)
                            .setUserAuthenticationRequired(protection == AuthKeyProtectionMode.UserPresence)
                    if (protection == AuthKeyProtectionMode.UserPresence &&
                        Build.VERSION.SDK_INT >= Build.VERSION_CODES.R
                    ) {
                        // State the authenticator class on the key explicitly rather than relying on the
                        // builder's default, so the policy is asserted in code and matches what
                        // validateExisting checks. setUserAuthenticationParameters is API 30; below that,
                        // setUserAuthenticationRequired(true) with the default per-use duration already binds
                        // the key to the platform's biometric auth type.
                        builder.setUserAuthenticationParameters(0, USER_PRESENCE_AUTHENTICATORS)
                    }
                    if (protection == AuthKeyProtectionMode.DeviceUnlocked) {
                        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
                            throw DaaSecureKeyException(DaaSecureKeyError.ProtectionUnavailable)
                        }
                        builder.setUnlockedDeviceRequired(true)
                    }
                    if (strongBox) {
                        builder.setIsStrongBoxBacked(true)
                    }
                    return builder.build()
                }
                // Request StrongBox — the dedicated secure element — on capable hardware, but its
                // availability is inconsistent across devices, so fall back to TEE unconditionally when the
                // platform reports it unavailable. setIsStrongBoxBacked is API 28; StrongBox is only requested
                // on API 28+, and the fallback control flow lives in generateWithStrongBoxFallback.
                generateWithStrongBoxFallback(Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) { strongBox ->
                    generator.initialize(spec(strongBox))
                    generator.generateKeyPair()
                }
                // KeyGenParameterSpec has no hardware-only gate: it accepts and silently
                // satisfies a request that falls back to software, so the hardware-backed guarantee can
                // only be enforced after the fact, against what the platform actually produced. Nothing
                // durable has been written for this alias yet — the metadata write is still below — so a
                // rejection here only has the fresh keystore entry itself to remove.
                try {
                    val created =
                        store.getKey(identity.alias, null) as? PrivateKey
                            ?: throw DaaSecureKeyException(DaaSecureKeyError.KeyCreationFailed)
                    val createdInfo =
                        KeyFactory.getInstance(created.algorithm, ANDROID_KEYSTORE)
                            .getKeySpec(created, KeyInfo::class.java)
                    requireHardwareBacked(createdInfo)
                } catch (error: DaaSecureKeyException) {
                    store.deleteEntry(identity.alias)
                    throw error
                } catch (error: Exception) {
                    store.deleteEntry(identity.alias)
                    throw DaaSecureKeyException(DaaSecureKeyError.KeyCreationFailed, error)
                }
                if (!metadata.edit().putString(identity.alias, protection.metadata).commit()) {
                    store.deleteEntry(identity.alias)
                    throw DaaSecureKeyException(DaaSecureKeyError.KeyCreationFailed)
                }
                AuthKeyState(DaaAuthKeyResolution.Created, publicKeyEncoded(store, identity))
            } catch (error: DaaSecureKeyException) {
                throw error
            } catch (error: ProviderException) {
                throw DaaSecureKeyException(DaaSecureKeyError.SecureHardwareUnavailable, error)
            } catch (error: Exception) {
                throw DaaSecureKeyException(DaaSecureKeyError.KeyCreationFailed, error)
            }
        }

    override suspend fun acknowledgeRegistration(
        identity: DaaAuthKeyIdentity,
        protection: AuthKeyProtectionMode,
        expectedPublicKeySpki: ByteArray,
    ): Unit =
        withContext(dispatcher) {
            try {
                val store = keyStore()
                if (!store.containsAlias(identity.alias)) {
                    throw DaaSecureKeyException(DaaSecureKeyError.KeyNotFound)
                }
                val recorded = requireRecordedProtection(metadata.all[identity.alias])
                validateExisting(store, identity, protection, recorded)
                val thumbprint = expectedKeyThumbprint(store, identity, expectedPublicKeySpki)
                if (registration.contains(identity.alias)) {
                    // Either version is an acknowledgement of this key; a marker that already carries
                    // identifiers keeps them.
                    AuthKeyRegistrationMetadata.decode(registration.all[identity.alias], thumbprint) {
                        registrationMac(identity.alias, it)
                    }
                    return@withContext
                }
                val marker = AuthKeyRegistrationMetadata.encode(thumbprint) { registrationMac(identity.alias, it) }
                if (!registration.edit().putString(identity.alias, marker).commit()) {
                    throw DaaSecureKeyException(DaaSecureKeyError.KeyMetadataUnavailable)
                }
            } catch (error: DaaSecureKeyException) {
                throw error
            } catch (error: ProviderException) {
                throw DaaSecureKeyException(DaaSecureKeyError.SecureHardwareUnavailable, error)
            } catch (error: Exception) {
                throw DaaSecureKeyException(DaaSecureKeyError.KeyMetadataUnavailable, error)
            }
        }

    override suspend fun recordRegistration(
        identity: DaaAuthKeyIdentity,
        protection: AuthKeyProtectionMode,
        record: AuthKeyRegistrationRecord,
        expectedPublicKeySpki: ByteArray,
    ): Unit =
        withContext(dispatcher) {
            try {
                val store = keyStore()
                if (!store.containsAlias(identity.alias)) {
                    throw DaaSecureKeyException(DaaSecureKeyError.KeyNotFound)
                }
                val recorded = requireRecordedProtection(metadata.all[identity.alias])
                validateExisting(store, identity, protection, recorded)
                // Written unconditionally. The key was just validated and the marker is bound to it, so
                // whatever was stored before -- a legacy marker, identifiers from an earlier registration
                // of this same key, or a marker that no longer verifies -- is replaced by the
                // registration Circle has just confirmed rather than left to block it.
                val thumbprint = expectedKeyThumbprint(store, identity, expectedPublicKeySpki)
                val marker =
                    AuthKeyRegistrationMetadata.encode(record, thumbprint) {
                        registrationMac(identity.alias, it)
                    }
                if (!registration.edit().putString(identity.alias, marker).commit()) {
                    throw DaaSecureKeyException(DaaSecureKeyError.KeyMetadataUnavailable)
                }
            } catch (error: DaaSecureKeyException) {
                throw error
            } catch (error: ProviderException) {
                throw DaaSecureKeyException(DaaSecureKeyError.SecureHardwareUnavailable, error)
            } catch (error: Exception) {
                throw DaaSecureKeyException(DaaSecureKeyError.KeyMetadataUnavailable, error)
            }
        }

    override suspend fun registeredAuthKey(
        identity: DaaAuthKeyIdentity,
        protection: AuthKeyProtectionMode,
    ): AuthKeyRegisteredKey? =
        withContext(dispatcher) {
            try {
                val store = keyStore()
                if (!store.containsAlias(identity.alias)) return@withContext null
                restorableRegistration(
                    protectionRecord = { metadata.all[identity.alias] },
                    // The same KeyInfo checks resolveOrCreate runs on an existing key, hardware backing
                    // included. Reading KeyInfo needs no user authentication, so no prompt is shown.
                    validateExisting = { recorded -> validateExisting(store, identity, protection, recorded) },
                    marker = { registration.all[identity.alias] },
                    // One certificate read supplies both the thumbprint the marker is verified against
                    // and the material the caller caches, so the two can never describe different keys.
                    certificate = { publicKeyEncoded(store, identity) },
                    decode = { marker, spki ->
                        AuthKeyRegistrationMetadata.decode(marker, P256PublicKeyEncoding.jwkThumbprint(spki)) {
                            existingRegistrationMac(identity.alias, it)
                        }?.let { AuthKeyRegisteredKey(it, spki) }
                    },
                )
            } catch (error: DaaSecureKeyException) {
                throw error
            } catch (error: ProviderException) {
                throw DaaSecureKeyException(DaaSecureKeyError.SecureHardwareUnavailable, error)
            } catch (error: Exception) {
                throw DaaSecureKeyException(DaaSecureKeyError.KeyAccessFailed, error)
            }
        }

    override suspend fun publicKeySpki(identity: DaaAuthKeyIdentity): ByteArray =
        withContext(dispatcher) {
            try {
                val certificate =
                    keyStore().getCertificate(identity.alias)
                        ?: throw DaaSecureKeyException(DaaSecureKeyError.KeyNotFound)
                certificate.publicKey.encoded?.copyOf()
                    ?: throw DaaSecureKeyException(DaaSecureKeyError.PublicKeyUnavailable)
            } catch (error: DaaSecureKeyException) {
                throw error
            } catch (error: Exception) {
                throw DaaSecureKeyException(DaaSecureKeyError.PublicKeyUnavailable, error)
            }
        }

    override suspend fun registrationState(
        identity: DaaAuthKeyIdentity,
        protection: AuthKeyProtectionMode,
    ): AuthKeyState =
        withContext(dispatcher) {
            try {
                val store = keyStore()
                if (!store.containsAlias(identity.alias)) {
                    throw DaaSecureKeyException(DaaSecureKeyError.KeyNotFound)
                }
                val recorded = requireRecordedProtection(metadata.all[identity.alias])
                validateExisting(store, identity, protection, recorded)
                registrationResolution(store, identity)
            } catch (error: DaaSecureKeyException) {
                throw error
            } catch (error: ProviderException) {
                throw DaaSecureKeyException(DaaSecureKeyError.SecureHardwareUnavailable, error)
            } catch (error: Exception) {
                throw DaaSecureKeyException(DaaSecureKeyError.KeyMetadataUnavailable, error)
            }
        }

    override suspend fun signDer(
        identity: DaaAuthKeyIdentity,
        protection: AuthKeyProtectionMode,
        message: ByteArray,
        activity: FragmentActivity,
        operation: String,
        expectedPublicKeySpki: ByteArray,
    ): ByteArray {
        val signature =
            withContext(dispatcher) {
                val key = expectedPrivateKey(identity, expectedPublicKeySpki)
                try {
                    Signature.getInstance("SHA256withECDSA").also { it.initSign(key) }
                } catch (error: KeyPermanentlyInvalidatedException) {
                    throw DaaSecureKeyException(DaaSecureKeyError.KeyInvalidated, error)
                } catch (error: java.security.NoSuchAlgorithmException) {
                    throw DaaSecureKeyException(DaaSecureKeyError.SigningAlgorithmUnavailable, error)
                } catch (error: Exception) {
                    throw DaaSecureKeyException(DaaSecureKeyError.SigningFailed, error)
                }
            }
        if (protection == AuthKeyProtectionMode.DeviceUnlocked) {
            return withContext(dispatcher) {
                signInitialized(signature, message)
            }
        }
        requireStrongBiometric(activity)
        return withContext(mainDispatcher) {
            authenticateAndSign(signature, message.copyOf(), activity, operation)
        }
    }

    private suspend fun authenticateAndSign(
        signature: Signature,
        message: ByteArray,
        activity: FragmentActivity,
        operation: String,
    ): ByteArray {
        val sessionFactory =
            BiometricAuthenticationSessionFactory { sessionActivity, onError, onSuccess ->
                val executor = ContextCompat.getMainExecutor(sessionActivity)
                val biometric =
                    BiometricPrompt(
                        sessionActivity,
                        executor,
                        object : BiometricPrompt.AuthenticationCallback() {
                            override fun onAuthenticationError(
                                errorCode: Int,
                                errString: CharSequence,
                            ) = onError(errorCode)

                            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                                onSuccess(result.cryptoObject?.signature)
                            }
                        },
                    )
                val info =
                    // Confirmation stays at the platform default (required). Suppressing it would
                    // let a passive biometric (e.g. face unlock) complete signing the instant the
                    // user glances at the screen, with no deliberate action -- weaker than the
                    // deliberate-action guarantee an Owner AuthKey signature is supposed to carry.
                    biometricPromptInfo(operation)
                object : BiometricAuthenticationSession {
                    override fun authenticate(signature: Signature) {
                        biometric.authenticate(info, BiometricPrompt.CryptoObject(signature))
                    }

                    override fun cancel() {
                        sessionActivity.runOnUiThread { biometric.cancelAuthentication() }
                    }
                }
            }
        return authenticateAndSignWithBiometric(
            signature = signature,
            message = message,
            activity = activity,
            sessionFactory = sessionFactory,
            postToUi = { action -> activity.runOnUiThread(action) },
            isActivityStateSaved = { activity.supportFragmentManager.isStateSaved },
            signingExecutor = executorService,
        )
    }

    private fun validateExisting(
        store: KeyStore,
        identity: DaaAuthKeyIdentity,
        requested: AuthKeyProtectionMode,
        recorded: AuthKeyProtectionMode,
    ) {
        try {
            if (recorded != requested) throw DaaSecureKeyException(DaaSecureKeyError.ProtectionMismatch)
            val key =
                store.getKey(identity.alias, null) as? PrivateKey
                    ?: throw DaaSecureKeyException(DaaSecureKeyError.KeyAccessFailed)
            val info = KeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE).getKeySpec(key, KeyInfo::class.java)
            val requiresPresence = requested == AuthKeyProtectionMode.UserPresence
            if (key.algorithm != KeyProperties.KEY_ALGORITHM_EC || info.keySize != 256 ||
                info.purposes != KeyProperties.PURPOSE_SIGN ||
                info.digests.toSet() != setOf(KeyProperties.DIGEST_SHA256) ||
                info.isUserAuthenticationRequired != requiresPresence ||
                (requiresPresence && !isAuthenticationPerUse(info.userAuthenticationValidityDurationSeconds))
            ) {
                throw DaaSecureKeyException(DaaSecureKeyError.ProtectionMismatch)
            }
            // Creation pins the authenticator class (KeyInfo.userAuthenticationType is API 30), so an existing key
            // must still carry exactly that pin. A key made below API 30 reports the same mask after an OS upgrade.
            if (requiresPresence &&
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.R &&
                !isAuthenticatorPolicyPinned(info.userAuthenticationType)
            ) {
                throw DaaSecureKeyException(DaaSecureKeyError.ProtectionMismatch)
            }
            // A key resolved from a prior run is trusted only as far as the platform still backs it: a
            // device that later lost its secure hardware (or a key restored onto different hardware than
            // it was created on) must fail the same way a brand-new software fallback does, not be waved
            // through because it once passed this check.
            requireHardwareBacked(info)
        } catch (error: DaaSecureKeyException) {
            throw error
        } catch (error: Exception) {
            throw DaaSecureKeyException(DaaSecureKeyError.KeyAccessFailed, error)
        }
    }

    /**
     * Enforces the one property `KeyInfo`'s other fields never speak to: whether the platform actually
     * placed the key in secure hardware rather than quietly falling back to software.
     *
     * From API 31, `securityLevel` distinguishes StrongBox from TEE from software; see
     * [isHardwareBackedSecurityLevel] for why `SECURITY_LEVEL_UNKNOWN` and `_UNKNOWN_SECURE` are handled
     * oppositely. Below API 31, `KeyInfo` has no `securityLevel` property at all — it would be a
     * `NoSuchMethodError` against the platform's real class, not merely an unmocked stub — so the
     * deprecated `isInsideSecureHardware` is the only signal available there. It collapses StrongBox and
     * TEE into a single bit, which is coarser, but it is still exactly the true/false distinction the
     * hardware-backed requirement asks for.
     */
    private fun requireHardwareBacked(info: KeyInfo) {
        val hardwareBacked =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                isHardwareBackedSecurityLevel(info.securityLevel)
            } else {
                // Deprecated in API 31, but there is nothing to migrate to on this branch: minSdk is 23,
                // and `securityLevel` does not exist below 31. Reading it here would be a NoSuchMethodError
                // against the real platform class at runtime, not a compile error. Suppressing the warning
                // is the only option that keeps the check running on API 23-30 — dropping it would fail
                // open on exactly the older devices least likely to have secure hardware.
                @Suppress("DEPRECATION")
                info.isInsideSecureHardware
            }
        if (!hardwareBacked) throw DaaSecureKeyException(DaaSecureKeyError.SecureHardwareUnavailable)
    }

    /**
     * Registration state for [identity]'s current key, with that key's SPKI. One certificate read
     * supplies both the thumbprint the marker is checked against and the SPKI returned, so the
     * state and the key it names can never describe different keys.
     *
     * The marker never stores a value computed from the thumbprint alone: it is always passed
     * through an HMAC under a dedicated, non-exportable Keystore key (see [registrationMac]). The
     * thumbprint is derivable by any same-process code straight from the Keystore certificate (it
     * is also this SDK's own public `thumbprint()`), so binding to it directly would let anything
     * that can write app-private storage mint its own valid-looking marker without touching the
     * Keystore.
     */
    private fun registrationResolution(
        store: KeyStore,
        identity: DaaAuthKeyIdentity,
    ): AuthKeyState {
        val spki =
            try {
                publicKeyEncoded(store, identity)
            } catch (error: DaaSecureKeyException) {
                throw error
            } catch (error: Exception) {
                throw DaaSecureKeyException(DaaSecureKeyError.KeyMetadataUnavailable, error)
            }
        if (!registration.contains(identity.alias)) return AuthKeyState(DaaAuthKeyResolution.Created, spki)
        val thumbprint =
            try {
                P256PublicKeyEncoding.jwkThumbprint(spki)
            } catch (error: Exception) {
                throw DaaSecureKeyException(DaaSecureKeyError.KeyMetadataUnavailable, error)
            }
        AuthKeyRegistrationMetadata.decode(registration.all[identity.alias], thumbprint) {
            registrationMac(identity.alias, it)
        }
        return AuthKeyState(DaaAuthKeyResolution.Existing, spki)
    }

    /**
     * The thumbprint of the key under [identity]'s alias, read once, provided it is still exactly
     * [expected] -- the key the caller resolved. A replacement visible at this read fails with
     * [DaaSecureKeyError.ResolutionRequired] before writing. This check does not coordinate
     * processes or prevent another process from changing the alias after the read.
     */
    private fun expectedKeyThumbprint(
        store: KeyStore,
        identity: DaaAuthKeyIdentity,
        expected: ByteArray,
    ): String {
        val spki = publicKeyEncoded(store, identity)
        if (!spki.contentEquals(expected)) throw DaaSecureKeyException(DaaSecureKeyError.ResolutionRequired)
        return P256PublicKeyEncoding.jwkThumbprint(spki)
    }

    private fun publicKeyEncoded(
        store: KeyStore,
        identity: DaaAuthKeyIdentity,
    ): ByteArray =
        store.getCertificate(identity.alias)?.publicKey?.encoded
            ?: throw DaaSecureKeyException(DaaSecureKeyError.KeyMetadataUnavailable)

    /**
     * The private key under [identity]'s alias, provided its certificate is still exactly
     * [expected]. The private key and the certificate come from one `getEntry` read, so the key
     * compared is the key that signs: a key replaced under the alias after the caller authorized
     * signing fails with [DaaSecureKeyError.ResolutionRequired], the same error
     * [recordRegistration] uses for a replaced key, and is never initialized for signing.
     */
    private fun expectedPrivateKey(
        identity: DaaAuthKeyIdentity,
        expected: ByteArray,
    ): PrivateKey =
        try {
            val entry =
                keyStore().getEntry(identity.alias, null) as? KeyStore.PrivateKeyEntry
                    ?: throw DaaSecureKeyException(DaaSecureKeyError.KeyNotFound)
            val spki =
                entry.certificate?.publicKey?.encoded
                    ?: throw DaaSecureKeyException(DaaSecureKeyError.PublicKeyUnavailable)
            if (!spki.contentEquals(expected)) throw DaaSecureKeyException(DaaSecureKeyError.ResolutionRequired)
            entry.privateKey
        } catch (error: DaaSecureKeyException) {
            throw error
        } catch (error: UnrecoverableKeyException) {
            throw DaaSecureKeyException(DaaSecureKeyError.KeyInvalidated, error)
        } catch (error: UnrecoverableEntryException) {
            throw DaaSecureKeyException(DaaSecureKeyError.KeyInvalidated, error)
        } catch (error: Exception) {
            throw DaaSecureKeyException(DaaSecureKeyError.KeyAccessFailed, error)
        }

    private fun requireStrongBiometric(context: Context) {
        strongBiometricUnavailableError(
            BiometricManager.from(context).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG),
        )?.let { throw DaaSecureKeyException(it) }
    }

    private fun requireDeviceCredential() {
        val manager = appContext.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        if (!manager.isDeviceSecure) throw DaaSecureKeyException(DaaSecureKeyError.DeviceCredentialNotSet)
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private val AuthKeyProtectionMode.metadata: String get() = "v2:$name"

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val METADATA_FILE = "com.circle.daa.authkey.protection.v2"
        const val LEGACY_METADATA_FILE = "com.circle.daa.authkey.protection.v1"
        const val REGISTRATION_FILE = "com.circle.daa.authkey.registration.v1"
        val executorService = Executors.newSingleThreadExecutor { runnable -> Thread(runnable, "daa-authkey") }
        val dispatcher: CoroutineDispatcher = executorService.asCoroutineDispatcher()
    }
}
