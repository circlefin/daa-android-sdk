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

import android.app.KeyguardManager
import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricManager
import androidx.fragment.app.FragmentActivity
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.circle.daa.sdk.DaaAuthKeyIdentity
import com.circle.daa.sdk.DaaAuthKeyProtection
import com.circle.daa.sdk.DaaAuthKeyResolution
import com.circle.daa.sdk.DaaEnvironment
import com.circle.daa.sdk.DaaSecureKey
import com.circle.daa.sdk.DaaSecureKeyError
import com.circle.daa.sdk.DaaSecureKeyException
import com.circle.daa.sdk.internal.authkey.P256PublicKeyEncoding
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.io.FileInputStream
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.spec.ECGenParameterSpec
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class AndroidAuthKeyBackendTest {
    private var lockScreenMutationAttempted = false
    private val testIdentities = mutableListOf<DaaAuthKeyIdentity>()

    @Before
    fun configureEphemeralManagedDeviceLockScreen() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val keyguard = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        if (keyguard.isDeviceSecure) return
        assumeTrue(
            "Device or emulator must have a secure lock screen",
            InstrumentationRegistry.getArguments().getString(CONFIGURE_TEST_LOCK_ARGUMENT) == "true",
        )
        check(Build.HARDWARE in EMULATOR_HARDWARE) {
            "$CONFIGURE_TEST_LOCK_ARGUMENT is emulator-only; refusing to set a PIN on ${Build.HARDWARE}"
        }

        lockScreenMutationAttempted = true
        val output = shell("locksettings set-pin $MANAGED_DEVICE_PIN 2>&1")
        repeat(LOCK_SCREEN_ATTEMPTS) {
            if (keyguard.isDeviceSecure) return
            Thread.sleep(LOCK_SCREEN_POLL_MILLIS)
        }
        error("Managed-device lock screen did not become secure: $output")
    }

    @After
    fun cleanUpDeviceState() {
        try {
            clearTestKeys()
        } finally {
            clearEphemeralManagedDeviceLockScreen()
        }
    }

    private fun clearTestKeys() {
        if (testIdentities.isEmpty()) return
        val context = ApplicationProvider.getApplicationContext<Context>()
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val failures = mutableListOf<Throwable>()
        testIdentities.forEach { identity ->
            failures.capture {
                if (store.containsAlias(identity.alias)) store.deleteEntry(identity.alias)
            }
            failures.capture {
                val macAlias = registrationMacAlias(identity.alias)
                if (store.containsAlias(macAlias)) store.deleteEntry(macAlias)
            }
            failures.capture {
                check(
                    NoBackupMetadataStore(context, METADATA_FILE)
                        .edit().remove(identity.alias).commit(),
                )
            }
            failures.capture {
                check(
                    NoBackupMetadataStore(context, LEGACY_METADATA_FILE)
                        .edit().remove(identity.alias).commit(),
                )
            }
            failures.capture {
                check(
                    NoBackupMetadataStore(context, REGISTRATION_FILE)
                        .edit().remove(identity.alias).commit(),
                )
            }
        }
        testIdentities.clear()
        if (failures.isNotEmpty()) {
            throw AssertionError("Unable to clean up ${failures.size} AuthKey test artifact(s)").apply {
                failures.forEach(::addSuppressed)
            }
        }
    }

    private fun MutableList<Throwable>.capture(block: () -> Unit) {
        runCatching(block).exceptionOrNull()?.let(::add)
    }

    private fun clearEphemeralManagedDeviceLockScreen() {
        if (!lockScreenMutationAttempted) return
        lockScreenMutationAttempted = false
        val context = ApplicationProvider.getApplicationContext<Context>()
        val keyguard = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        val output = shell("locksettings clear --old $MANAGED_DEVICE_PIN 2>&1")
        repeat(LOCK_SCREEN_ATTEMPTS) {
            if (!keyguard.isDeviceSecure) return
            Thread.sleep(LOCK_SCREEN_POLL_MILLIS)
        }
        error("Unable to clear managed-device lock screen: $output")
    }

    private fun testIdentity(): DaaAuthKeyIdentity =
        DaaAuthKeyIdentity(
            appId = "instrumentation",
            environment = DaaEnvironment.Sandbox,
            installationId = UUID.randomUUID(),
        ).also(testIdentities::add)

    /**
     * Whether this device's keystore actually backs a freshly generated key with secure hardware.
     *
     * The backend under test enforces this rather than assuming it, so what a test here should expect
     * from `resolveOrCreate` depends on real device capability, not on the emulator/device matrix this
     * suite happened to run on. Probing with a throwaway key generated the same way the backend generates
     * its own — rather than trusting a hardware feature flag — is what makes this trustworthy on an
     * emulator whose reported feature set and its Keymaster/KeyMint implementation could in principle
     * disagree.
     */
    private fun probeIsHardwareBacked(context: Context): Boolean {
        val alias = testIdentity().alias
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").run {
            initialize(
                KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .build(),
            )
            generateKeyPair()
        }
        val key = store.getKey(alias, null) as PrivateKey
        val info = KeyFactory.getInstance(key.algorithm, "AndroidKeyStore").getKeySpec(key, KeyInfo::class.java)
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            isHardwareBackedSecurityLevel(info.securityLevel)
        } else {
            @Suppress("DEPRECATION")
            info.isInsideSecureHardware
        }
    }

    private fun shell(command: String): String =
        InstrumentationRegistry.getInstrumentation().uiAutomation.executeShellCommand(command).use {
            FileInputStream(it.fileDescriptor).bufferedReader().use { reader -> reader.readText() }
        }

    @Test
    fun reportsCreatedAcrossRestartUntilRegistrationIsAcknowledged(): Unit =
        runBlocking {
            val context = ApplicationProvider.getApplicationContext<Context>()
            val keyguard = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
            assumeTrue("Device or emulator must have a secure lock screen", keyguard.isDeviceSecure)
            assumeTrue("Device-unlocked keys require API 28", Build.VERSION.SDK_INT >= Build.VERSION_CODES.P)
            val identity = testIdentity()
            val backend = AndroidAuthKeyBackend(context)

            if (!probeIsHardwareBacked(context)) {
                // This device's keystore cannot produce a hardware-backed key, which an AuthKey must be, so
                // no restart-persistence or acknowledgement behavior is reachable here: creation itself
                // must refuse before any of that state exists.
                val error =
                    try {
                        backend.resolveOrCreate(identity, AuthKeyProtectionMode.DeviceUnlocked)
                        null
                    } catch (caught: DaaSecureKeyException) {
                        caught
                    }
                assertEquals(DaaSecureKeyError.SecureHardwareUnavailable, error?.error)
                return@runBlocking
            }

            assertEquals(
                DaaAuthKeyResolution.Created,
                backend.resolveOrCreate(identity, AuthKeyProtectionMode.DeviceUnlocked).resolution,
            )
            assertTrue(File(context.noBackupFilesDir, METADATA_FILE).isFile)
            assertFalse(File(context.dataDir, "shared_prefs/$METADATA_FILE.xml").exists())
            assertEquals(
                DaaAuthKeyResolution.Created,
                AndroidAuthKeyBackend(
                    context,
                ).resolveOrCreate(identity, AuthKeyProtectionMode.DeviceUnlocked).resolution,
            )
            backend.acknowledgeRegistration(
                identity,
                AuthKeyProtectionMode.DeviceUnlocked,
                backend.publicKeySpki(identity),
            )
            backend.acknowledgeRegistration(
                identity,
                AuthKeyProtectionMode.DeviceUnlocked,
                backend.publicKeySpki(identity),
            )
            assertTrue(File(context.noBackupFilesDir, REGISTRATION_FILE).isFile)
            assertFalse(File(context.dataDir, "shared_prefs/$REGISTRATION_FILE.xml").exists())
            assertEquals(
                DaaAuthKeyResolution.Existing,
                AndroidAuthKeyBackend(
                    context,
                ).resolveOrCreate(identity, AuthKeyProtectionMode.DeviceUnlocked).resolution,
            )
            assertEquals(91, backend.publicKeySpki(identity).size)
        }

    @Test
    fun recoversMetadataWhenAtomicFileHasOnlyItsBackup(): Unit =
        runBlocking {
            val context = ApplicationProvider.getApplicationContext<Context>()
            val name = "atomic-recovery"
            val key = "recovery-key"
            val file = File(context.noBackupFilesDir, name)
            val backup = File("${file.path}.bak")
            file.delete()
            backup.delete()

            try {
                assertTrue(NoBackupMetadataStore(context, name).edit().putString(key, "value").commit())
                assertTrue(file.renameTo(backup))
                assertFalse(file.exists())

                assertEquals("value", NoBackupMetadataStore(context, name).all[key])
                assertTrue(file.isFile)
                assertFalse(backup.exists())
            } finally {
                file.delete()
                backup.delete()
            }
        }

    @Test
    fun publicConstructorResolvesAUserPresenceKeyEndToEnd(): Unit =
        runBlocking {
            // DaaSecureKey's public constructor is the only path application code has into this
            // module, and DaaAuthKeyProtection.toBackendMode() hard-maps every value it can carry
            // to AuthKeyProtectionMode.UserPresence. That mapping is exercised nowhere else: the
            // JVM tests construct DaaSecureKey with an already-converted AuthKeyProtectionMode via
            // the internal constructor, and the rest of this suite drives AndroidAuthKeyBackend
            // directly. This resolves a key the same way an integrator would and checks the
            // Keystore entry it actually produced, so a future regression that let the boundary
            // conversion resolve to DeviceUnlocked (or anything else) would fail here.
            val context = ApplicationProvider.getApplicationContext<Context>()
            val keyguard = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
            assumeTrue("Device or emulator must have a secure lock screen", keyguard.isDeviceSecure)
            val identity = testIdentity()
            val key = DaaSecureKey(context, identity, DaaAuthKeyProtection.UserPresence)

            // The key is bound to a strong biometric, so creation is refused up front without one.
            val biometricError =
                strongBiometricUnavailableError(
                    BiometricManager.from(context).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG),
                )
            if (biometricError != null) {
                val error =
                    try {
                        key.resolveOrCreate()
                        null
                    } catch (caught: DaaSecureKeyException) {
                        caught
                    }
                assertEquals(biometricError, error?.error)
                return@runBlocking
            }

            if (!probeIsHardwareBacked(context)) {
                val error =
                    try {
                        key.resolveOrCreate()
                        null
                    } catch (caught: DaaSecureKeyException) {
                        caught
                    }
                assertEquals(DaaSecureKeyError.SecureHardwareUnavailable, error?.error)
                return@runBlocking
            }

            assertEquals(DaaAuthKeyResolution.Created, key.resolveOrCreate())

            val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val privateKey = store.getKey(identity.alias, null) as PrivateKey
            val info =
                KeyFactory.getInstance(privateKey.algorithm, "AndroidKeyStore")
                    .getKeySpec(privateKey, KeyInfo::class.java)
            assertTrue(info.isUserAuthenticationRequired)
            assertTrue(isAuthenticationPerUse(info.userAuthenticationValidityDurationSeconds))
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                // The key must bind the authenticator class itself, not defer to the platform default.
                assertEquals(KeyProperties.AUTH_BIOMETRIC_STRONG, info.userAuthenticationType)
            }
        }

    @Test
    fun failsClosedInsteadOfDeletingAKeyWithUnrecoverableMetadata(): Unit =
        runBlocking {
            val context = ApplicationProvider.getApplicationContext<Context>()
            val keyguard = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
            assumeTrue("Device or emulator must have a secure lock screen", keyguard.isDeviceSecure)
            assumeTrue("Device-unlocked keys require API 28", Build.VERSION.SDK_INT >= Build.VERSION_CODES.P)
            val identity = testIdentity()
            val backend = AndroidAuthKeyBackend(context)
            val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

            // Simulates the alias the Keystore still has once its metadata is missing or
            // unparsable. No metadata means no basis for treating any protection profile as
            // correct, so this must never be read as license to delete the key it describes and
            // mint a replacement in its place.
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").run {
                initialize(
                    KeyGenParameterSpec.Builder(identity.alias, KeyProperties.PURPOSE_SIGN)
                        .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                        .setDigests(KeyProperties.DIGEST_SHA256)
                        .setUserAuthenticationRequired(false)
                        .build(),
                )
                generateKeyPair()
            }
            val originalSpki = store.getCertificate(identity.alias).publicKey.encoded

            // The read-only restore lookup reports the same state as nothing to restore, and leaves
            // the key alone; resolution is the one place that reports it.
            assertNull(backend.registeredAuthKey(identity, AuthKeyProtectionMode.DeviceUnlocked))
            assertArrayEquals(originalSpki, store.getCertificate(identity.alias).publicKey.encoded)

            val error =
                try {
                    backend.resolveOrCreate(identity, AuthKeyProtectionMode.DeviceUnlocked)
                    null
                } catch (caught: DaaSecureKeyException) {
                    caught
                }

            assertEquals(DaaSecureKeyError.KeyMetadataUnavailable, error?.error)
            assertTrue(store.containsAlias(identity.alias))
            assertArrayEquals(originalSpki, store.getCertificate(identity.alias).publicKey.encoded)
        }

    @Test
    fun rejectsAnExistingUserPresenceKeyThatAdmitsTheDeviceCredential(): Unit =
        runBlocking {
            val context = ApplicationProvider.getApplicationContext<Context>()
            val keyguard = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
            assumeTrue("Device or emulator must have a secure lock screen", keyguard.isDeviceSecure)
            assumeTrue("Authenticator types are API 30", Build.VERSION.SDK_INT >= Build.VERSION_CODES.R)
            val identity = testIdentity()
            val backend = AndroidAuthKeyBackend(context)
            val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

            // An otherwise-valid per-use key carrying a wider authenticator mask than the pin, with metadata that
            // records it as UserPresence. The mask check runs before the hardware-backing check, so this is reached
            // on a software-tier emulator Keystore too.
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").run {
                initialize(
                    KeyGenParameterSpec.Builder(identity.alias, KeyProperties.PURPOSE_SIGN)
                        .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                        .setDigests(KeyProperties.DIGEST_SHA256)
                        .setUserAuthenticationRequired(true)
                        .setUserAuthenticationParameters(
                            0,
                            KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
                        )
                        .build(),
                )
                generateKeyPair()
            }
            assertTrue(
                NoBackupMetadataStore(context, METADATA_FILE).edit()
                    .putString(identity.alias, "v2:${AuthKeyProtectionMode.UserPresence.name}").commit(),
            )
            val originalSpki = store.getCertificate(identity.alias).publicKey.encoded

            val error =
                try {
                    backend.resolveOrCreate(identity, AuthKeyProtectionMode.UserPresence)
                    null
                } catch (caught: DaaSecureKeyException) {
                    caught
                }

            assertEquals(DaaSecureKeyError.ProtectionMismatch, error?.error)
            assertTrue(store.containsAlias(identity.alias))
            assertArrayEquals(originalSpki, store.getCertificate(identity.alias).publicKey.encoded)
        }

    @Test
    fun rejectsRegistrationMetadataBoundToAnotherKey(): Unit =
        runBlocking {
            val context = ApplicationProvider.getApplicationContext<Context>()
            val keyguard = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
            assumeTrue("Device or emulator must have a secure lock screen", keyguard.isDeviceSecure)
            assumeTrue("Device-unlocked keys require API 28", Build.VERSION.SDK_INT >= Build.VERSION_CODES.P)
            val first = testIdentity()
            val second = testIdentity()
            val backend = AndroidAuthKeyBackend(context)

            if (!probeIsHardwareBacked(context)) {
                // Both keys this test binds a spoofed registration marker to must exist before the marker
                // means anything, and neither can come into being on this device.
                val error =
                    try {
                        backend.resolveOrCreate(first, AuthKeyProtectionMode.DeviceUnlocked)
                        null
                    } catch (caught: DaaSecureKeyException) {
                        caught
                    }
                assertEquals(DaaSecureKeyError.SecureHardwareUnavailable, error?.error)
                return@runBlocking
            }

            backend.resolveOrCreate(first, AuthKeyProtectionMode.DeviceUnlocked)
            backend.resolveOrCreate(second, AuthKeyProtectionMode.DeviceUnlocked)
            val firstThumbprint = P256PublicKeyEncoding.jwkThumbprint(backend.publicKeySpki(first))
            val registrations = NoBackupMetadataStore(context, REGISTRATION_FILE)
            registrations.edit().putString(
                second.alias,
                AuthKeyRegistrationMetadata.encode(firstThumbprint) { it },
            ).commit()

            val error =
                try {
                    AndroidAuthKeyBackend(context).resolveOrCreate(second, AuthKeyProtectionMode.DeviceUnlocked)
                    null
                } catch (caught: DaaSecureKeyException) {
                    caught
                }

            assertEquals(DaaSecureKeyError.KeyMetadataUnavailable, error?.error)
        }

    // The registration marker must not be forgeable by anything that can merely write
    // app-private storage. The key's bare RFC 7638 thumbprint is derivable in-process from the
    // Keystore certificate with no Keystore Sign operation involved, and is also this SDK's own
    // public thumbprint(). A marker written using exactly that bare thumbprint for the *correct*
    // key must therefore be rejected: the field it is compared against is an HMAC tag over that
    // thumbprint computed with a dedicated, non-exportable Keystore key (see registrationMac), not
    // the thumbprint itself.
    @Test
    fun rejectsARegistrationMarkerBoundToTheBareThumbprintInsteadOfTheKeystoreMac(): Unit =
        runBlocking {
            val context = ApplicationProvider.getApplicationContext<Context>()
            val keyguard = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
            assumeTrue("Device or emulator must have a secure lock screen", keyguard.isDeviceSecure)
            assumeTrue("Device-unlocked keys require API 28", Build.VERSION.SDK_INT >= Build.VERSION_CODES.P)
            val identity = testIdentity()
            val backend = AndroidAuthKeyBackend(context)

            if (!probeIsHardwareBacked(context)) {
                val error =
                    try {
                        backend.resolveOrCreate(identity, AuthKeyProtectionMode.DeviceUnlocked)
                        null
                    } catch (caught: DaaSecureKeyException) {
                        caught
                    }
                assertEquals(DaaSecureKeyError.SecureHardwareUnavailable, error?.error)
                return@runBlocking
            }

            backend.resolveOrCreate(identity, AuthKeyProtectionMode.DeviceUnlocked)
            val bareThumbprint = P256PublicKeyEncoding.jwkThumbprint(backend.publicKeySpki(identity))
            val registrations = NoBackupMetadataStore(context, REGISTRATION_FILE)
            registrations.edit().putString(
                identity.alias,
                AuthKeyRegistrationMetadata.encode(bareThumbprint) { it },
            ).commit()

            val error =
                try {
                    AndroidAuthKeyBackend(context).resolveOrCreate(identity, AuthKeyProtectionMode.DeviceUnlocked)
                    null
                } catch (caught: DaaSecureKeyException) {
                    caught
                }

            assertEquals(DaaSecureKeyError.KeyMetadataUnavailable, error?.error)
        }

    @Test
    fun recordsAndRestoresRegistrationIdentifiersAndReplacesThemOnReRegistration(): Unit =
        runBlocking {
            val context = ApplicationProvider.getApplicationContext<Context>()
            val keyguard = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
            assumeTrue("Device or emulator must have a secure lock screen", keyguard.isDeviceSecure)
            assumeTrue("Device-unlocked keys require API 28", Build.VERSION.SDK_INT >= Build.VERSION_CODES.P)
            assumeTrue("Requires a hardware-backed keystore", probeIsHardwareBacked(context))
            val identity = testIdentity()
            val backend = AndroidAuthKeyBackend(context)
            backend.resolveOrCreate(identity, AuthKeyProtectionMode.DeviceUnlocked)
            assertNull(backend.registeredAuthKey(identity, AuthKeyProtectionMode.DeviceUnlocked))

            // A legacy acknowledgement is an acknowledgement, but restores nothing.
            backend.acknowledgeRegistration(
                identity,
                AuthKeyProtectionMode.DeviceUnlocked,
                backend.publicKeySpki(identity),
            )
            assertNull(AndroidAuthKeyBackend(context).registeredAuthKey(identity, AuthKeyProtectionMode.DeviceUnlocked))
            assertEquals(
                DaaAuthKeyResolution.Existing,
                AndroidAuthKeyBackend(
                    context,
                ).resolveOrCreate(identity, AuthKeyProtectionMode.DeviceUnlocked).resolution,
            )

            val first = AuthKeyRegistrationRecord(UUID.randomUUID().toString(), UUID.randomUUID().toString(), 1L)
            backend.recordRegistration(
                identity,
                AuthKeyProtectionMode.DeviceUnlocked,
                first,
                backend.publicKeySpki(identity),
            )
            val restored =
                AndroidAuthKeyBackend(context).registeredAuthKey(identity, AuthKeyProtectionMode.DeviceUnlocked)
            assertEquals(first, restored?.record)
            // The lookup reports the exact key material it verified the registration against.
            assertArrayEquals(backend.publicKeySpki(identity), restored?.publicKeySpki)

            val second = AuthKeyRegistrationRecord(UUID.randomUUID().toString(), UUID.randomUUID().toString(), 2L)
            backend.recordRegistration(
                identity,
                AuthKeyProtectionMode.DeviceUnlocked,
                second,
                backend.publicKeySpki(identity),
            )
            assertEquals(
                second,
                AndroidAuthKeyBackend(
                    context,
                ).registeredAuthKey(identity, AuthKeyProtectionMode.DeviceUnlocked)?.record,
            )
            // The legacy acknowledgement keeps identifiers that are already recorded.
            backend.acknowledgeRegistration(
                identity,
                AuthKeyProtectionMode.DeviceUnlocked,
                backend.publicKeySpki(identity),
            )
            assertEquals(second, backend.registeredAuthKey(identity, AuthKeyProtectionMode.DeviceUnlocked)?.record)
            assertEquals(
                DaaAuthKeyResolution.Existing,
                backend.registrationState(identity, AuthKeyProtectionMode.DeviceUnlocked).resolution,
            )
        }

    @Test
    fun registeredAuthKeyReportsNoRegistrationForAForeignOrUnreadableMarker(): Unit =
        runBlocking {
            val context = ApplicationProvider.getApplicationContext<Context>()
            val keyguard = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
            assumeTrue("Device or emulator must have a secure lock screen", keyguard.isDeviceSecure)
            assumeTrue("Device-unlocked keys require API 28", Build.VERSION.SDK_INT >= Build.VERSION_CODES.P)
            assumeTrue("Requires a hardware-backed keystore", probeIsHardwareBacked(context))
            val first = testIdentity()
            val second = testIdentity()
            val backend = AndroidAuthKeyBackend(context)
            val record = AuthKeyRegistrationRecord(UUID.randomUUID().toString(), UUID.randomUUID().toString(), 1L)
            backend.resolveOrCreate(first, AuthKeyProtectionMode.DeviceUnlocked)
            backend.resolveOrCreate(second, AuthKeyProtectionMode.DeviceUnlocked)
            backend.recordRegistration(
                first,
                AuthKeyProtectionMode.DeviceUnlocked,
                record,
                backend.publicKeySpki(first),
            )
            val registrations = NoBackupMetadataStore(context, REGISTRATION_FILE)

            listOf(
                // Copied from another key.
                registrations.all.getValue(first.alias),
                "not a marker",
                "v9:registration:registered:x",
            ).forEach { marker ->
                registrations.edit().putString(second.alias, marker).commit()
                assertNull(backend.registeredAuthKey(second, AuthKeyProtectionMode.DeviceUnlocked))
                assertEquals(marker, registrations.all[second.alias])
            }
        }

    @Test
    fun signDerRefusesAKeyOtherThanTheOneAuthorized(): Unit =
        runBlocking {
            val context = ApplicationProvider.getApplicationContext<Context>()
            val keyguard = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
            assumeTrue("Device or emulator must have a secure lock screen", keyguard.isDeviceSecure)
            assumeTrue("Device-unlocked keys require API 28", Build.VERSION.SDK_INT >= Build.VERSION_CODES.P)
            assumeTrue("Requires a hardware-backed keystore", probeIsHardwareBacked(context))
            val identity = testIdentity()
            val backend = AndroidAuthKeyBackend(context)
            backend.resolveOrCreate(identity, AuthKeyProtectionMode.DeviceUnlocked)
            val other =
                KeyPairGenerator.getInstance("EC").run {
                    initialize(ECGenParameterSpec("secp256r1"))
                    generateKeyPair().public.encoded
                }
            // DeviceUnlocked signing never shows a prompt, so the activity is never used; the expected-key
            // check runs before the signature is even initialized.
            lateinit var activity: FragmentActivity
            InstrumentationRegistry.getInstrumentation().runOnMainSync { activity = FragmentActivity() }

            val error =
                try {
                    backend.signDer(
                        identity,
                        AuthKeyProtectionMode.DeviceUnlocked,
                        ByteArray(0),
                        activity,
                        "get_device_context",
                        other,
                    )
                    null
                } catch (caught: DaaSecureKeyException) {
                    caught
                }

            assertEquals(DaaSecureKeyError.ResolutionRequired, error?.error)
        }

    @Test
    fun registeredAuthKeyDoesNotCreateAMissingKey(): Unit =
        runBlocking {
            val context = ApplicationProvider.getApplicationContext<Context>()
            val identity = testIdentity()
            val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

            assertNull(AndroidAuthKeyBackend(context).registeredAuthKey(identity, AuthKeyProtectionMode.DeviceUnlocked))

            assertFalse(store.containsAlias(identity.alias))
            assertFalse(store.containsAlias(registrationMacAlias(identity.alias)))
            assertFalse(NoBackupMetadataStore(context, METADATA_FILE).contains(identity.alias))
        }

    @Test
    fun registrationStateNeverMutatesExistingKeyOrMetadata(): Unit =
        runBlocking {
            val context = ApplicationProvider.getApplicationContext<Context>()
            val keyguard = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
            assumeTrue("Device or emulator must have a secure lock screen", keyguard.isDeviceSecure)
            assumeTrue("Device-unlocked keys require API 28", Build.VERSION.SDK_INT >= Build.VERSION_CODES.P)
            val identity = testIdentity()
            val backend = AndroidAuthKeyBackend(context)
            val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val metadata = NoBackupMetadataStore(context, METADATA_FILE)
            val registrations = NoBackupMetadataStore(context, REGISTRATION_FILE)

            if (!probeIsHardwareBacked(context)) {
                // Nothing this test verifies about registrationState's read-only behavior is reachable
                // without a key to read in the first place.
                val error =
                    try {
                        backend.resolveOrCreate(identity, AuthKeyProtectionMode.DeviceUnlocked)
                        null
                    } catch (caught: DaaSecureKeyException) {
                        caught
                    }
                assertEquals(DaaSecureKeyError.SecureHardwareUnavailable, error?.error)
                assertFalse(store.containsAlias(identity.alias))
                assertFalse(metadata.contains(identity.alias))
                assertFalse(registrations.contains(identity.alias))
                return@runBlocking
            }

            assertEquals(
                DaaAuthKeyResolution.Created,
                backend.resolveOrCreate(identity, AuthKeyProtectionMode.DeviceUnlocked).resolution,
            )
            val spki = backend.publicKeySpki(identity)
            val protectionMetadata = metadata.all[identity.alias]

            assertEquals(
                DaaAuthKeyResolution.Created,
                backend.registrationState(identity, AuthKeyProtectionMode.DeviceUnlocked).resolution,
            )
            assertEquals(protectionMetadata, metadata.all[identity.alias])
            assertFalse(registrations.contains(identity.alias))
            assertArrayEquals(spki, backend.publicKeySpki(identity))
            assertTrue(store.containsAlias(identity.alias))

            backend.acknowledgeRegistration(
                identity,
                AuthKeyProtectionMode.DeviceUnlocked,
                backend.publicKeySpki(identity),
            )
            val registrationMetadata = registrations.all[identity.alias]
            assertEquals(
                DaaAuthKeyResolution.Existing,
                backend.registrationState(identity, AuthKeyProtectionMode.DeviceUnlocked).resolution,
            )
            assertEquals(protectionMetadata, metadata.all[identity.alias])
            assertEquals(registrationMetadata, registrations.all[identity.alias])
            assertArrayEquals(spki, backend.publicKeySpki(identity))
            assertTrue(store.containsAlias(identity.alias))
        }

    @Test
    fun registrationStateDoesNotCreateMissingKeyOrMetadata(): Unit =
        runBlocking {
            val context = ApplicationProvider.getApplicationContext<Context>()
            val identity = testIdentity()
            val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val metadata = NoBackupMetadataStore(context, METADATA_FILE)
            val registrations = NoBackupMetadataStore(context, REGISTRATION_FILE)

            val error =
                try {
                    AndroidAuthKeyBackend(context).registrationState(
                        identity,
                        AuthKeyProtectionMode.DeviceUnlocked,
                    )
                    null
                } catch (caught: DaaSecureKeyException) {
                    caught
                }

            assertEquals(DaaSecureKeyError.KeyNotFound, error?.error)
            assertFalse(store.containsAlias(identity.alias))
            assertFalse(metadata.contains(identity.alias))
            assertFalse(registrations.contains(identity.alias))
        }

    @Test
    fun refusesAndCleansUpAKeyTheKeystoreFellBackToSoftwareFor(): Unit =
        runBlocking {
            val context = ApplicationProvider.getApplicationContext<Context>()
            val keyguard = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
            assumeTrue("Device or emulator must have a secure lock screen", keyguard.isDeviceSecure)
            assumeTrue("Device-unlocked keys require API 28", Build.VERSION.SDK_INT >= Build.VERSION_CODES.P)
            assumeTrue(
                "Requires a keystore that falls back to software to exercise the rejection path",
                !probeIsHardwareBacked(context),
            )
            val identity = testIdentity()
            val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val metadata = NoBackupMetadataStore(context, METADATA_FILE)
            val registrations = NoBackupMetadataStore(context, REGISTRATION_FILE)

            val error =
                try {
                    AndroidAuthKeyBackend(context).resolveOrCreate(identity, AuthKeyProtectionMode.DeviceUnlocked)
                    null
                } catch (caught: DaaSecureKeyException) {
                    caught
                }

            assertEquals(DaaSecureKeyError.SecureHardwareUnavailable, error?.error)
            assertFalse(store.containsAlias(identity.alias))
            assertFalse(metadata.contains(identity.alias))
            assertFalse(registrations.contains(identity.alias))
        }

    /**
     * The biometric consent prompt must state the operation being authorized as a human-readable
     * label — never the raw wire discriminator — and every piece of its text is SDK-set: there is
     * no caller input to build it from. `PromptInfo` is a real `androidx.biometric` class —
     * unavailable in a plain JVM unit test — so this is the only lane that can assert on the
     * constructed object; [OperationAuthorizationPromptTest] (`sdk/src/test`) covers the underlying
     * discriminator→label mapping and does execute.
     */
    @Test
    fun biometricPromptIsSetEntirelyFromTheOperation() {
        val createAccount = biometricPromptInfo("create_account")
        assertEquals("Authorizing: account creation", createAccount.title)
        assertEquals("Cancel", createAccount.negativeButtonText)
        assertNull(createAccount.subtitle)
        assertNull(createAccount.description)
        assertFalse(createAccount.title.contains("create_account"))

        val transfer = biometricPromptInfo("transfer")
        assertEquals("Authorizing: transfer", transfer.title)
        assertNull(transfer.subtitle)
        assertNull(transfer.description)
    }

    private companion object {
        const val CONFIGURE_TEST_LOCK_ARGUMENT = "configureTestLock"
        const val MANAGED_DEVICE_PIN = "34263426"
        const val METADATA_FILE = "com.circle.daa.authkey.protection.v2"
        const val LEGACY_METADATA_FILE = "com.circle.daa.authkey.protection.v1"
        const val REGISTRATION_FILE = "com.circle.daa.authkey.registration.v1"
        const val LOCK_SCREEN_ATTEMPTS = 100
        const val LOCK_SCREEN_POLL_MILLIS = 100L
        val EMULATOR_HARDWARE = setOf("ranchu", "goldfish")
    }
}
