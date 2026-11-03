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

import androidx.fragment.app.FragmentActivity
import com.circle.daa.sdk.internal.authkey.AuthKeyWireFixture
import com.circle.daa.sdk.internal.authkey.Base64Url
import com.circle.daa.sdk.internal.authkey.P256PublicKeyEncoding
import com.circle.daa.sdk.internal.authkey.TestP256Jwk
import com.circle.daa.sdk.internal.securekey.AuthKeyBackend
import com.circle.daa.sdk.internal.securekey.AuthKeyProtectionMode
import com.circle.daa.sdk.internal.securekey.AuthKeyRegisteredKey
import com.circle.daa.sdk.internal.securekey.AuthKeyRegistrationRecord
import com.circle.daa.sdk.internal.securekey.AuthKeyState
import com.circle.daa.sdk.internal.securekey.requireValidSigningInputAtSignatureTime
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Mockito.mock
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.spec.ECGenParameterSpec
import java.time.Instant
import java.util.UUID

class DaaSecureKeyTest {
    @Test
    fun `namespaces aliases by app environment and installation`() {
        val first = identity(DaaEnvironment.Sandbox)
        val second = first.copy(environment = DaaEnvironment.Production)
        val third = first.copy(installationId = UUID.randomUUID())
        assertNotEquals(first.alias, second.alias)
        assertNotEquals(first.alias, third.alias)
    }

    @Test
    fun `redacts identity values and keystore alias from string output`() {
        val identity = identity(DaaEnvironment.Sandbox)

        assertFalse(identity.toString().contains(identity.appId))
        assertFalse(identity.toString().contains(identity.installationId.toString()))
        assertFalse(identity.toString().contains(identity.alias))
    }

    @Test
    fun `serializes resolution and retries after failure`() =
        runBlocking {
            val resolutionGate = CompletableDeferred<Unit>()
            val backend = FakeBackend(failures = 1, resolutionGate = resolutionGate)
            val key = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)
            assertThrows(DaaSecureKeyException::class.java) { runBlocking { key.resolveOrCreate() } }
            val values = List(3) { async(start = CoroutineStart.UNDISPATCHED) { key.resolveOrCreate() } }
            try {
                assertEquals(2, backend.resolveCount)
            } finally {
                resolutionGate.complete(Unit)
            }
            assertEquals(
                listOf(DaaAuthKeyResolution.Created, DaaAuthKeyResolution.Created, DaaAuthKeyResolution.Created),
                values.awaitAll(),
            )
            assertEquals(4, backend.resolveCount)
        }

    @Test
    fun `preserves existing resolution and stable backend errors`() =
        runBlocking {
            val existing =
                DaaSecureKey(
                    identity(DaaEnvironment.Sandbox),
                    AuthKeyProtectionMode.UserPresence,
                    FakeBackend(resolution = DaaAuthKeyResolution.Existing),
                )
            assertEquals(DaaAuthKeyResolution.Existing, existing.resolveOrCreate())

            val failure = DaaSecureKeyException(DaaSecureKeyError.UserCancelled)
            val failing =
                DaaSecureKey(
                    identity(DaaEnvironment.Sandbox),
                    AuthKeyProtectionMode.UserPresence,
                    FakeBackend(signingFailure = failure),
                )
            failing.resolveOrCreate()
            failing.acknowledgeRegistration()
            val thrown =
                assertThrows(DaaSecureKeyException::class.java) {
                    runBlocking {
                        failing.signDeviceAuthorization(
                            DaaDeviceAuthorizationSigningInput(validInput()),
                            mock(FragmentActivity::class.java),
                        )
                    }
                }
            assertSame(failure, thrown)
        }

    @Test
    fun `requires resolution before export and signing`() =
        runBlocking {
            val backend = FakeBackend()
            val key = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)

            val exportError = assertThrows(DaaSecureKeyException::class.java) { runBlocking { key.thumbprint() } }
            assertEquals(DaaSecureKeyError.ResolutionRequired, exportError.error)
            val spkiError =
                assertThrows(DaaSecureKeyException::class.java) { runBlocking { key.publicKeySpkiBase64Url() } }
            assertEquals(DaaSecureKeyError.ResolutionRequired, spkiError.error)

            val signError =
                assertThrows(DaaSecureKeyException::class.java) {
                    runBlocking {
                        key.signDeviceAuthorization(
                            DaaDeviceAuthorizationSigningInput(validInput()),
                            mock(FragmentActivity::class.java),
                        )
                    }
                }
            assertEquals(DaaSecureKeyError.ResolutionRequired, signError.error)
            assertEquals(0, backend.resolveCount)
            assertEquals(0, backend.signCount)
        }

    @Test
    fun `signs every operation for an acknowledged key without repeating resolution`() =
        runBlocking {
            val backend = FakeBackend()
            val enrolling = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)
            val activity = mock(FragmentActivity::class.java)
            enrolling.resolveOrCreate()
            enrolling.acknowledgeRegistration()

            // A relaunched instance holds no in-memory resolution, so the durable
            // acknowledgement alone must let a returning user sign.
            val returning = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)
            returning.signDeviceAuthorization(DaaDeviceAuthorizationSigningInput(validInput()), activity)
            returning.signDeviceAuthorization(DaaDeviceAuthorizationSigningInput(contextInput()), activity)
            // The acknowledgement observed while signing answers this resolution from
            // the cache, so an enrolled installation never re-enters key creation.
            assertEquals(DaaAuthKeyResolution.Existing, returning.resolveOrCreate())
            returning.signDeviceAuthorization(DaaDeviceAuthorizationSigningInput(contextInput()), activity)

            assertEquals(3, backend.signCount)
            assertEquals(1, backend.resolveCount)
        }

    @Test
    fun `reads durable state once for repeated signatures by an acknowledged key`() =
        runBlocking {
            val backend = FakeBackend()
            val enrolling = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)
            val activity = mock(FragmentActivity::class.java)
            enrolling.resolveOrCreate()
            enrolling.acknowledgeRegistration()

            val returning = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)
            returning.signDeviceAuthorization(DaaDeviceAuthorizationSigningInput(validInput()), activity)
            returning.signDeviceAuthorization(DaaDeviceAuthorizationSigningInput(contextInput()), activity)

            // An acknowledgement is durable and nothing can undo it, so the second
            // signature answers from the cache instead of reading storage again.
            assertEquals(2, backend.signCount)
            assertEquals(1, backend.registrationStateCount)
        }

    @Test
    fun `a cached acknowledgement does not satisfy the export requirement`() =
        runBlocking {
            val backend = FakeBackend(spki = Base64Url.decode(AuthKeyWireFixture.load().p256PublicKey.spkiBase64Url)!!)
            val enrolling = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)
            val activity = mock(FragmentActivity::class.java)
            enrolling.resolveOrCreate()
            enrolling.acknowledgeRegistration()

            // Signing caches the acknowledgement it observed. That cache must not stand
            // in for the caller's own resolution, which the exporters still require.
            val returning = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)
            returning.signDeviceAuthorization(DaaDeviceAuthorizationSigningInput(validInput()), activity)
            val spkiError =
                assertThrows(DaaSecureKeyException::class.java) { runBlocking { returning.publicKeySpkiBase64Url() } }
            val thumbprintError =
                assertThrows(DaaSecureKeyException::class.java) { runBlocking { returning.thumbprint() } }

            assertEquals(DaaSecureKeyError.ResolutionRequired, spkiError.error)
            assertEquals(DaaSecureKeyError.ResolutionRequired, thumbprintError.error)
            // Exactly one separate key read: `enrolling`'s acknowledgeRegistration() re-verifies its
            // cached binding via requireResolved(). resolveOrCreate() and `returning`'s
            // observed-acknowledgement transition record the key material their own backend read
            // returned instead of reading it a second time. None of these is the caller's own
            // resolution, which `returning` never performed -- the exporters above still demand it.
            assertEquals(1, backend.publicKeySpkiCount)
            assertEquals(1, backend.resolveCount)
        }

    @Test
    fun `a pending key stays blocked however often signing is attempted`() =
        runBlocking {
            val backend = FakeBackend()
            val key = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)
            val activity = mock(FragmentActivity::class.java)

            // Reading `Created` must leave no cached state that a second attempt could
            // mistake for the caller's explicit resolution.
            repeat(2) {
                val error =
                    assertThrows(DaaSecureKeyException::class.java) {
                        runBlocking {
                            key.signDeviceAuthorization(DaaDeviceAuthorizationSigningInput(validInput()), activity)
                        }
                    }
                assertEquals(DaaSecureKeyError.ResolutionRequired, error.error)
            }

            assertEquals(0, backend.signCount)
            assertEquals(0, backend.resolveCount)
            assertEquals(2, backend.registrationStateCount)
        }

    @Test
    fun `signs login completion for a pending key only after explicit resolution`() =
        runBlocking {
            val backend = FakeBackend()
            val activity = mock(FragmentActivity::class.java)
            val unresolved = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)

            val error =
                assertThrows(DaaSecureKeyException::class.java) {
                    runBlocking {
                        unresolved.signDeviceAuthorization(DaaDeviceAuthorizationSigningInput(validInput()), activity)
                    }
                }
            assertEquals(DaaSecureKeyError.ResolutionRequired, error.error)
            val contextError =
                assertThrows(DaaSecureKeyException::class.java) {
                    runBlocking {
                        unresolved.signDeviceAuthorization(DaaDeviceAuthorizationSigningInput(contextInput()), activity)
                    }
                }
            assertEquals(DaaSecureKeyError.ResolutionRequired, contextError.error)
            assertEquals(0, backend.resolveCount)
            assertEquals(0, backend.signCount)

            val resolved = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)
            assertEquals(DaaAuthKeyResolution.Created, resolved.resolveOrCreate())
            resolved.signDeviceAuthorization(DaaDeviceAuthorizationSigningInput(validInput()), activity)

            assertEquals(1, backend.signCount)
            assertEquals(0, backend.acknowledgeCount)
        }

    @Test
    fun `reports resolution required without minting a key when none exists`() =
        runBlocking {
            val absent = DaaSecureKeyException(DaaSecureKeyError.KeyNotFound)
            val backend = FakeBackend(registrationStateFailure = absent)
            val key = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)
            val activity = mock(FragmentActivity::class.java)

            listOf(validInput(), contextInput()).forEach { input ->
                val error =
                    assertThrows(DaaSecureKeyException::class.java) {
                        runBlocking {
                            key.signDeviceAuthorization(DaaDeviceAuthorizationSigningInput(input), activity)
                        }
                    }
                assertEquals(DaaSecureKeyError.ResolutionRequired, error.error)
                assertSame(absent, error.cause)
            }

            assertEquals(0, backend.resolveCount)
            assertEquals(0, backend.signCount)
        }

    @Test
    fun `reports a key wiped after explicit resolution as not found`() =
        runBlocking {
            val backend = FakeBackend()
            val key = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)
            val activity = mock(FragmentActivity::class.java)
            assertEquals(DaaAuthKeyResolution.Created, key.resolveOrCreate())

            // A passcode reset or a cleared keystore removes the alias mid-session. The
            // caller resolved on purpose, so report the wiped credential instead of
            // inviting another resolution, which would mint an unknown key.
            val wiped = DaaSecureKeyException(DaaSecureKeyError.KeyNotFound)
            backend.registrationStateFailure = wiped
            val error =
                assertThrows(DaaSecureKeyException::class.java) {
                    runBlocking {
                        key.signDeviceAuthorization(DaaDeviceAuthorizationSigningInput(validInput()), activity)
                    }
                }

            assertSame(wiped, error)
            assertEquals(1, backend.resolveCount)
            assertEquals(0, backend.signCount)
        }

    @Test
    fun `acknowledging with identifiers overwrites the identifiers of an already acknowledged key`() =
        runBlocking {
            val backend = FakeBackend()
            val key = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)
            key.resolveOrCreate()
            key.acknowledgeRegistration(AUTH_KEY_ID, OWNER_BINDING_ID)

            // A later registration of the same key under new identifiers must replace the stored
            // ones, even though this instance already holds an acknowledgement.
            key.acknowledgeRegistration(OTHER_AUTH_KEY_ID, OTHER_OWNER_BINDING_ID)

            assertEquals(2, backend.recordCount)
            val relaunched =
                DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)
            val restored = relaunched.resolveExisting()
            assertEquals(OTHER_AUTH_KEY_ID, restored?.authKeyId)
            assertEquals(OTHER_OWNER_BINDING_ID, restored?.ownerBindingId)
        }

    @Test
    fun `acknowledging with identifiers upgrades a legacy acknowledgement`() =
        runBlocking {
            val backend = FakeBackend()
            val key = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)
            key.resolveOrCreate()
            key.acknowledgeRegistration()
            assertNull(key.resolveExisting())

            key.acknowledgeRegistration(AUTH_KEY_ID, OWNER_BINDING_ID)

            assertEquals(1, backend.acknowledgeCount)
            assertEquals(1, backend.recordCount)
            assertEquals(AUTH_KEY_ID, key.resolveExisting()?.authKeyId)
        }

    @Test
    fun `records the time the acknowledgement was written`() =
        runBlocking {
            val backend = FakeBackend()
            val key = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)
            key.resolveOrCreate()

            val before = System.currentTimeMillis()
            key.acknowledgeRegistration(AUTH_KEY_ID, OWNER_BINDING_ID)
            val after = System.currentTimeMillis()

            val registeredAt = key.resolveExisting()!!.registeredAtEpochMillis
            assertTrue(registeredAt in before..after)
        }

    @Test
    fun `a legacy acknowledgement restores nothing but still resolves as existing`() =
        runBlocking {
            val backend = FakeBackend()
            val enrolling = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)
            enrolling.resolveOrCreate()
            enrolling.acknowledgeRegistration()

            val relaunched =
                DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)
            assertNull(relaunched.resolveExisting())
            // A null lookup is not a resolution.
            val error = assertThrows(DaaSecureKeyException::class.java) { runBlocking { relaunched.thumbprint() } }
            assertEquals(DaaSecureKeyError.ResolutionRequired, error.error)
            assertEquals(DaaAuthKeyResolution.Existing, relaunched.resolveOrCreate())
        }

    @Test
    fun `reports no registration when the stored acknowledgement does not verify`() =
        runBlocking {
            // The backend reports an acknowledgement it cannot read, or one bound to another key,
            // as no registration; the metadata tests pin which markers those are.
            val backend = FakeBackend(resolution = DaaAuthKeyResolution.Existing)
            val key = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)

            assertNull(key.resolveExisting())
            val error = assertThrows(DaaSecureKeyException::class.java) { runBlocking { key.thumbprint() } }
            assertEquals(DaaSecureKeyError.ResolutionRequired, error.error)
        }

    @Test
    fun `resolveExisting never creates a key`() =
        runBlocking {
            val backend = FakeBackend(keyPresent = false)
            val key = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)

            assertNull(key.resolveExisting())
            assertNull(key.resolveExisting())

            assertFalse(backend.keyPresent)
            assertEquals(0, backend.resolveCount)
            assertEquals(0, backend.mintCount)
            assertEquals(0, backend.signCount)
            val error =
                assertThrows(DaaSecureKeyException::class.java) { runBlocking { key.publicKeySpkiBase64Url() } }
            assertEquals(DaaSecureKeyError.ResolutionRequired, error.error)
        }

    @Test
    fun `a restored registration enables export and signing without resolveOrCreate`() =
        runBlocking {
            val spki = Base64Url.decode(AuthKeyWireFixture.load().p256PublicKey.spkiBase64Url)!!
            val backend = FakeBackend(spki = spki)
            val enrolling = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)
            enrolling.resolveOrCreate()
            enrolling.acknowledgeRegistration(AUTH_KEY_ID, OWNER_BINDING_ID)

            val relaunched =
                DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)
            val restored = relaunched.resolveExisting()

            assertEquals(
                DaaRegisteredAuthKey(AUTH_KEY_ID, OWNER_BINDING_ID, backend.record!!.registeredAtEpochMillis),
                restored,
            )
            assertEquals(Base64Url.encode(spki), relaunched.publicKeySpkiBase64Url())
            assertEquals(P256PublicKeyEncoding.jwkThumbprint(spki), relaunched.thumbprint())
            relaunched.signDeviceAuthorization(
                DaaDeviceAuthorizationSigningInput(validInput()),
                mock(FragmentActivity::class.java),
            )
            assertEquals(1, backend.signCount)
            assertEquals(1, backend.resolveCount, "only the enrolling instance resolved")
        }

    @Test
    fun `resolveExisting never caches a key re-minted after the registration was verified`() =
        runBlocking {
            val original = Base64Url.decode(AuthKeyWireFixture.load().p256PublicKey.spkiBase64Url)!!
            val backend = FakeBackend(spki = original)
            val enrolling = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)
            enrolling.resolveOrCreate()
            enrolling.acknowledgeRegistration(AUTH_KEY_ID, OWNER_BINDING_ID)
            val remintedSpki =
                KeyPairGenerator.getInstance("EC").run {
                    initialize(ECGenParameterSpec("secp256r1"))
                    generateKeyPair().public.encoded
                }
            // Another live instance replaces the key, unacknowledged, right after the lookup verified
            // the recorded registration against the original key.
            backend.afterRegisteredAuthKey = {
                backend.afterRegisteredAuthKey = null
                backend.spki = remintedSpki
                backend.record = null
                backend.registrationStateFailure = null
            }
            val relaunched =
                DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)

            assertEquals(AUTH_KEY_ID, relaunched.resolveExisting()?.authKeyId)
            // The fake still reports the identity as acknowledged; only the key material changed. The
            // cached resolution names the original key, so it must not vouch for the re-minted one.
            backend.registrationStateFailure = DaaSecureKeyException(DaaSecureKeyError.KeyMetadataUnavailable)

            val exportError =
                assertThrows(DaaSecureKeyException::class.java) { runBlocking { relaunched.thumbprint() } }
            assertEquals(DaaSecureKeyError.ResolutionRequired, exportError.error)
            val signError =
                assertThrows(DaaSecureKeyException::class.java) {
                    runBlocking {
                        relaunched.signDeviceAuthorization(
                            DaaDeviceAuthorizationSigningInput(contextInput()),
                            mock(FragmentActivity::class.java),
                        )
                    }
                }
            assertEquals(DaaSecureKeyError.KeyMetadataUnavailable, signError.error)
            assertEquals(0, backend.signCount)
        }

    @Test
    fun `acknowledgement is checked and written before another instance can replace the key`() =
        runBlocking {
            val original = Base64Url.decode(AuthKeyWireFixture.load().p256PublicKey.spkiBase64Url)!!
            val backend = FakeBackend(spki = original)
            val enrolling = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)
            val other = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)
            enrolling.resolveOrCreate()
            val reached = CompletableDeferred<Unit>()
            val release = CompletableDeferred<Unit>()
            // Suspend the acknowledgement right after it read the key it is about to acknowledge.
            backend.pauseNextPublicKeySpki = reached to release

            val acknowledgement = async { enrolling.acknowledgeRegistration(AUTH_KEY_ID, OWNER_BINDING_ID) }
            withTimeout(1_000) { reached.await() }
            backend.replaceOnNextResolve = true
            val reset = launch { other.resolveOrCreate() }
            // Give the second instance every chance to run: it must not reach the backend while the
            // acknowledgement's check is still pending its write.
            repeat(20) { delay(1) }
            assertEquals(0, backend.replaceCount)
            assertEquals(0, backend.recordCount)

            release.complete(Unit)
            withTimeout(1_000) {
                acknowledgement.await()
                reset.join()
            }

            // The acknowledgement landed on the key it checked, and was then replaced with it. The
            // new key carries no registration, least of all the old one's identifiers.
            assertEquals(1, backend.recordCount)
            assertEquals(1, backend.replaceCount)
            assertEquals(1, backend.mintCount)
            assertNull(backend.record)
            val relaunched =
                DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)
            assertNull(relaunched.resolveExisting())
            assertEquals(DaaAuthKeyResolution.Created, relaunched.resolveOrCreate())
        }

    @Test
    fun `acknowledgement after another instance re-created the key fails closed without writing`() =
        runBlocking {
            val original = Base64Url.decode(AuthKeyWireFixture.load().p256PublicKey.spkiBase64Url)!!
            val backend = FakeBackend(spki = original)
            val enrolling = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)
            val other = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)
            enrolling.resolveOrCreate()
            backend.replaceOnNextResolve = true
            other.resolveOrCreate()

            listOf<suspend () -> Unit>(
                { enrolling.acknowledgeRegistration(AUTH_KEY_ID, OWNER_BINDING_ID) },
                { enrolling.acknowledgeRegistration() },
            ).forEach { acknowledge ->
                val error = assertThrows(DaaSecureKeyException::class.java) { runBlocking { acknowledge() } }
                assertEquals(DaaSecureKeyError.ResolutionRequired, error.error)
            }
            assertEquals(0, backend.recordCount)
            assertEquals(0, backend.acknowledgeCount)
            assertNull(backend.record)
        }

    @Test
    fun `the backend refuses an acknowledgement for a key replaced outside the process lock`() =
        runBlocking {
            val original = Base64Url.decode(AuthKeyWireFixture.load().p256PublicKey.spkiBase64Url)!!
            val backend = FakeBackend(spki = original)
            val key = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)
            key.resolveOrCreate()
            // Another process re-mints the key between this instance's check and the backend write.
            backend.beforeRegistrationWrite = {
                backend.beforeRegistrationWrite = null
                backend.spki =
                    KeyPairGenerator.getInstance("EC").run {
                        initialize(ECGenParameterSpec("secp256r1"))
                        generateKeyPair().public.encoded
                    }
            }

            val error =
                assertThrows(DaaSecureKeyException::class.java) {
                    runBlocking { key.acknowledgeRegistration(AUTH_KEY_ID, OWNER_BINDING_ID) }
                }

            assertEquals(DaaSecureKeyError.ResolutionRequired, error.error)
            assertNull(backend.record)
            assertEquals(DaaAuthKeyResolution.Created, key.resolveOrCreate())
        }

    private fun freshSpki(): ByteArray =
        KeyPairGenerator.getInstance("EC").run {
            initialize(ECGenParameterSpec("secp256r1"))
            generateKeyPair().public.encoded
        }

    @Test
    fun `signs only with the key the signing gate authorized`() =
        runBlocking {
            val original = Base64Url.decode(AuthKeyWireFixture.load().p256PublicKey.spkiBase64Url)!!
            val backend = FakeBackend(spki = original)
            val enrolling = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)
            enrolling.resolveOrCreate()
            enrolling.acknowledgeRegistration(AUTH_KEY_ID, OWNER_BINDING_ID)
            val relaunched =
                DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)
            // The gate authorizes the acknowledged key; then, before the backend signs, another instance
            // or process replaces it with an unregistered key under the same alias.
            backend.beforeSign = {
                backend.beforeSign = null
                backend.spki = freshSpki()
                backend.record = null
            }

            val error =
                assertThrows(DaaSecureKeyException::class.java) {
                    runBlocking {
                        relaunched.signDeviceAuthorization(
                            DaaDeviceAuthorizationSigningInput(validInput()),
                            mock(FragmentActivity::class.java),
                        )
                    }
                }

            assertEquals(DaaSecureKeyError.ResolutionRequired, error.error)
            assertEquals(0, backend.signCount)
            assertNull(backend.signedMessage)
            assertArrayEquals(original, backend.signedWith.single())
        }

    @Test
    fun `registration device authorization signs only with the key the signing gate authorized`() =
        runBlocking {
            val original = Base64Url.decode(AuthKeyWireFixture.load().p256PublicKey.spkiBase64Url)!!
            val backend = FakeBackend(spki = original)
            val key = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)
            assertEquals(DaaAuthKeyResolution.Created, key.resolveOrCreate())
            backend.beforeSign = {
                backend.beforeSign = null
                backend.spki = freshSpki()
            }

            val error =
                assertThrows(DaaSecureKeyException::class.java) {
                    runBlocking {
                        key.signRegistrationDeviceAuthorization(
                            DaaRegistrationAuthorizationSigningInput(registrationInput()),
                            mock(FragmentActivity::class.java),
                        )
                    }
                }

            assertEquals(DaaSecureKeyError.ResolutionRequired, error.error)
            assertEquals(0, backend.signCount)
            assertArrayEquals(original, backend.signedWith.single())
        }

    @Test
    fun `caches the key a durable acknowledgement was read for, not a second read`() =
        runBlocking {
            val original = Base64Url.decode(AuthKeyWireFixture.load().p256PublicKey.spkiBase64Url)!!
            val backend = FakeBackend(spki = original)
            val enrolling = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)
            enrolling.resolveOrCreate()
            enrolling.acknowledgeRegistration(AUTH_KEY_ID, OWNER_BINDING_ID)
            val relaunched =
                DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)
            // The durable read reports the original key acknowledged; right after it, the key is
            // re-created, unregistered, so any second read would name the new key.
            backend.afterRegistrationState = {
                backend.afterRegistrationState = null
                backend.spki = freshSpki()
                backend.record = null
            }

            val error =
                assertThrows(DaaSecureKeyException::class.java) {
                    runBlocking {
                        relaunched.signDeviceAuthorization(
                            DaaDeviceAuthorizationSigningInput(validInput()),
                            mock(FragmentActivity::class.java),
                        )
                    }
                }

            // The acknowledgement authorized the original key only, so the re-created key is never
            // signed with on the strength of it.
            assertEquals(DaaSecureKeyError.ResolutionRequired, error.error)
            assertEquals(0, backend.signCount)
            assertArrayEquals(original, backend.signedWith.single())
        }

    @Test
    fun `resolution caches the key the backend resolved, not a second read`() =
        runBlocking {
            val original = Base64Url.decode(AuthKeyWireFixture.load().p256PublicKey.spkiBase64Url)!!
            val swapped = freshSpki()
            val resolvedFor = mutableListOf<ByteArray>()
            val fake = FakeBackend(spki = original)
            val backend =
                object : AuthKeyBackend by fake {
                    override suspend fun resolveOrCreate(
                        identity: DaaAuthKeyIdentity,
                        protection: AuthKeyProtectionMode,
                    ): AuthKeyState =
                        fake.resolveOrCreate(identity, protection).also {
                            resolvedFor.add(it.publicKeySpki)
                            // Re-created right after the backend resolved the original key.
                            fake.spki = swapped
                        }
                }
            val key = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)

            assertEquals(DaaAuthKeyResolution.Created, key.resolveOrCreate())

            assertArrayEquals(original, resolvedFor.single())
            // The cached resolution names the original key, so it no longer matches what the alias
            // holds and stands in for nothing.
            val error = assertThrows(DaaSecureKeyException::class.java) { runBlocking { key.thumbprint() } }
            assertEquals(DaaSecureKeyError.ResolutionRequired, error.error)
        }

    @Test
    fun `an old handle never exports a key re-created after its resolution was verified`() =
        runBlocking {
            val original = Base64Url.decode(AuthKeyWireFixture.load().p256PublicKey.spkiBase64Url)!!
            val backend = FakeBackend(spki = original)
            val old = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)
            val other = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)
            old.resolveOrCreate()

            listOf<suspend () -> String>(
                { old.publicKeySpkiBase64Url() },
                { old.thumbprint() },
            ).forEachIndexed { index, export ->
                val exported = backend.spki.copyOf()
                val reached = CompletableDeferred<Unit>()
                val release = CompletableDeferred<Unit>()
                // Pause the export's verification read right after it captured the current key.
                backend.pauseNextPublicKeySpki = reached to release
                val result = async { export() }
                withTimeout(1_000) { reached.await() }

                // Another handle replaces the key with a new one under the same alias.
                backend.replaceOnNextResolve = true
                other.resolveOrCreate()
                val replacement = backend.spki.copyOf()
                assertFalse(exported.contentEquals(replacement))

                release.complete(Unit)
                val value = withTimeout(1_000) { result.await() }

                // The export names the key it verified, never the replacement.
                val expected =
                    if (index == 0) Base64Url.encode(exported) else P256PublicKeyEncoding.jwkThumbprint(exported)
                val replaced =
                    if (index == 0) Base64Url.encode(replacement) else P256PublicKeyEncoding.jwkThumbprint(replacement)
                assertEquals(expected, value)
                assertNotEquals(replaced, value)

                // The old handle's resolution no longer matches the alias, so the next export fails.
                val error =
                    assertThrows(DaaSecureKeyException::class.java) { runBlocking { old.publicKeySpkiBase64Url() } }
                assertEquals(DaaSecureKeyError.ResolutionRequired, error.error)
                // Re-resolve the old handle for the next variant.
                old.resolveOrCreate()
            }
        }

    @Test
    fun `an instance adopts a key another instance re-created and acknowledged only by signing with it`() =
        runBlocking {
            val original = Base64Url.decode(AuthKeyWireFixture.load().p256PublicKey.spkiBase64Url)!!
            val backend = FakeBackend(spki = original)
            val first = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)
            val second = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)
            first.resolveOrCreate()
            backend.replaceOnNextResolve = true
            second.resolveOrCreate()
            second.acknowledgeRegistration(AUTH_KEY_ID, OWNER_BINDING_ID)
            val replacement = backend.spki.copyOf()

            // Nothing has re-verified the first instance's cache, so it exports nothing.
            val error = assertThrows(DaaSecureKeyException::class.java) { runBlocking { first.thumbprint() } }
            assertEquals(DaaSecureKeyError.ResolutionRequired, error.error)

            // Signing reads the durable acknowledgement, which names the replacement, and signs with it.
            first.signDeviceAuthorization(
                DaaDeviceAuthorizationSigningInput(validInput()),
                mock(FragmentActivity::class.java),
            )
            assertArrayEquals(replacement, backend.signedWith.single())
            assertEquals(P256PublicKeyEncoding.jwkThumbprint(replacement), first.thumbprint())
        }

    @Test
    fun `resolveExisting fails closed when the existing key does not validate`() =
        runBlocking {
            val failure = DaaSecureKeyException(DaaSecureKeyError.SecureHardwareUnavailable)
            val backend = FakeBackend(registeredAuthKeyFailure = failure)
            val key = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)

            val thrown = assertThrows(DaaSecureKeyException::class.java) { runBlocking { key.resolveExisting() } }

            assertSame(failure, thrown)
            val error = assertThrows(DaaSecureKeyException::class.java) { runBlocking { key.thumbprint() } }
            assertEquals(DaaSecureKeyError.ResolutionRequired, error.error)
        }

    @Test
    fun `rejects registration identifiers that are not UUIDs before touching storage`() =
        runBlocking {
            val backend = FakeBackend()
            val key = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)
            key.resolveOrCreate()
            val invalid =
                listOf(
                    "",
                    "not-a-uuid",
                    "0f6a3c1e8b2d4e5f9a7b1c2d3e4f5a6b",
                    "{$AUTH_KEY_ID}",
                    "$AUTH_KEY_ID ",
                    "$AUTH_KEY_ID:x",
                )

            invalid.forEach { value ->
                listOf(value to OWNER_BINDING_ID, AUTH_KEY_ID to value).forEach { (authKeyId, ownerBindingId) ->
                    val error =
                        assertThrows(DaaSecureKeyException::class.java) {
                            runBlocking { key.acknowledgeRegistration(authKeyId, ownerBindingId) }
                        }
                    assertEquals(DaaSecureKeyError.InvalidSigningInput, error.error)
                }
            }
            assertEquals(0, backend.recordCount)
            assertEquals(DaaAuthKeyResolution.Created, key.resolveOrCreate())
        }

    @Test
    fun `requires resolution before acknowledging with identifiers`() =
        runBlocking {
            val backend = FakeBackend()
            val key = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)

            val error =
                assertThrows(DaaSecureKeyException::class.java) {
                    runBlocking { key.acknowledgeRegistration(AUTH_KEY_ID, OWNER_BINDING_ID) }
                }

            assertEquals(DaaSecureKeyError.ResolutionRequired, error.error)
            assertEquals(0, backend.recordCount)
        }

    @Test
    fun `requires resolution before registration acknowledgement`() =
        runBlocking {
            val backend = FakeBackend()
            val key = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)

            val error =
                assertThrows(DaaSecureKeyException::class.java) {
                    runBlocking { key.acknowledgeRegistration() }
                }

            assertEquals(DaaSecureKeyError.ResolutionRequired, error.error)
            assertEquals(0, backend.resolveCount)
            assertEquals(0, backend.acknowledgeCount)
        }

    @Test
    fun `maps malformed public key material to the stable public error`() =
        runBlocking {
            val key =
                DaaSecureKey(
                    identity(DaaEnvironment.Sandbox),
                    AuthKeyProtectionMode.UserPresence,
                    FakeBackend(spki = ByteArray(91)),
                )
            key.resolveOrCreate()

            val error = assertThrows(DaaSecureKeyException::class.java) { runBlocking { key.publicKeySpkiBase64Url() } }

            assertEquals(DaaSecureKeyError.PublicKeyUnavailable, error.error)
        }

    @Test
    fun `uses shared SPKI and thumbprint vectors`() =
        runBlocking {
            val fixture = AuthKeyWireFixture.load()
            val backend = FakeBackend(spki = Base64Url.decode(fixture.p256PublicKey.spkiBase64Url)!!)
            val key = DaaSecureKey(identity(DaaEnvironment.Production), AuthKeyProtectionMode.UserPresence, backend)
            key.resolveOrCreate()
            assertEquals(fixture.p256PublicKey.spkiBase64Url, key.publicKeySpkiBase64Url())
            assertEquals(fixture.p256PublicKey.jwkThumbprint, key.thumbprint())
        }

    @Test
    fun `signs the exact validated bytes and converts DER to JOSE`() =
        runBlocking {
            val fixture = AuthKeyWireFixture.load()
            val backend = FakeBackend(signature = fixture.signedMessage.derHex.hex(), mutateSigningBytes = true)
            val key = DaaSecureKey(identity(DaaEnvironment.Production), AuthKeyProtectionMode.UserPresence, backend)
            val bytes = validInput()
            val input = DaaDeviceAuthorizationSigningInput(bytes)
            key.resolveOrCreate()
            key.acknowledgeRegistration()
            val result =
                key.signDeviceAuthorization(
                    input,
                    mock(FragmentActivity::class.java),
                )
            assertEquals(fixture.signedMessage.rawHex, result.hexString())
            assertEquals(bytes.toList(), backend.signedMessage?.toList())
            assertEquals("complete_social_login", backend.signedOperation)
            assertArrayEquals(bytes, input.signingBytes())
        }

    @Test
    fun `signs a device authorization whose kid is the server-assigned AuthKey id, not the key thumbprint`() =
        runBlocking {
            val fixture = AuthKeyWireFixture.load()
            val backend =
                FakeBackend(
                    spki = Base64Url.decode(fixture.p256PublicKey.spkiBase64Url)!!,
                    signature = fixture.signedMessage.derHex.hex(),
                )
            val key = DaaSecureKey(identity(DaaEnvironment.Production), AuthKeyProtectionMode.UserPresence, backend)
            key.resolveOrCreate()
            key.acknowledgeRegistration()
            assertNotEquals(key.thumbprint(), serverAuthKeyId)
            val result =
                key.signDeviceAuthorization(
                    DaaDeviceAuthorizationSigningInput(validInput()),
                    mock(FragmentActivity::class.java),
                )
            assertEquals(fixture.signedMessage.rawHex, result.hexString())
        }

    @Test
    fun `serializes concurrent signing calls on one key instance`() =
        runBlocking {
            val signingGate = CompletableDeferred<Unit>()
            val backend = FakeBackend(signingGate = signingGate)
            val key = DaaSecureKey(identity(DaaEnvironment.Production), AuthKeyProtectionMode.UserPresence, backend)
            val activity = mock(FragmentActivity::class.java)
            key.resolveOrCreate()
            key.acknowledgeRegistration()
            val first =
                async { key.signDeviceAuthorization(DaaDeviceAuthorizationSigningInput(validInput()), activity) }
            withTimeout(1_000) {
                while (backend.signCount == 0) delay(1)
            }
            val second =
                async(start = CoroutineStart.UNDISPATCHED) {
                    key.signDeviceAuthorization(DaaDeviceAuthorizationSigningInput(validInput()), activity)
                }

            try {
                assertEquals(1, backend.signCount)
            } finally {
                signingGate.complete(Unit)
            }
            awaitAll(first, second)

            assertEquals(2, backend.signCount)
            assertEquals(1, backend.maxConcurrentSigns)
        }

    @Test
    fun `cancelling a queued signing call prevents a second backend operation`() =
        runBlocking {
            val signingGate = CompletableDeferred<Unit>()
            val backend = FakeBackend(signingGate = signingGate)
            val key = DaaSecureKey(identity(DaaEnvironment.Production), AuthKeyProtectionMode.UserPresence, backend)
            val activity = mock(FragmentActivity::class.java)
            key.resolveOrCreate()
            key.acknowledgeRegistration()
            val first =
                async { key.signDeviceAuthorization(DaaDeviceAuthorizationSigningInput(validInput()), activity) }
            withTimeout(1_000) {
                while (backend.signCount == 0) delay(1)
            }
            val queued =
                launch(start = CoroutineStart.UNDISPATCHED) {
                    key.signDeviceAuthorization(DaaDeviceAuthorizationSigningInput(validInput()), activity)
                }

            try {
                queued.cancelAndJoin()
            } finally {
                signingGate.complete(Unit)
            }
            first.await()

            assertEquals(1, backend.signCount)
            key.signDeviceAuthorization(DaaDeviceAuthorizationSigningInput(validInput()), activity)
            assertEquals(2, backend.signCount)
        }

    private fun identity(environment: DaaEnvironment) =
        DaaAuthKeyIdentity(
            "mobile-app",
            environment,
            UUID.fromString("01234567-89ab-cdef-0123-456789abcdef"),
        )

    /**
     * The header `kid` the service assigns at Device Registration Complete (`DeviceContext.authKeyId`, a
     * UUID). It is a lookup key, not the AuthKey's RFC 7638 thumbprint, so the fixtures use one.
     */
    private val serverAuthKeyId = "3f6c2a9e-8b1d-4e7a-9c55-0d2b7e4f1a63"

    private fun validInput(): ByteArray {
        val header = """{"alg":"ES256","kid":"$serverAuthKeyId","typ":"aw-device-authorization+jws"}"""
        val digest = Base64Url.encode(ByteArray(32))
        val iat = Instant.now().epochSecond - 60
        val payload =
            buildString {
                append(
                    """{"aud":"circle-digital-asset-accounts","body_sha256":"$digest",""",
                )
                append(
                    """"canonical_path":"/v1/accounts/auth/sessions",""",
                )
                append(""""discriminator":"complete_social_login","exp":${iat + 300},"iat":$iat,""")
                append("\"idempotency_key\":\"01234567-89ab-cdef-0123-456789abcdef\",")
                append("\"jti\":\"01234567-89ab-cdef-0123-456789abcdef\",\"method\":\"POST\",")
                append("\"schema_version\":1}")
            }
        return "${Base64Url.encode(header.toByteArray())}.${Base64Url.encode(payload.toByteArray())}".toByteArray()
    }

    /** A bodyless context authorization: valid, and never signable by a pending key. */
    private fun contextInput(): ByteArray {
        val header = """{"alg":"ES256","kid":"$serverAuthKeyId","typ":"aw-device-authorization+jws"}"""
        val digest = Base64Url.encode(MessageDigest.getInstance("SHA-256").digest(ByteArray(0)))
        val iat = Instant.now().epochSecond - 60
        val payload =
            buildString {
                append(
                    """{"aud":"circle-digital-asset-accounts","body_sha256":"$digest",""",
                )
                append(
                    """"canonical_path":"/v1/accounts/auth/context",""",
                )
                append(""""discriminator":"get_device_context","exp":${iat + 300},"iat":$iat,""")
                append("\"jti\":\"01234567-89ab-cdef-0123-456789abcdef\",\"method\":\"GET\",")
                append("\"schema_version\":1}")
            }
        return "${Base64Url.encode(header.toByteArray())}.${Base64Url.encode(payload.toByteArray())}".toByteArray()
    }

    private fun registerDeviceKeyInput(): ByteArray {
        val header = """{"alg":"ES256","kid":"$serverAuthKeyId","typ":"aw-device-authorization+jws"}"""
        val digest = Base64Url.encode(ByteArray(32))
        val iat = Instant.now().epochSecond - 60
        val payload =
            "{\"aud\":\"circle-digital-asset-accounts\",\"body_sha256\":\"$digest\"," +
                "\"canonical_path\":\"/v1/accounts/auth/deviceKeyRegistration\"," +
                "\"discriminator\":\"register_device_key\",\"exp\":${iat + 300},\"iat\":$iat," +
                "\"idempotency_key\":\"01234567-89ab-cdef-0123-456789abcdef\"," +
                "\"jti\":\"01234567-89ab-cdef-0123-456789abcdef\",\"method\":\"POST\"," +
                "\"schema_version\":1}"
        return "${Base64Url.encode(header.toByteArray())}.${Base64Url.encode(payload.toByteArray())}".toByteArray()
    }

    /** A sensitive (money-moving or account-creation) device-auth operation, valid and POST-with-idempotency shaped. */
    private fun operationInput(
        discriminator: String,
        path: String,
    ): ByteArray {
        val header = """{"alg":"ES256","kid":"$serverAuthKeyId","typ":"aw-device-authorization+jws"}"""
        val digest = Base64Url.encode(ByteArray(32))
        val iat = Instant.now().epochSecond - 60
        val payload =
            "{\"aud\":\"circle-digital-asset-accounts\",\"body_sha256\":\"$digest\"," +
                "\"canonical_path\":\"$path\"," +
                "\"discriminator\":\"$discriminator\",\"exp\":${iat + 300},\"iat\":$iat," +
                "\"idempotency_key\":\"01234567-89ab-cdef-0123-456789abcdef\"," +
                "\"jti\":\"01234567-89ab-cdef-0123-456789abcdef\",\"method\":\"POST\"," +
                "\"schema_version\":1}"
        return "${Base64Url.encode(header.toByteArray())}.${Base64Url.encode(payload.toByteArray())}".toByteArray()
    }

    private fun transferInput(): ByteArray = operationInput("transfer", "/v1/accounts/transfers")

    private fun withdrawalInput(): ByteArray = operationInput("withdrawal", "/v1/accounts/withdrawals")

    private fun createAccountInput(): ByteArray = operationInput("create_account", "/v1/accounts")

    private fun completeSocialLoginInput(): ByteArray =
        operationInput("complete_social_login", "/v1/accounts/auth/sessions")

    /**
     * A device-proof registration input: the ten request-binding claims only.
     * The header `jwk` defaults to the conformance fixture's key, which is the
     * key `FakeBackend(spki = fixture spki)` signs with. Callers that exercise
     * the signing-site `jwk` binding pass a different on-curve key's coordinates.
     */
    private fun registrationInput(
        jwkX: String = TestP256Jwk.X,
        jwkY: String = TestP256Jwk.Y,
    ): ByteArray {
        val digest = Base64Url.encode(ByteArray(32))
        val header =
            "{\"alg\":\"ES256\",\"typ\":\"daa-device-authorization+jws\"," +
                "\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"$jwkX\",\"y\":\"$jwkY\"}}"
        val iat = Instant.now().epochSecond - 60
        val payload =
            "{\"aud\":\"circle-digital-asset-accounts\"," +
                "\"body_sha256\":\"$digest\",\"canonical_path\":\"/v1/accounts/auth/deviceKeyRegistration\"," +
                "\"discriminator\":\"device_key_registration.v1\"," +
                "\"exp\":${iat + 300},\"iat\":$iat,\"idempotency_key\":\"01234567-89ab-cdef-0123-456789abcdef\"," +
                "\"jti\":\"fedcba98-7654-3210-fedc-ba9876543210\",\"method\":\"POST\"," +
                "\"schema_version\":1}"
        return "${Base64Url.encode(header.toByteArray())}.${Base64Url.encode(payload.toByteArray())}".toByteArray()
    }

    /** Header `jwk` coordinates of a freshly generated P-256 key that is not the fixture key. */
    private fun otherKeyJwk(): Pair<String, String> {
        val spki =
            KeyPairGenerator.getInstance("EC").run {
                initialize(ECGenParameterSpec("secp256r1"))
                generateKeyPair().public.encoded
            }
        val x963 = P256PublicKeyEncoding.x963Representation(spki)
        return Base64Url.encode(x963.copyOfRange(1, 33)) to Base64Url.encode(x963.copyOfRange(33, 65))
    }

    private fun registrationFlowInput(): ByteArray {
        val digest = Base64Url.encode(ByteArray(32))
        val jwkX = TestP256Jwk.X
        val jwkY = TestP256Jwk.Y
        val header =
            "{\"alg\":\"ES256\",\"typ\":\"daa-registration-flow-authorization+jws\"," +
                "\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"$jwkX\",\"y\":\"$jwkY\"}}"
        val iat = Instant.now().epochSecond - 60
        val payload =
            "{\"aud\":\"circle-digital-asset-accounts\",\"auth_key_thumbprint\":\"$digest\"," +
                "\"body_sha256\":\"$digest\",\"canonical_path\":\"/v1/accounts/auth/deviceKeyRegistration\"," +
                "\"code_verifier_sha256\":\"$digest\",\"discriminator\":\"device_key_registration.v1\"," +
                "\"exp\":${iat + 300},\"iat\":$iat,\"idempotency_key\":\"01234567-89ab-cdef-0123-456789abcdef\"," +
                "\"jti\":\"fedcba98-7654-3210-fedc-ba9876543210\",\"method\":\"POST\"," +
                "\"profile_id\":\"profile-1\"," +
                "\"registration_handle_sha256\":\"$digest\",\"schema_version\":1}"
        return "${Base64Url.encode(header.toByteArray())}.${Base64Url.encode(payload.toByteArray())}".toByteArray()
    }

    @Test
    fun `returns created until registration is acknowledged and rejects context signing`() =
        runBlocking {
            val backend = FakeBackend()
            val key = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)
            val activity = mock(FragmentActivity::class.java)

            assertEquals(DaaAuthKeyResolution.Created, key.resolveOrCreate())
            assertEquals(DaaAuthKeyResolution.Created, key.resolveOrCreate())
            val error =
                assertThrows(DaaSecureKeyException::class.java) {
                    runBlocking {
                        key.signDeviceAuthorization(DaaDeviceAuthorizationSigningInput(contextInput()), activity)
                    }
                }
            assertEquals(DaaSecureKeyError.AuthKeyRegistrationRequired, error.error)
            assertEquals(0, backend.signCount)
            assertEquals(2, backend.resolveCount)
            assertEquals(1, backend.registrationStateCount)

            key.acknowledgeRegistration()
            key.acknowledgeRegistration()
            assertEquals(2, backend.resolveCount)
            assertEquals(1, backend.acknowledgeCount)
            assertEquals(DaaAuthKeyResolution.Existing, key.resolveOrCreate())
            key.signDeviceAuthorization(DaaDeviceAuthorizationSigningInput(validInput()), activity)
            assertEquals(1, backend.signCount)
        }

    @Test
    fun `registration refresh failure preserves resolution and never resolves destructively`() =
        runBlocking {
            val failure = DaaSecureKeyException(DaaSecureKeyError.KeyMetadataUnavailable)
            val spki = Base64Url.decode(AuthKeyWireFixture.load().p256PublicKey.spkiBase64Url)!!
            val backend = FakeBackend(spki = spki, registrationStateFailure = failure)
            val key = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)
            val activity = mock(FragmentActivity::class.java)

            assertEquals(DaaAuthKeyResolution.Created, key.resolveOrCreate())
            val thrown =
                assertThrows(DaaSecureKeyException::class.java) {
                    runBlocking {
                        key.signDeviceAuthorization(DaaDeviceAuthorizationSigningInput(validInput()), activity)
                    }
                }

            assertSame(failure, thrown)
            assertEquals(Base64Url.encode(spki), key.publicKeySpkiBase64Url())
            assertEquals(1, backend.resolveCount)
            assertEquals(1, backend.registrationStateCount)
            assertEquals(0, backend.signCount)
        }

    @Test
    fun `resolve observes registration acknowledged by another key instance`() =
        runBlocking {
            val backend = FakeBackend()
            val first = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)
            val second = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)

            assertEquals(DaaAuthKeyResolution.Created, first.resolveOrCreate())
            assertEquals(DaaAuthKeyResolution.Created, second.resolveOrCreate())
            first.acknowledgeRegistration()

            assertEquals(DaaAuthKeyResolution.Existing, second.resolveOrCreate())
            assertEquals(3, backend.resolveCount)
        }

    @Test
    fun `refreshes registration acknowledged by another key instance before signing`() =
        runBlocking {
            val backend = FakeBackend()
            val first = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)
            val second = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)
            val activity = mock(FragmentActivity::class.java)

            assertEquals(DaaAuthKeyResolution.Created, first.resolveOrCreate())
            assertEquals(DaaAuthKeyResolution.Created, second.resolveOrCreate())
            first.acknowledgeRegistration()

            second.signDeviceAuthorization(DaaDeviceAuthorizationSigningInput(validInput()), activity)
            assertEquals(1, backend.signCount)
        }

    @Test
    fun `coalesces concurrent registration acknowledgements`() =
        runBlocking {
            val acknowledgementGate = CompletableDeferred<Unit>()
            val backend = FakeBackend(acknowledgementGate = acknowledgementGate)
            val key = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)
            key.resolveOrCreate()

            val acknowledgements = List(3) { async { key.acknowledgeRegistration() } }
            withTimeout(1_000) {
                while (backend.acknowledgeCount == 0) delay(1)
            }
            assertEquals(1, backend.acknowledgeCount)
            acknowledgementGate.complete(Unit)
            acknowledgements.awaitAll()

            assertEquals(1, backend.acknowledgeCount)
            assertEquals(DaaAuthKeyResolution.Existing, key.resolveOrCreate())
        }

    @Test
    fun `failed registration acknowledgement leaves signing blocked and can be retried`() =
        runBlocking {
            val backend = FakeBackend(acknowledgementFailures = 1)
            val key = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)
            val activity = mock(FragmentActivity::class.java)
            key.resolveOrCreate()

            val failure =
                assertThrows(DaaSecureKeyException::class.java) {
                    runBlocking { key.acknowledgeRegistration() }
                }
            assertEquals(DaaSecureKeyError.KeyMetadataUnavailable, failure.error)
            val signingFailure =
                assertThrows(DaaSecureKeyException::class.java) {
                    runBlocking {
                        key.signDeviceAuthorization(DaaDeviceAuthorizationSigningInput(contextInput()), activity)
                    }
                }
            assertEquals(DaaSecureKeyError.AuthKeyRegistrationRequired, signingFailure.error)
            assertEquals(0, backend.signCount)

            key.acknowledgeRegistration()
            key.signDeviceAuthorization(DaaDeviceAuthorizationSigningInput(validInput()), activity)
            assertEquals(1, backend.signCount)
        }

    @Test
    fun `register device key on the device-auth profile signs a created key`() =
        runBlocking {
            val backend = FakeBackend()
            val key = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)
            val activity = mock(FragmentActivity::class.java)
            assertEquals(DaaAuthKeyResolution.Created, key.resolveOrCreate())

            val result =
                key.signDeviceAuthorization(
                    DaaDeviceAuthorizationSigningInput(registerDeviceKeyInput()),
                    activity,
                )

            assertEquals(64, result.size)
            assertEquals(1, backend.signCount)
        }

    @Test
    fun `signs registration device authorization without acknowledgement`() =
        runBlocking {
            val fixture = AuthKeyWireFixture.load()
            val spki = Base64Url.decode(fixture.p256PublicKey.spkiBase64Url)!!
            val backend = FakeBackend(spki = spki)
            val key = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)
            val activity = mock(FragmentActivity::class.java)
            val bytes = registrationInput()
            assertEquals(DaaAuthKeyResolution.Created, key.resolveOrCreate())

            val result =
                key.signRegistrationDeviceAuthorization(
                    DaaRegistrationAuthorizationSigningInput(bytes),
                    activity,
                )

            assertEquals(64, result.size)
            assertEquals(1, backend.signCount)
            assertEquals(0, backend.acknowledgeCount)
            assertEquals(bytes.toList(), backend.signedMessage?.toList())
            // The registration call site titles the prompt the same way a
            // signDeviceAuthorization for register_device_key would.
            assertEquals("register_device_key", backend.signedOperation)
            // This path must re-validate the key through the backend exactly as
            // signDeviceAuthorization does, not merely check the bare resolved flag.
            assertEquals(1, backend.registrationStateCount)
        }

    @Test
    fun `signs registration device authorization when the header jwk is the signing key`() =
        runBlocking {
            val fixture = AuthKeyWireFixture.load()
            val spki = Base64Url.decode(fixture.p256PublicKey.spkiBase64Url)!!
            val backend = FakeBackend(spki = spki)
            val key = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)
            val activity = mock(FragmentActivity::class.java)
            val bytes = registrationInput()
            assertEquals(DaaAuthKeyResolution.Created, key.resolveOrCreate())

            val result =
                key.signRegistrationDeviceAuthorization(
                    DaaRegistrationAuthorizationSigningInput(bytes),
                    activity,
                )

            assertEquals(64, result.size)
            assertEquals(1, backend.signCount)
            assertEquals(bytes.toList(), backend.signedMessage?.toList())
        }

    @Test
    fun `rejects a header jwk for a different key before reaching the signing backend`() =
        runBlocking {
            val fixture = AuthKeyWireFixture.load()
            val spki = Base64Url.decode(fixture.p256PublicKey.spkiBase64Url)!!
            val backend = FakeBackend(spki = spki)
            val key = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)
            val activity = mock(FragmentActivity::class.java)
            // A valid, on-curve P-256 jwk that is not this key's public key.
            val (otherX, otherY) = otherKeyJwk()
            assertNotEquals(TestP256Jwk.X, otherX)
            val bytes = registrationInput(jwkX = otherX, jwkY = otherY)
            assertEquals(DaaAuthKeyResolution.Created, key.resolveOrCreate())

            val error =
                assertThrows(DaaSecureKeyException::class.java) {
                    runBlocking {
                        key.signRegistrationDeviceAuthorization(
                            DaaRegistrationAuthorizationSigningInput(bytes),
                            activity,
                        )
                    }
                }

            assertEquals(DaaSecureKeyError.AuthKeyThumbprintMismatch, error.error)
            assertEquals(0, backend.signCount, "a foreign header jwk must never reach the signing backend")
        }

    /**
     * Pins the deliberate tradeoff documented on `signRegistrationDeviceAuthorization`:
     * unlike `signDeviceAuthorization`'s durable-acknowledgement shortcut in
     * `requireSigningAuthorized`, the thumbprint check's call to `thumbprint()` has
     * no shortcut for a durably-acknowledged key signed from a freshly relaunched
     * instance. Even though the shared backend already durably acknowledges this
     * identity's key -- the exact state under which `requireSigningAuthorized` lets
     * an unresolved instance proceed -- a fresh `DaaSecureKey` that never calls
     * `resolveOrCreate()` still gets `ResolutionRequired` here, not a signature.
     * This is deliberate: Device Registration Complete never relies on that
     * shortcut for this method, and the failure mode is an erroneous rejection,
     * not a security gap.
     */
    @Test
    fun `throws resolution required rather than signing when a relaunched instance never resolved`() =
        runBlocking {
            val fixture = AuthKeyWireFixture.load()
            val spki = Base64Url.decode(fixture.p256PublicKey.spkiBase64Url)!!
            val backend = FakeBackend(spki = spki)
            val sharedIdentity = identity(DaaEnvironment.Sandbox)
            val enrolling = DaaSecureKey(sharedIdentity, AuthKeyProtectionMode.UserPresence, backend)
            val activity = mock(FragmentActivity::class.java)

            // Durably acknowledge the key via a separate instance first, so the
            // backend already reports Existing for this identity.
            assertEquals(DaaAuthKeyResolution.Created, enrolling.resolveOrCreate())
            enrolling.acknowledgeRegistration()

            // A fresh instance for the same identity that never calls
            // resolveOrCreate() -- the relaunched-instance shape.
            val relaunched = DaaSecureKey(sharedIdentity, AuthKeyProtectionMode.UserPresence, backend)
            val bytes = registrationInput()

            val error =
                assertThrows(DaaSecureKeyException::class.java) {
                    runBlocking {
                        relaunched.signRegistrationDeviceAuthorization(
                            DaaRegistrationAuthorizationSigningInput(bytes),
                            activity,
                        )
                    }
                }

            assertEquals(DaaSecureKeyError.ResolutionRequired, error.error)
            assertEquals(0, backend.signCount, "an unresolved instance must never reach the signing backend")
        }

    @Test
    fun `re-verifies durable state instead of trusting a cache observed for a different key`() =
        runBlocking {
            val original = Base64Url.decode(AuthKeyWireFixture.load().p256PublicKey.spkiBase64Url)!!
            val backend = FakeBackend(spki = original)
            val key = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)
            val activity = mock(FragmentActivity::class.java)
            assertEquals(DaaAuthKeyResolution.Created, key.resolveOrCreate())
            key.acknowledgeRegistration()
            // Acknowledging directly caches Existing without a durable-state read, and this first
            // sign answers from that cache -- no backend re-validation is expected yet.
            key.signDeviceAuthorization(DaaDeviceAuthorizationSigningInput(validInput()), activity)
            assertEquals(0, backend.registrationStateCount)

            // Simulates the key under this identity's alias being replaced -- e.g. a migration or
            // a re-creation driven by another live DaaSecureKey instance for the same identity --
            // without this instance being told. A real backend's own marker check would fail for
            // the replaced key (its stored marker is bound to the old key's material); configuring
            // the fake to reject the next durable-state read stands in for that.
            backend.spki = ByteArray(91) { 1 }
            backend.registrationStateFailure = DaaSecureKeyException(DaaSecureKeyError.KeyMetadataUnavailable)

            val error =
                assertThrows(DaaSecureKeyException::class.java) {
                    runBlocking {
                        key.signDeviceAuthorization(DaaDeviceAuthorizationSigningInput(contextInput()), activity)
                    }
                }

            // A cache observed for the original key must not authorize signing on its own once
            // the key material it was bound to no longer matches -- the backend has to be asked
            // again, which is what surfaces the rejection here instead of a silently reused stale
            // acknowledgement.
            assertEquals(DaaSecureKeyError.KeyMetadataUnavailable, error.error)
            assertEquals(1, backend.registrationStateCount)
        }

    @Test
    fun `refuses a device registration input that carries the flow proof's binding claims`() {
        val digest = Base64Url.encode(ByteArray(32))
        val decoded = registrationInput().toString(Charsets.UTF_8).split('.')
        val payload = Base64Url.decode(decoded[1])!!.toString(Charsets.UTF_8)
        val withBindingClaims =
            payload.dropLast(1) +
                ",\"auth_key_thumbprint\":\"$digest\",\"code_verifier_sha256\":\"$digest\"," +
                "\"profile_id\":\"profile-1\",\"registration_handle_sha256\":\"$digest\"}"
        val bytes = "${decoded[0]}.${Base64Url.encode(withBindingClaims.toByteArray())}".toByteArray()

        val error =
            assertThrows(DaaSecureKeyException::class.java) { DaaRegistrationAuthorizationSigningInput(bytes) }

        assertEquals(DaaSecureKeyError.InvalidSigningInput, error.error)
    }

    @Test
    fun `refuses to sign a flow-authorization typ on the AuthKey`() =
        runBlocking {
            val backend = FakeBackend()
            val key = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)
            val activity = mock(FragmentActivity::class.java)
            assertEquals(DaaAuthKeyResolution.Created, key.resolveOrCreate())

            val error =
                assertThrows(DaaSecureKeyException::class.java) {
                    runBlocking {
                        key.signRegistrationDeviceAuthorization(
                            DaaRegistrationAuthorizationSigningInput(registrationFlowInput()),
                            activity,
                        )
                    }
                }

            assertEquals(DaaSecureKeyError.InvalidSigningInput, error.error)
            assertEquals(0, backend.signCount)
        }

    @Test
    fun `refuses a sensitive operation under DeviceUnlocked protection`() =
        runBlocking {
            val backend = FakeBackend()
            val key = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.DeviceUnlocked, backend)
            val activity = mock(FragmentActivity::class.java)
            key.resolveOrCreate()
            key.acknowledgeRegistration()

            for (input in listOf(transferInput(), withdrawalInput(), createAccountInput())) {
                val error =
                    assertThrows(DaaSecureKeyException::class.java) {
                        runBlocking {
                            key.signDeviceAuthorization(DaaDeviceAuthorizationSigningInput(input), activity)
                        }
                    }
                assertEquals(DaaSecureKeyError.ProtectionUnavailable, error.error)
            }
            assertEquals(0, backend.signCount)
        }

    @Test
    fun `signs every allowlisted operation under DeviceUnlocked protection`() =
        runBlocking {
            val backend = FakeBackend()
            val key = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.DeviceUnlocked, backend)
            val activity = mock(FragmentActivity::class.java)
            key.resolveOrCreate()
            key.acknowledgeRegistration()

            for (input in listOf(contextInput(), registerDeviceKeyInput(), completeSocialLoginInput())) {
                val result = key.signDeviceAuthorization(DaaDeviceAuthorizationSigningInput(input), activity)
                assertEquals(64, result.size)
            }
            assertEquals(3, backend.signCount)
        }

    @Test
    fun `signs a sensitive operation under UserPresence protection`() =
        runBlocking {
            val backend = FakeBackend()
            val key = DaaSecureKey(identity(DaaEnvironment.Sandbox), AuthKeyProtectionMode.UserPresence, backend)
            val activity = mock(FragmentActivity::class.java)
            key.resolveOrCreate()
            key.acknowledgeRegistration()

            for (input in listOf(transferInput(), withdrawalInput(), createAccountInput())) {
                val result = key.signDeviceAuthorization(DaaDeviceAuthorizationSigningInput(input), activity)
                assertEquals(64, result.size)
            }
            assertEquals(3, backend.signCount)
        }

    @Test
    fun `rejects invalid registration signing input before AuthKey sign`() {
        val error =
            assertThrows(DaaSecureKeyException::class.java) {
                DaaRegistrationAuthorizationSigningInput("not-a-jws".toByteArray())
            }
        assertEquals(DaaSecureKeyError.InvalidSigningInput, error.error)
    }
}

private const val AUTH_KEY_ID = "0f6a3c1e-8b2d-4e5f-9a7b-1c2d3e4f5a6b"
private const val OWNER_BINDING_ID = "7d9e8f10-2a3b-4c5d-8e9f-a0b1c2d3e4f5"
private const val OTHER_AUTH_KEY_ID = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"
private const val OTHER_OWNER_BINDING_ID = "6e7f8a9b-0c1d-4e2f-9a3b-4c5d6e7f8a9b"

private class FakeBackend(
    var spki: ByteArray = ByteArray(91),
    private var failures: Int = 0,
    private val signature: ByteArray = byteArrayOf(0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01),
    resolution: DaaAuthKeyResolution = DaaAuthKeyResolution.Created,
    private val signingFailure: DaaSecureKeyException? = null,
    private val resolutionGate: CompletableDeferred<Unit>? = null,
    private val acknowledgementGate: CompletableDeferred<Unit>? = null,
    private var acknowledgementFailures: Int = 0,
    var registrationStateFailure: DaaSecureKeyException? = null,
    private val signingGate: CompletableDeferred<Unit>? = null,
    private val mutateSigningBytes: Boolean = false,
    var keyPresent: Boolean = true,
    var registeredAuthKeyFailure: DaaSecureKeyException? = null,
    var afterRegisteredAuthKey: (() -> Unit)? = null,
    var beforeRegistrationWrite: (() -> Unit)? = null,
    var afterRegistrationState: (() -> Unit)? = null,
    var beforeSign: (() -> Unit)? = null,
) : AuthKeyBackend {
    private var resolution = resolution
    var resolveCount = 0
    var mintCount = 0
    var recordCount = 0
    var registeredAuthKeyCount = 0
    var replaceCount = 0

    /**
     * When set, the next [resolveOrCreate] replaces the key under the alias with a freshly minted,
     * unregistered one, the way the real backend replaces a key it can no longer use -- the
     * "another instance replaced the key" case the concurrency tests need.
     */
    var replaceOnNextResolve = false
    var record: AuthKeyRegistrationRecord? = null
    val signedWith = mutableListOf<ByteArray>()

    var acknowledgeCount = 0
    var registrationStateCount = 0
    var publicKeySpkiCount = 0

    @Volatile
    var signCount = 0
    var maxConcurrentSigns = 0
    var signedMessage: ByteArray? = null
    var signedOperation: String? = null
    private var activeSigns = 0

    override suspend fun resolveOrCreate(
        identity: DaaAuthKeyIdentity,
        protection: AuthKeyProtectionMode,
    ): AuthKeyState {
        resolveCount++
        if (failures-- > 0) throw DaaSecureKeyException(DaaSecureKeyError.SecureHardwareUnavailable)
        resolutionGate?.await()
        if (replaceOnNextResolve) {
            replaceOnNextResolve = false
            replaceCount++
            keyPresent = false
            record = null
            resolution = DaaAuthKeyResolution.Created
        }
        if (!keyPresent) {
            keyPresent = true
            mintCount++
            spki =
                KeyPairGenerator.getInstance("EC").run {
                    initialize(ECGenParameterSpec("secp256r1"))
                    generateKeyPair().public.encoded
                }
        }
        return AuthKeyState(resolution, spki)
    }

    /**
     * When set, the next [publicKeySpki] read captures the current key material, signals the first
     * deferred, and suspends until the second completes before returning what it captured -- the
     * window between a caller's check of the key and the write that depends on it.
     */
    var pauseNextPublicKeySpki: Pair<CompletableDeferred<Unit>, CompletableDeferred<Unit>>? = null

    override suspend fun publicKeySpki(identity: DaaAuthKeyIdentity): ByteArray {
        publicKeySpkiCount++
        val observed = spki.copyOf()
        pauseNextPublicKeySpki?.let { (reached, release) ->
            pauseNextPublicKeySpki = null
            reached.complete(Unit)
            release.await()
        }
        return observed
    }

    private fun requireExpectedKey(expected: ByteArray) {
        beforeRegistrationWrite?.invoke()
        if (!keyPresent || !spki.contentEquals(expected)) {
            throw DaaSecureKeyException(DaaSecureKeyError.ResolutionRequired)
        }
    }

    override suspend fun registrationState(
        identity: DaaAuthKeyIdentity,
        protection: AuthKeyProtectionMode,
    ): AuthKeyState {
        registrationStateCount++
        if (!keyPresent) throw DaaSecureKeyException(DaaSecureKeyError.KeyNotFound)
        registrationStateFailure?.let { throw it }
        val state = AuthKeyState(resolution, spki)
        afterRegistrationState?.invoke()
        return state
    }

    override suspend fun acknowledgeRegistration(
        identity: DaaAuthKeyIdentity,
        protection: AuthKeyProtectionMode,
        expectedPublicKeySpki: ByteArray,
    ) {
        acknowledgeCount++
        acknowledgementGate?.await()
        if (acknowledgementFailures-- > 0) {
            throw DaaSecureKeyException(DaaSecureKeyError.KeyMetadataUnavailable)
        }
        requireExpectedKey(expectedPublicKeySpki)
        resolution = DaaAuthKeyResolution.Existing
    }

    override suspend fun recordRegistration(
        identity: DaaAuthKeyIdentity,
        protection: AuthKeyProtectionMode,
        record: AuthKeyRegistrationRecord,
        expectedPublicKeySpki: ByteArray,
    ) {
        recordCount++
        if (!keyPresent) throw DaaSecureKeyException(DaaSecureKeyError.KeyNotFound)
        requireExpectedKey(expectedPublicKeySpki)
        this.record = record
        resolution = DaaAuthKeyResolution.Existing
    }

    override suspend fun registeredAuthKey(
        identity: DaaAuthKeyIdentity,
        protection: AuthKeyProtectionMode,
    ): AuthKeyRegisteredKey? {
        registeredAuthKeyCount++
        if (!keyPresent) return null
        registeredAuthKeyFailure?.let { throw it }
        val registered =
            if (resolution == DaaAuthKeyResolution.Existing) record?.let { AuthKeyRegisteredKey(it, spki) } else null
        afterRegisteredAuthKey?.invoke()
        return registered
    }

    override suspend fun signDer(
        identity: DaaAuthKeyIdentity,
        protection: AuthKeyProtectionMode,
        message: ByteArray,
        activity: FragmentActivity,
        operation: String,
        expectedPublicKeySpki: ByteArray,
    ): ByteArray {
        // Mirrors AndroidAuthKeyBackend: the key that would sign must be exactly the key the caller
        // authorized, or nothing is signed. signCount counts signatures that reached the key.
        beforeSign?.invoke()
        signedWith.add(expectedPublicKeySpki.copyOf())
        if (!keyPresent || !spki.contentEquals(expectedPublicKeySpki)) {
            throw DaaSecureKeyException(DaaSecureKeyError.ResolutionRequired)
        }
        synchronized(this) {
            signCount++
            activeSigns++
            maxConcurrentSigns = maxOf(maxConcurrentSigns, activeSigns)
        }
        try {
            signingGate?.await()
            signingFailure?.let { throw it }
            requireValidSigningInputAtSignatureTime(message, Instant.now().epochSecond)
            signedMessage = message.copyOf()
            signedOperation = operation
            if (mutateSigningBytes) message.fill(0)
            return signature.copyOf()
        } finally {
            synchronized(this) { activeSigns-- }
        }
    }
}

private fun String.hex(): ByteArray = chunked(2).map { it.toInt(16).toByte() }.toByteArray()

private fun ByteArray.hexString(): String = joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }
