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
import com.circle.daa.sdk.DaaSecureKeyError
import com.circle.daa.sdk.DaaSecureKeyException
import com.circle.daa.sdk.internal.authkey.Base64Url
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Mockito.mock
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.time.Instant
import java.util.concurrent.Executor

class BiometricAuthenticationSessionTest {
    @Test
    fun `saved activity state completes with authentication failure without presenting`() {
        val session = RecordingSession()

        val error =
            assertThrows(DaaSecureKeyException::class.java) {
                runBlocking {
                    authenticateAndSignWithBiometric(
                        signature = mock(Signature::class.java),
                        message = byteArrayOf(),
                        activity = activity(),
                        sessionFactory = factory(session),
                        postToUi = { it() },
                        isActivityStateSaved = { true },
                        signingExecutor = directExecutor,
                    )
                }
            }

        assertEquals(DaaSecureKeyError.AuthenticationFailed, error.error)
        assertFalse(session.authenticated)
        assertFalse(session.cancelled)
    }

    @Test
    fun `ui post failure completes with stable authentication failure`() {
        val cause = IllegalStateException("activity unavailable")

        val error =
            assertThrows(DaaSecureKeyException::class.java) {
                runBlocking {
                    authenticateAndSignWithBiometric(
                        signature = mock(Signature::class.java),
                        message = byteArrayOf(),
                        activity = activity(),
                        sessionFactory = factory(RecordingSession()),
                        postToUi = { throw cause },
                        isActivityStateSaved = { false },
                        signingExecutor = directExecutor,
                    )
                }
            }

        assertEquals(DaaSecureKeyError.AuthenticationFailed, error.error)
        assertSame(cause, error.cause)
    }

    @Test
    fun `cancellation before posted start cancels session without presenting`() =
        runBlocking {
            val session = RecordingSession()
            var posted: (() -> Unit)? = null
            val operation =
                launch(start = CoroutineStart.UNDISPATCHED) {
                    authenticateAndSignWithBiometric(
                        signature = mock(Signature::class.java),
                        message = byteArrayOf(),
                        activity = activity(),
                        sessionFactory = factory(session),
                        postToUi = { posted = it },
                        isActivityStateSaved = { false },
                        signingExecutor = directExecutor,
                    )
                }

            operation.cancelAndJoin()
            requireNotNull(posted).invoke()

            assertTrue(session.cancelled)
            assertFalse(session.authenticated)
        }

    @Test
    fun `platform cancellation callback maps to user cancelled`() {
        lateinit var onError: (Int) -> Unit
        val session = RecordingSession()

        val error =
            assertThrows(DaaSecureKeyException::class.java) {
                runBlocking {
                    authenticateAndSignWithBiometric(
                        signature = mock(Signature::class.java),
                        message = byteArrayOf(),
                        activity = activity(),
                        sessionFactory =
                            BiometricAuthenticationSessionFactory { _, errorCallback, _ ->
                                onError = errorCallback
                                session
                            },
                        postToUi = {
                            it()
                            onError(androidx.biometric.BiometricPrompt.ERROR_USER_CANCELED)
                        },
                        isActivityStateSaved = { false },
                        signingExecutor = directExecutor,
                    )
                }
            }

        assertEquals(DaaSecureKeyError.UserCancelled, error.error)
        assertTrue(session.authenticated)
    }

    @Test
    fun `signing executor rejection completes with signing failure`() {
        lateinit var onSuccess: (Signature?) -> Unit
        val cause = IllegalStateException("executor unavailable")

        val error =
            assertThrows(DaaSecureKeyException::class.java) {
                runBlocking {
                    authenticateAndSignWithBiometric(
                        signature = mock(Signature::class.java),
                        message = byteArrayOf(),
                        activity = activity(),
                        sessionFactory =
                            BiometricAuthenticationSessionFactory { _, _, successCallback ->
                                onSuccess = successCallback
                                RecordingSession()
                            },
                        postToUi = {
                            it()
                            onSuccess(mock(Signature::class.java))
                        },
                        isActivityStateSaved = { false },
                        signingExecutor = Executor { throw cause },
                    )
                }
            }

        assertEquals(DaaSecureKeyError.SigningFailed, error.error)
        assertSame(cause, error.cause)
    }

    @Test
    fun `successful authentication signs the exact valid bytes`() {
        lateinit var onSuccess: (Signature?) -> Unit
        val message = validInput()
        val expectedMessage = message.copyOf()
        val keyPair =
            KeyPairGenerator.getInstance("EC").run {
                initialize(ECGenParameterSpec("secp256r1"))
                generateKeyPair()
            }
        val signer = Signature.getInstance("SHA256withECDSA").apply { initSign(keyPair.private) }

        val der =
            runBlocking {
                authenticateAndSignWithBiometric(
                    signature = signer,
                    message = message,
                    activity = activity(),
                    sessionFactory =
                        BiometricAuthenticationSessionFactory { _, _, successCallback ->
                            onSuccess = successCallback
                            RecordingSession()
                        },
                    postToUi = {
                        it()
                        onSuccess(signer)
                    },
                    isActivityStateSaved = { false },
                    signingExecutor = directExecutor,
                )
            }

        val verifier = Signature.getInstance("SHA256withECDSA").apply { initVerify(keyPair.public) }
        verifier.update(message)
        assertTrue(verifier.verify(der))
        assertArrayEquals(expectedMessage, message)
    }

    @Test
    fun `success without signature completes with authentication failure`() {
        lateinit var onSuccess: (Signature?) -> Unit

        val error =
            assertThrows(DaaSecureKeyException::class.java) {
                runBlocking {
                    authenticateAndSignWithBiometric(
                        signature = mock(Signature::class.java),
                        message = validInput(),
                        activity = activity(),
                        sessionFactory =
                            BiometricAuthenticationSessionFactory { _, _, successCallback ->
                                onSuccess = successCallback
                                RecordingSession()
                            },
                        postToUi = {
                            it()
                            onSuccess(null)
                        },
                        isActivityStateSaved = { false },
                        signingExecutor = directExecutor,
                    )
                }
            }

        assertEquals(DaaSecureKeyError.AuthenticationFailed, error.error)
    }

    @Test
    fun `session construction failure completes with authentication failure`() {
        val cause = IllegalStateException("prompt unavailable")

        val error =
            assertThrows(DaaSecureKeyException::class.java) {
                runBlocking {
                    authenticateAndSignWithBiometric(
                        signature = mock(Signature::class.java),
                        message = validInput(),
                        activity = activity(),
                        sessionFactory = BiometricAuthenticationSessionFactory { _, _, _ -> throw cause },
                        postToUi = { it() },
                        isActivityStateSaved = { false },
                        signingExecutor = directExecutor,
                    )
                }
            }

        assertEquals(DaaSecureKeyError.AuthenticationFailed, error.error)
        assertSame(cause, error.cause)
    }

    @Test
    fun `platform authentication error maps to authentication failure`() {
        lateinit var onError: (Int) -> Unit

        val error =
            assertThrows(DaaSecureKeyException::class.java) {
                runBlocking {
                    authenticateAndSignWithBiometric(
                        signature = mock(Signature::class.java),
                        message = validInput(),
                        activity = activity(),
                        sessionFactory =
                            BiometricAuthenticationSessionFactory { _, errorCallback, _ ->
                                onError = errorCallback
                                RecordingSession()
                            },
                        postToUi = {
                            it()
                            onError(androidx.biometric.BiometricPrompt.ERROR_HW_UNAVAILABLE)
                        },
                        isActivityStateSaved = { false },
                        signingExecutor = directExecutor,
                    )
                }
            }

        assertEquals(DaaSecureKeyError.AuthenticationFailed, error.error)
    }

    private fun activity() = mock(FragmentActivity::class.java)

    private fun factory(session: BiometricAuthenticationSession) =
        BiometricAuthenticationSessionFactory { _, _, _ -> session }

    private fun validInput(): ByteArray {
        val header = """{"alg":"ES256","kid":"key-1","typ":"aw-device-authorization+jws"}"""
        val iat = Instant.now().epochSecond - 60
        val payload =
            "{\"aud\":\"circle-digital-asset-accounts\",\"body_sha256\":\"${Base64Url.encode(ByteArray(32))}\"," +
                "\"canonical_path\":\"/v1/accounts/auth/sessions\"," +
                "\"discriminator\":\"complete_social_login\"," +
                "\"exp\":${iat + 300},\"iat\":$iat,\"idempotency_key\":\"01234567-89ab-cdef-0123-456789abcdef\"," +
                "\"jti\":\"01234567-89ab-cdef-0123-456789abcdef\",\"method\":\"POST\",\"schema_version\":1}"
        return "${Base64Url.encode(header.toByteArray())}.${Base64Url.encode(payload.toByteArray())}".toByteArray()
    }

    private class RecordingSession : BiometricAuthenticationSession {
        var authenticated = false
        var cancelled = false

        override fun authenticate(signature: Signature) {
            authenticated = true
        }

        override fun cancel() {
            cancelled = true
        }
    }

    private companion object {
        val directExecutor = Executor { it.run() }
    }
}
