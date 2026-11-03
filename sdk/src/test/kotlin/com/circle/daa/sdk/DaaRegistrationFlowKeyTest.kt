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

import com.circle.daa.sdk.internal.authkey.Base64Url
import com.circle.daa.sdk.internal.authkey.EcdsaSignatureJose
import com.circle.daa.sdk.internal.authkey.P256PublicKeyEncoding
import com.circle.daa.sdk.internal.authkey.TestP256Jwk
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.lang.reflect.Method
import java.lang.reflect.Modifier
import java.security.KeyFactory
import java.security.KeyPair
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.time.Instant

/**
 * Behavioral constraints on the ephemeral registration-flow key.
 *
 * The exported public key is decoded through the internal [Base64Url] and checked
 * with the internal [P256PublicKeyEncoding] rather than a locally written
 * decoder: unit tests in this module reach `internal` declarations directly, so
 * the assertions are made against the same encoder the production path uses.
 */
class DaaRegistrationFlowKeyTest {
    @Test
    fun `exports a well-formed 91-byte P-256 SubjectPublicKeyInfo`() {
        val encoded = DaaRegistrationFlowKey.generate().publicKeySpkiBase64Url()

        // Unpadded Base64URL of 91 bytes is always exactly 122 characters, so a
        // padded or truncated encoding fails here before the decode.
        assertEquals(122, encoded.length)
        val spki = Base64Url.decode(encoded)
        assertNotNull(spki, "export is not canonical unpadded Base64URL")
        assertEquals(91, spki!!.size)

        // The whole contract, not just the length: DER prefix, canonical P-256
        // curve parameters, the point on the curve, and a round-tripping encoding.
        val x963 = P256PublicKeyEncoding.x963Representation(spki = spki)
        assertEquals(65, x963.size)
        assertEquals(0x04.toByte(), x963.first())
        assertEquals(encoded, P256PublicKeyEncoding.subjectPublicKeyInfoBase64Url(x963 = x963))
    }

    @Test
    fun `generates a distinct keypair per call`() {
        val keys = List(8) { DaaRegistrationFlowKey.generate() }

        // A P-256 public key determines its private key, so eight distinct public
        // keys are eight distinct keypairs. The private halves are deliberately not
        // reached for here: they are `private`, not `internal`, so this test cannot
        // see them and neither can a Java caller in a host app.
        val publicKeys = keys.map { it.publicKeySpkiBase64Url() }
        assertEquals(publicKeys.size, publicKeys.toSet().size, "a public key repeated across attempts")
    }

    @Test
    fun `the same key exports the same public key every time`() {
        val key = DaaRegistrationFlowKey.generate()

        assertEquals(key.publicKeySpkiBase64Url(), key.publicKeySpkiBase64Url())
    }

    @Test
    fun `typed Complete sign is the only signing-shaped member`() {
        // `apiCheck` against sdk/api/sdk.api is the build gate; this asserts the
        // same invariant from the consumer's side. The only signing-shaped member
        // is the typed Complete sign; a generic `sign(bytes)` is excluded.
        assertEquals(
            setOf("publicKeySpkiBase64Url", "signRegistrationAuthorization", "toString"),
            callableApi(DaaRegistrationFlowKey::class.java),
            "the flow key's callable surface changed",
        )
        assertEquals(
            setOf("generate"),
            callableApi(DaaRegistrationFlowKey.Companion::class.java),
            "the flow key's companion surface changed",
        )

        // The retained private key must not be reachable under any name. Checked
        // against every declared method, not just the public ones: an `internal`
        // member compiles to a public JVM method under a `$sdk_release` name that a
        // Java caller in a host app can reach, so a visibility filter here would
        // look clean while the hole existed.
        // `signRegistrationAuthorization` is the only allowed signing-shaped name;
        // a bare `sign` and any PrivateKey/KeyPair return remain forbidden.
        val declared =
            DaaRegistrationFlowKey::class.java.declaredMethods +
                DaaRegistrationFlowKey.Companion::class.java.declaredMethods
        declared
            .filterNot(Method::isSynthetic)
            .forEach { method ->
                assertNotEquals(PrivateKey::class.java, method.returnType, "${method.name} returns a PrivateKey")
                assertNotEquals(KeyPair::class.java, method.returnType, "${method.name} returns a KeyPair")
                assertFalse(method.name == "sign", "bare sign member: ${method.name}")
                if (method.name != "signRegistrationAuthorization") {
                    assertFalse(
                        method.name.lowercase().contains("sign"),
                        "signing-shaped member: ${method.name}",
                    )
                }
                assertFalse(method.name.lowercase().contains("private"), "private-key-shaped member: ${method.name}")
            }
    }

    @Test
    fun `signs exact registration bytes and verifies against the exported SPKI`() {
        val key = DaaRegistrationFlowKey.generate()
        val bytes = registrationSigningInput()
        val input = DaaRegistrationAuthorizationSigningInput(bytes)

        val signature = key.signRegistrationAuthorization(input)

        assertEquals(64, signature.size)
        assertArrayEquals(bytes, input.signingBytes())
        val spki = requireNotNull(Base64Url.decode(key.publicKeySpkiBase64Url()))
        val publicKey = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(spki))
        val der = EcdsaSignatureJose.derRepresentation(signature)
        assertTrue(
            Signature.getInstance("SHA256withECDSA").run {
                initVerify(publicKey)
                update(bytes)
                verify(der)
            },
        )
    }

    @Test
    fun `refuses to sign a device-authorization typ`() {
        val key = DaaRegistrationFlowKey.generate()
        val input = DaaRegistrationAuthorizationSigningInput(registrationSigningInput(deviceTyp = true))

        val error =
            assertThrows(DaaSecureKeyException::class.java) {
                key.signRegistrationAuthorization(input)
            }

        assertEquals(DaaSecureKeyError.InvalidSigningInput, error.error)
    }

    @Test
    fun `toString redacts the key`() {
        val key = DaaRegistrationFlowKey.generate()

        val printed = key.toString()

        assertEquals("DaaRegistrationFlowKey(publicKey=<redacted>)", printed)
        assertFalse(printed.contains(key.publicKeySpkiBase64Url()))
    }

    @Test
    fun `the exception names its case and carries nothing else`() {
        val exception = DaaRegistrationFlowKeyException(DaaRegistrationFlowKeyError.PublicKeyUnavailable)

        assertEquals(DaaRegistrationFlowKeyError.PublicKeyUnavailable, exception.error)
        assertEquals("DAA registration-flow key operation failed: PublicKeyUnavailable", exception.message)
        assertNotEquals(
            DaaRegistrationFlowKeyException(DaaRegistrationFlowKeyError.KeyGenerationFailed).message,
            exception.message,
        )
        assertTrue(
            DaaRegistrationFlowKeyError.entries.map { it.name }
                .containsAll(listOf("KeyGenerationFailed", "PublicKeyUnavailable", "SigningFailed")),
        )
        assertEquals(3, DaaRegistrationFlowKeyError.entries.size)
    }

    /**
     * The names a consumer can actually call on [type]: public, declared here, and
     * not a compiler artifact. `$`-bearing names are excluded because Kotlin emits
     * synthetic accessors and `internal` members that way; the separate loop above
     * is what catches a signing- or private-key-shaped member arriving under any
     * name, mangled or not.
     */
    private fun callableApi(type: Class<*>): Set<String> =
        type.declaredMethods
            .filter(::isCallableApi)
            .map(Method::getName)
            .toSet()

    private fun isCallableApi(method: Method): Boolean =
        Modifier.isPublic(method.modifiers) && !method.isSynthetic && !method.name.contains('$')

    private fun registrationSigningInput(deviceTyp: Boolean = false): ByteArray {
        val digest = Base64Url.encode(ByteArray(32))
        val jwkX = TestP256Jwk.X
        val jwkY = TestP256Jwk.Y
        val typ =
            if (deviceTyp) {
                "daa-device-authorization+jws"
            } else {
                "daa-registration-flow-authorization+jws"
            }
        val header =
            "{\"alg\":\"ES256\",\"typ\":\"$typ\"," +
                "\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"$jwkX\",\"y\":\"$jwkY\"}}"
        val iat = Instant.now().epochSecond - 1
        // Each typ carries its own exact claim set: the device proof has only
        // the request-binding claims, the flow proof adds the four
        // registration-binding claims.
        val registrationBinding =
            if (deviceTyp) {
                ""
            } else {
                "\"auth_key_thumbprint\":\"$digest\",\"code_verifier_sha256\":\"$digest\"," +
                    "\"profile_id\":\"profile-1\",\"registration_handle_sha256\":\"$digest\","
            }
        val payload =
            "{\"aud\":\"circle-digital-asset-accounts\"," +
                "\"body_sha256\":\"$digest\",\"canonical_path\":\"/v1/accounts/auth/deviceKeyRegistration\"," +
                "\"discriminator\":\"device_key_registration.v1\"," +
                "\"exp\":${iat + 300},\"iat\":$iat,\"idempotency_key\":\"01234567-89ab-cdef-0123-456789abcdef\"," +
                "\"jti\":\"fedcba98-7654-3210-fedc-ba9876543210\",\"method\":\"POST\"," +
                registrationBinding +
                "\"schema_version\":1}"
        return "${Base64Url.encode(header.toByteArray())}.${Base64Url.encode(payload.toByteArray())}".toByteArray()
    }
}
