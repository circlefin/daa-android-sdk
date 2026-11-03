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

package com.circle.daa.sdk.internal.authkey

import org.junit.jupiter.api.Assertions.fail
import java.security.MessageDigest

internal data class AuthKeyWireFixture(
    val profile: String,
    val contract: String,
    val p256PublicKey: P256PublicKey,
    val signedMessage: SignedMessage,
    val ecdsaSignatures: List<EcdsaSignature>,
    val rejected: Rejected,
) {
    internal data class P256PublicKey(
        val x963Hex: String,
        val spkiBase64Url: String,
        val jwkThumbprint: String,
    )

    internal data class EcdsaSignature(
        val name: String,
        val derHex: String,
        val rawHex: String,
    )

    internal data class SignedMessage(
        val name: String,
        val messageHex: String,
        val publicKeyX963Hex: String,
        val derHex: String,
        val rawHex: String,
    )

    internal data class NamedHex(
        val name: String,
        val hex: String,
    )

    internal data class Rejected(
        val ecdsaDer: List<NamedHex>,
        val ecdsaRaw: List<NamedHex>,
        val x963PublicKeys: List<NamedHex>,
        val subjectPublicKeyInfo: List<NamedHex>,
    )

    internal companion object {
        private const val EXPECTED_PROFILE: String = "daa-authkey-wire-v1"
        private const val EXPECTED_CONTRACT: String = "docs/authkey-wire-contract.md"
        private const val EXPECTED_SHA256: String =
            "fc1d3f78b19269872aa75433a3ea14932a947a99af4c76329aca15bc867bf6ff"

        internal fun load(): AuthKeyWireFixture {
            val fixtureBytes =
                AuthKeyWireFixture::class.java
                    .getResourceAsStream("/Fixtures/AuthKeyWireV1.json")
                    ?.use { it.readBytes() }
                    ?: fail("Missing AuthKeyWireV1.json fixture")
            val actualSha256 = MessageDigest.getInstance("SHA-256").digest(fixtureBytes).toLowerHex()
            if (actualSha256 != EXPECTED_SHA256) {
                throw AssertionError("Unexpected AuthKeyWireV1.json SHA-256: $actualSha256")
            }
            val json = fixtureBytes.toString(Charsets.UTF_8)

            val publicKeyJson = requiredObject(json, "p256PublicKey")
            val signedMessageJson = requiredObject(json, "signedMessage")
            val rejectedJson = requiredObject(json, "rejected")
            val fixture =
                AuthKeyWireFixture(
                    profile = requiredValue(json, "profile"),
                    contract = requiredValue(json, "contract"),
                    p256PublicKey =
                        P256PublicKey(
                            x963Hex = requiredValue(publicKeyJson, "x963Hex"),
                            spkiBase64Url = requiredValue(publicKeyJson, "spkiBase64Url"),
                            jwkThumbprint = requiredValue(publicKeyJson, "jwkThumbprint"),
                        ),
                    signedMessage =
                        SignedMessage(
                            name = requiredValue(signedMessageJson, "name"),
                            messageHex = requiredValue(signedMessageJson, "messageHex"),
                            publicKeyX963Hex = requiredValue(signedMessageJson, "publicKeyX963Hex"),
                            derHex = requiredValue(signedMessageJson, "derHex"),
                            rawHex = requiredValue(signedMessageJson, "rawHex"),
                        ),
                    ecdsaSignatures = parseSignatures(requiredArray(json, "ecdsaSignatures")),
                    rejected =
                        Rejected(
                            ecdsaDer = parseNamedHex(requiredArray(rejectedJson, "ecdsaDer")),
                            ecdsaRaw = parseNamedHex(requiredArray(rejectedJson, "ecdsaRaw")),
                            x963PublicKeys = parseNamedHex(requiredArray(rejectedJson, "x963PublicKeys")),
                            subjectPublicKeyInfo = parseNamedHex(requiredArray(rejectedJson, "subjectPublicKeyInfo")),
                        ),
                )

            if (fixture.profile != EXPECTED_PROFILE || fixture.contract != EXPECTED_CONTRACT) {
                throw AssertionError("Unexpected fixture metadata: ${fixture.profile} / ${fixture.contract}")
            }
            if (
                fixture.ecdsaSignatures.size != 3 ||
                fixture.rejected.ecdsaDer.size != 3 ||
                fixture.rejected.ecdsaRaw.size != 6 ||
                fixture.rejected.x963PublicKeys.size != 3 ||
                fixture.rejected.subjectPublicKeyInfo.size != 4
            ) {
                throw AssertionError("Unexpected AuthKeyWireV1.json vector counts")
            }
            return fixture
        }

        private val signaturePattern: Regex =
            Regex(
                """\{\s*"name"\s*:\s*"([^"]+)"\s*,\s*"derHex"\s*:\s*"([^"]+)"\s*,\s*"rawHex"\s*:\s*"([^"]+)"\s*}""",
            )

        private val namedHexPattern: Regex =
            Regex(
                """\{\s*"name"\s*:\s*"([^"]+)"\s*,\s*"hex"\s*:\s*"([^"]+)"\s*}""",
            )

        private fun parseSignatures(json: String): List<EcdsaSignature> =
            signaturePattern.findAll(json).map { match ->
                EcdsaSignature(
                    name = match.groupValues[1],
                    derHex = match.groupValues[2],
                    rawHex = match.groupValues[3],
                )
            }.toList().also { signatures ->
                if (signatures.isEmpty()) {
                    throw AssertionError("Missing ecdsaSignatures in AuthKeyWireV1.json")
                }
            }

        private fun parseNamedHex(json: String): List<NamedHex> =
            namedHexPattern.findAll(json).map { match ->
                NamedHex(name = match.groupValues[1], hex = match.groupValues[2])
            }.toList().also { vectors ->
                if (vectors.isEmpty()) {
                    throw AssertionError("Missing rejected vectors in AuthKeyWireV1.json")
                }
            }

        private fun requiredObject(
            json: String,
            key: String,
        ): String = requiredContainer(json, key, '{', '}')

        private fun requiredArray(
            json: String,
            key: String,
        ): String = requiredContainer(json, key, '[', ']')

        private fun requiredContainer(
            json: String,
            key: String,
            opening: Char,
            closing: Char,
        ): String {
            val keyOffset = json.indexOf("\"$key\"")
            val startOffset = if (keyOffset >= 0) json.indexOf(opening, keyOffset + key.length + 2) else -1
            if (startOffset < 0) {
                throw AssertionError("Missing $key in AuthKeyWireV1.json")
            }

            var depth = 0
            var inString = false
            var escaped = false
            for (index in startOffset until json.length) {
                val character = json[index]
                if (inString) {
                    when {
                        escaped -> escaped = false
                        character == '\\' -> escaped = true
                        character == '"' -> inString = false
                    }
                    continue
                }

                when (character) {
                    '"' -> inString = true
                    opening -> depth += 1
                    closing -> {
                        depth -= 1
                        if (depth == 0) {
                            return json.substring(startOffset + 1, index)
                        }
                    }
                }
            }
            throw AssertionError("Unterminated $key in AuthKeyWireV1.json")
        }

        private fun requiredValue(
            json: String,
            key: String,
        ): String =
            Regex(""""$key"\s*:\s*"([^"]+)"""").find(json)?.groupValues?.get(1)
                ?: throw AssertionError("Missing $key in AuthKeyWireV1.json")
    }
}

private fun ByteArray.toLowerHex(): String =
    joinToString(separator = "") { byte ->
        (byte.toInt() and 0xFF).toString(16).padStart(2, '0')
    }

internal fun String.hexToByteArray(): ByteArray {
    require(length % 2 == 0) { "Hex strings must have an even length" }
    return chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
