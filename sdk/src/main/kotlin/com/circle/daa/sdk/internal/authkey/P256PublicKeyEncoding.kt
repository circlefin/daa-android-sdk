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

import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.ProviderException
import java.security.Security
import java.security.interfaces.ECPublicKey
import java.security.spec.ECFieldFp
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.X509EncodedKeySpec

internal object P256PublicKeyEncoding {
    private const val COORDINATE_BYTE_COUNT: Int = 32
    private const val X963_BYTE_COUNT: Int = 65
    private const val SPKI_BYTE_COUNT: Int = 91
    private const val UNCOMPRESSED_POINT_MARKER: Byte = 0x04

    private val CURVE_PRIME: BigInteger =
        BigInteger(
            "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
            16,
        )
    private val CURVE_A: BigInteger = CURVE_PRIME.subtract(BigInteger.valueOf(3))
    private val CURVE_B: BigInteger =
        BigInteger(
            "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
            16,
        )
    private val GROUP_ORDER: BigInteger =
        BigInteger(
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
            16,
        )
    private val GENERATOR_X: BigInteger =
        BigInteger(
            "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
            16,
        )
    private val GENERATOR_Y: BigInteger =
        BigInteger(
            "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
            16,
        )
    private val SPKI_PREFIX: ByteArray =
        byteArrayOf(
            0x30,
            0x59,
            0x30,
            0x13,
            0x06,
            0x07,
            0x2A,
            0x86.toByte(),
            0x48,
            0xCE.toByte(),
            0x3D,
            0x02,
            0x01,
            0x06,
            0x08,
            0x2A,
            0x86.toByte(),
            0x48,
            0xCE.toByte(),
            0x3D,
            0x03,
            0x01,
            0x07,
            0x03,
            0x42,
            0x00,
        )

    private val EC_PARAMETERS: ECParameterSpec =
        AlgorithmParameters.getInstance("EC").run {
            init(ECGenParameterSpec("secp256r1"))
            getParameterSpec(ECParameterSpec::class.java)
        }

    internal fun subjectPublicKeyInfo(x963: ByteArray): ByteArray {
        val point = parseAndValidateX963(x963)
        val expectedSpki = SPKI_PREFIX + x963
        val generated = generatePublicKey(point)
        if (!generated.encoded.contentEquals(expectedSpki)) {
            throw AuthKeyWireError.MalformedP256PublicKey
        }
        return expectedSpki
    }

    internal fun x963Representation(spki: ByteArray): ByteArray {
        if (spki.size != SPKI_BYTE_COUNT || !spki.copyOfRange(0, SPKI_PREFIX.size).contentEquals(SPKI_PREFIX)) {
            throw AuthKeyWireError.MalformedP256PublicKey
        }

        val publicKey =
            try {
                keyFactory().generatePublic(X509EncodedKeySpec(spki)) as? ECPublicKey
            } catch (_: GeneralSecurityException) {
                null
            } catch (_: ProviderException) {
                null
            } catch (_: IllegalArgumentException) {
                null
            } ?: throw AuthKeyWireError.MalformedP256PublicKey

        if (!hasCanonicalP256Parameters(publicKey.params)) {
            throw AuthKeyWireError.MalformedP256PublicKey
        }

        if (!publicKey.encoded.contentEquals(spki)) {
            throw AuthKeyWireError.MalformedP256PublicKey
        }

        val x963 = encodeUncompressedPoint(publicKey.w)
        parseAndValidateX963(x963)
        if (!spki.contentEquals(SPKI_PREFIX + x963)) {
            throw AuthKeyWireError.MalformedP256PublicKey
        }
        return x963
    }

    internal fun subjectPublicKeyInfoBase64Url(x963: ByteArray): String = Base64Url.encode(subjectPublicKeyInfo(x963))

    internal fun jwkThumbprint(spki: ByteArray): String {
        val x963 = x963Representation(spki = spki)
        val xCoordinate = x963.copyOfRange(1, 1 + COORDINATE_BYTE_COUNT)
        val yCoordinate = x963.copyOfRange(1 + COORDINATE_BYTE_COUNT, x963.size)
        val canonicalJwk =
            buildString(86) {
                append("{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"")
                append(Base64Url.encode(xCoordinate))
                append("\",\"y\":\"")
                append(Base64Url.encode(yCoordinate))
                append("\"}")
            }
        return Base64Url.encode(MessageDigest.getInstance("SHA-256").digest(canonicalJwk.toByteArray()))
    }

    private fun parseAndValidateX963(x963: ByteArray): ECPoint {
        if (x963.size != X963_BYTE_COUNT || x963.firstOrNull() != UNCOMPRESSED_POINT_MARKER) {
            throw AuthKeyWireError.MalformedP256PublicKey
        }

        val point =
            ECPoint(
                BigInteger(1, x963.copyOfRange(1, 1 + COORDINATE_BYTE_COUNT)),
                BigInteger(1, x963.copyOfRange(1 + COORDINATE_BYTE_COUNT, x963.size)),
            )
        if (!isValidAffineCoordinate(point.affineX) || !isValidAffineCoordinate(point.affineY)) {
            throw AuthKeyWireError.MalformedP256PublicKey
        }
        if (!isPointOnCurve(point)) {
            throw AuthKeyWireError.MalformedP256PublicKey
        }

        val generated = generatePublicKey(point)
        if (!generated.encoded.contentEquals(SPKI_PREFIX + x963)) {
            throw AuthKeyWireError.MalformedP256PublicKey
        }
        return point
    }

    private fun generatePublicKey(point: ECPoint): ECPublicKey =
        try {
            keyFactory().generatePublic(ECPublicKeySpec(point, EC_PARAMETERS)) as? ECPublicKey
        } catch (_: GeneralSecurityException) {
            null
        } catch (_: ProviderException) {
            null
        } catch (_: IllegalArgumentException) {
            null
        } ?: throw AuthKeyWireError.MalformedP256PublicKey

    private fun keyFactory(): KeyFactory {
        val provider =
            Security.getProvider("AndroidOpenSSL")
                ?: Security.getProvider("SunEC")
                ?: throw AuthKeyWireError.MalformedP256PublicKey
        return KeyFactory.getInstance("EC", provider)
    }

    private fun hasCanonicalP256Parameters(parameters: ECParameterSpec): Boolean {
        val field = parameters.curve.field as? ECFieldFp ?: return false
        return field.p == CURVE_PRIME &&
            parameters.curve.a == CURVE_A &&
            parameters.curve.b == CURVE_B &&
            parameters.order == GROUP_ORDER &&
            parameters.cofactor == 1 &&
            parameters.generator.affineX == GENERATOR_X &&
            parameters.generator.affineY == GENERATOR_Y
    }

    private fun isValidAffineCoordinate(coordinate: BigInteger): Boolean =
        coordinate.signum() >= 0 && coordinate < CURVE_PRIME

    private fun isPointOnCurve(point: ECPoint): Boolean {
        val left = point.affineY.modPow(BigInteger.valueOf(2), CURVE_PRIME)
        val right =
            point.affineX.modPow(BigInteger.valueOf(3), CURVE_PRIME)
                .add(CURVE_A.multiply(point.affineX))
                .add(CURVE_B)
                .mod(CURVE_PRIME)
        return left == right
    }

    private fun encodeUncompressedPoint(point: ECPoint): ByteArray =
        byteArrayOf(UNCOMPRESSED_POINT_MARKER) +
            point.affineX.toUnsignedFixedLength(COORDINATE_BYTE_COUNT) +
            point.affineY.toUnsignedFixedLength(COORDINATE_BYTE_COUNT)

    private fun BigInteger.toUnsignedFixedLength(length: Int): ByteArray {
        val raw = toByteArray().stripLeadingSignByte()
        if (signum() < 0 || raw.size > length) {
            throw AuthKeyWireError.MalformedP256PublicKey
        }
        return ByteArray(length).also { padded ->
            raw.copyInto(
                destination = padded,
                destinationOffset = length - raw.size,
            )
        }
    }

    private fun ByteArray.stripLeadingSignByte(): ByteArray =
        if (size > 1 && this[0] == 0.toByte()) {
            copyOfRange(1, size)
        } else {
            this
        }
}
