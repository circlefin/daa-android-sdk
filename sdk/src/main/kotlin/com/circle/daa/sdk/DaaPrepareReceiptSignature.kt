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
import com.circle.daa.sdk.internal.authkey.EcdsaSignatureJose
import com.circle.daa.sdk.internal.authkey.P256PublicKeyEncoding
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.ProviderException
import java.security.PublicKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

// Verify-only ES256 check for the DAA-signed Prepare receipt.
//
// `java.security` does the hashing and the signature check. This file adds no
// curve arithmetic of its own; it only moves bytes between wire forms, and it
// does that through the two `internal/authkey` encoders the AuthKey
// already uses:
//
// - `P256PublicKeyEncoding.subjectPublicKeyInfo` turns the uncompressed point
//   into the canonical 91-byte SPKI. It rejects a coordinate outside the field,
//   a point that is not on P-256, and any encoding the platform key factory does
//   not round-trip. That check is here, not left to the provider, because a
//   desktop JVM's SunEC key factory accepts an off-curve point that Android's
//   Conscrypt rejects; without it, a JVM test run would say nothing about the
//   device.
// - `EcdsaSignatureJose.derRepresentation` turns JOSE `R || S` into the DER form
//   `SHA256withECDSA` takes, rejecting `r` or `s` outside `0 < v < n`.
//
// There is no signing, no key generation, and no private-key type anywhere on
// this surface: a receipt is signed by DAA, and the SDK only checks it.

public object DaaPrepareReceiptSignature {
    private const val SIGNATURE_BYTE_COUNT: Int = 64

    /**
     * Whether [signature] is a valid ES256 signature over [signingInput] under
     * [publicKeyX963].
     *
     * [publicKeyX963] is the uncompressed P-256 point `0x04 || X || Y` of a key
     * the caller pinned from its own receipt trust material — never a key taken
     * from the token. [signingInput] is the exact JWS signing input bytes
     * (`BASE64URL(header) || '.' || BASE64URL(payload)` as received).
     * [signature] is the 64-byte JOSE `R || S`.
     *
     * Every signature problem returns `false`: a length other than 64 bytes, a
     * scalar outside `0 < r, s < n`, a mismatch, and any exception from the
     * platform verifier. Only a literal `true` means verified.
     *
     * @throws IllegalArgumentException if [publicKeyX963] is not a valid P-256
     *   point. That is a fault in the caller's pinned trust material rather than
     *   a bad receipt, so it is reported apart from a `false` a caller would read
     *   as a rejected token.
     */
    public fun verify(
        publicKeyX963: ByteArray,
        signingInput: ByteArray,
        signature: ByteArray,
    ): Boolean {
        val publicKey = publicKey(publicKeyX963)
        if (signature.size != SIGNATURE_BYTE_COUNT) {
            return false
        }
        val der =
            try {
                EcdsaSignatureJose.derRepresentation(signature)
            } catch (_: AuthKeyWireError) {
                return false
            }
        // Broad on purpose: a verifier that throws has not said yes, and the
        // only answer that may leave this function for an unverified signature
        // is `false`.
        return try {
            Signature.getInstance("SHA256withECDSA").run {
                initVerify(publicKey)
                update(signingInput)
                verify(der)
            }
        } catch (_: Exception) {
            false
        }
    }

    private fun publicKey(x963: ByteArray): PublicKey {
        val spki =
            try {
                P256PublicKeyEncoding.subjectPublicKeyInfo(x963)
            } catch (_: AuthKeyWireError) {
                throw IllegalArgumentException("not a P-256 public key")
            }
        return try {
            KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(spki))
        } catch (_: GeneralSecurityException) {
            throw IllegalArgumentException("not a P-256 public key")
        } catch (_: ProviderException) {
            throw IllegalArgumentException("not a P-256 public key")
        }
    }
}
