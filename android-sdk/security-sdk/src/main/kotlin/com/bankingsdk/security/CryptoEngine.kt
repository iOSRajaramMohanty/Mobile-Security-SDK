package com.bankingsdk.security

import com.bankingsdk.security.crypto.AesGcm256
import com.bankingsdk.security.crypto.AesGcmCiphertext
import com.bankingsdk.security.crypto.EcP256
import com.bankingsdk.security.crypto.HkdfSha256
import java.security.Signature

/**
 * Native-only cryptographic primitives exposed for advanced integrations (still no JS crypto).
 *
 * AES-GCM: 12-byte random IV, 128-bit tag; decryption verifies the tag (AEAD) and fails on tampering.
 * ECC: NIST P-256 (secp256r1) for ECDH and ECDSA (SHA-256).
 */
object CryptoEngine {
    fun encryptAesGcm256(key: ByteArray, plaintext: ByteArray): AesGcmCiphertext =
        AesGcm256.encrypt(key, plaintext)

    /** Decrypts and authenticates; throws [javax.crypto.AEADBadTagException] if the tag does not match. */
    fun decryptAesGcm256(key: ByteArray, blob: AesGcmCiphertext): ByteArray =
        AesGcm256.decrypt(key, blob)

    fun hkdfSha256(ikm: ByteArray, salt: ByteArray?, info: String, length: Int): ByteArray =
        HkdfSha256.derive(ikm, salt, info, length)

    /**
     * Verify ECDSA P-256 signature (SHA-256) against an SPKI-encoded peer public key.
     */
    fun verifyEcdsaSha256(data: ByteArray, signatureDer: ByteArray, peerPublicKeySpki: ByteArray): Boolean {
        return try {
            val pub = EcP256.publicKeyFromSpki(peerPublicKeySpki)
            val sig = Signature.getInstance("SHA256withECDSA")
            sig.initVerify(pub)
            sig.update(data)
            sig.verify(signatureDer)
        } catch (_: Exception) {
            false
        }
    }
}
