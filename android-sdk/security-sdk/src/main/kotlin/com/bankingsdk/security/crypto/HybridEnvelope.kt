package com.bankingsdk.security.crypto

import android.util.Base64
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Hybrid encryption: random DEK → AES-GCM(payload); ECDH(server) → HKDF → AES-GCM(DEK); ECDSA(device) over canonical bytes.
 */
internal object HybridEnvelope {
    private val rnd = SecureRandom()

    private fun base64url(bytes: ByteArray): String {
        return Base64.encodeToString(bytes, Base64.NO_WRAP)
            .replace('+', '-')
            .replace('/', '_')
            .trimEnd('=')
    }

    private fun keyIdFromSpki(spkiDer: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(spkiDer)
        return base64url(digest)
    }

    fun build(
        method: String,
        host: String,
        contentType: String,
        riskScore: Int,
        path: String,
        plaintext: ByteArray,
        serverPublicSpki: ByteArray,
        signer: AndroidKeystoreSigner,
    ): Map<String, Any?> {
        val serverPub = EcP256.publicKeyFromSpki(serverPublicSpki)
        val ephemeral = EcP256.generateEphemeralKeyPair()
        val shared = EcdhP256.sharedSecret(ephemeral.private, serverPub)
        val dek = ByteArray(32).also { rnd.nextBytes(it) }
        val payloadSealed = AesGcm256.encrypt(dek, plaintext)
        val wrapKey = HkdfSha256.derive(shared, null, "banking-sdk-wrap-v1", 32)
        val wrappedDek = AesGcm256.encrypt(wrapKey, dek)
        val ts = System.currentTimeMillis()
        val nonce = ByteArray(16).also { rnd.nextBytes(it) }
        val ephSpki = EcP256.encodePublicSpki(ephemeral.public)
        val devicePubSpki = signer.signingPublicKeySpki()
        val keyId = keyIdFromSpki(devicePubSpki)
        val canonical =
            CanonicalPayload.build(method, host, contentType, riskScore, keyId, path, ts, nonce, payloadSealed, wrappedDek, ephSpki)
        val signature = signer.sign(canonical)
        return mapOf(
            "v" to 1,
            "algorithm" to "HYBRID_P256_AES256GCM_ECDSA_SHA256",
            "method" to method,
            "host" to host,
            "contentType" to contentType,
            "riskScore" to riskScore.coerceIn(0, 100),
            "keyId" to keyId,
            "timestampMs" to ts,
            "nonce" to Base64.encodeToString(nonce, Base64.NO_WRAP),
            "path" to path,
            "aesIv" to Base64.encodeToString(payloadSealed.iv, Base64.NO_WRAP),
            "ciphertext" to Base64.encodeToString(payloadSealed.ciphertext, Base64.NO_WRAP),
            "aesTag" to Base64.encodeToString(payloadSealed.tag, Base64.NO_WRAP),
            "wrappedDekIv" to Base64.encodeToString(wrappedDek.iv, Base64.NO_WRAP),
            "wrappedDekCipher" to Base64.encodeToString(wrappedDek.ciphertext, Base64.NO_WRAP),
            "wrappedDekTag" to Base64.encodeToString(wrappedDek.tag, Base64.NO_WRAP),
            "ephemeralPublicSpki" to Base64.encodeToString(ephSpki, Base64.NO_WRAP),
            // Included for debugging/telemetry only; backend must not trust this for verification.
            "deviceSigningPublicSpki" to Base64.encodeToString(devicePubSpki, Base64.NO_WRAP),
            // Local-only: used to decrypt encrypted gateway responses. MUST NOT be forwarded over the network.
            "_clientDek" to Base64.encodeToString(dek, Base64.NO_WRAP),
            "signature" to Base64.encodeToString(signature, Base64.NO_WRAP),
        )
    }
}
