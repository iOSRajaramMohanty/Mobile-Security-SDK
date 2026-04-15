package com.bankingsdk.security.crypto

import com.bankingsdk.security.CryptoEngine
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/**
 * JVM-only checks: ECDH P-256 + HKDF + AES-GCM + ECDSA match the algorithms used in [HybridEnvelope].
 */
class HybridCryptoEngineTest {

    @Test
    fun ecdhSharedSecretMatchesBothDirections() {
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"))
        val server = kpg.generateKeyPair()
        val ephemeral = kpg.generateKeyPair()

        val sharedClient = EcdhP256.sharedSecret(ephemeral.private, server.public as ECPublicKey)
        val sharedServer = EcdhP256.sharedSecret(server.private as ECPrivateKey, ephemeral.public as ECPublicKey)
        assertArrayEquals(sharedClient, sharedServer)
    }

    @Test
    fun hkdfThenAesWrapRoundtrip() {
        val ikm = ByteArray(32) { 3 }
        val wrapKey = HkdfSha256.derive(ikm, null, "banking-sdk-wrap-v1", 32)
        val dek = ByteArray(32) { 9 }
        val wrapped = AesGcm256.encrypt(wrapKey, dek)
        val out = AesGcm256.decrypt(wrapKey, wrapped)
        assertArrayEquals(dek, out)
    }

    @Test
    fun aesGcmRejectsWrongTag() {
        val key = ByteArray(32) { 1 }
        val sealed = AesGcm256.encrypt(key, "hello".toByteArray(Charsets.UTF_8))
        val badTag = sealed.tag.copyOf().also { it[0] = (it[0].toInt() xor 0xff).toByte() }
        val tampered = AesGcmCiphertext(sealed.iv, sealed.ciphertext, badTag)
        try {
            AesGcm256.decrypt(key, tampered)
            throw AssertionError("expected AEAD failure")
        } catch (_: Exception) {
            // AEADBadTagException or javax.crypto.AEADBadTagException
        }
    }

    @Test
    fun cryptoEngineVerifyEcdsa() {
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"))
        val kp = kpg.generateKeyPair()
        val priv = kp.private as ECPrivateKey
        val pub = kp.public as ECPublicKey
        val spki = pub.encoded
        val msg = "canonical-bytes".toByteArray(Charsets.UTF_8)
        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initSign(priv)
        sig.update(msg)
        val der = sig.sign()
        assertTrue(CryptoEngine.verifyEcdsaSha256(msg, der, spki))
    }

    @Test
    fun ecP256SpkiRoundtrip() {
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"))
        val pub = kpg.generateKeyPair().public as ECPublicKey
        val spki = pub.encoded
        val parsed = EcP256.publicKeyFromSpki(spki)
        assertArrayEquals(spki, parsed.encoded)
    }
}
