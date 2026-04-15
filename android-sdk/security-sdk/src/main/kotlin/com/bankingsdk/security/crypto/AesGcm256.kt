package com.bankingsdk.security.crypto

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

private const val AES_KEY_LEN = 32
private const val GCM_IV_LEN = 12
private const val GCM_TAG_BITS = 128

data class AesGcmCiphertext(
    val iv: ByteArray,
    val ciphertext: ByteArray,
    val tag: ByteArray,
)

object AesGcm256 {
    private val secureRandom = SecureRandom()

    fun encrypt(key: ByteArray, plaintext: ByteArray): AesGcmCiphertext {
        require(key.size == AES_KEY_LEN) { "AES-256 key must be 32 bytes" }
        val iv = ByteArray(GCM_IV_LEN)
        secureRandom.nextBytes(iv)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(GCM_TAG_BITS, iv)
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), spec)
        val out = cipher.doFinal(plaintext)
        val tagLen = GCM_TAG_BITS / 8
        val ct = out.copyOfRange(0, out.size - tagLen)
        val tag = out.copyOfRange(out.size - tagLen, out.size)
        return AesGcmCiphertext(iv, ct, tag)
    }

    /**
     * Decrypts and authenticates. A bad authentication tag causes [javax.crypto.AEADBadTagException].
     */
    fun decrypt(key: ByteArray, blob: AesGcmCiphertext): ByteArray {
        require(key.size == AES_KEY_LEN) { "AES-256 key must be 32 bytes" }
        require(blob.iv.size == GCM_IV_LEN) { "GCM IV must be 12 bytes" }
        require(blob.tag.size == GCM_TAG_BITS / 8) { "GCM tag must be 16 bytes" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(GCM_TAG_BITS, blob.iv)
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), spec)
        return cipher.doFinal(blob.ciphertext + blob.tag)
    }
}
