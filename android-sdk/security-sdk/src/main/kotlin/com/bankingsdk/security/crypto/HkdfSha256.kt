package com.bankingsdk.security.crypto

import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * HKDF-SHA256 (RFC 5869) — extract + expand.
 */
object HkdfSha256 {
    private const val HASH_LEN = 32

    fun derive(
        ikm: ByteArray,
        salt: ByteArray?,
        info: String,
        length: Int,
    ): ByteArray {
        val saltBytes = salt ?: ByteArray(HASH_LEN)
        val prk = extract(saltBytes, ikm)
        return expand(prk, info.toByteArray(StandardCharsets.UTF_8), length)
    }

    private fun extract(salt: ByteArray, ikm: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(salt, "HmacSHA256"))
        return mac.doFinal(ikm)
    }

    private fun expand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        val hashLen = HASH_LEN
        val n = (length + hashLen - 1) / hashLen
        require(n <= 255) { "HKDF length too large" }
        val okm = ByteBuffer.allocate(length)
        var tPrev = ByteArray(0)
        for (i in 1..n) {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(prk, "HmacSHA256"))
            mac.update(tPrev)
            mac.update(info)
            mac.update(i.toByte())
            tPrev = mac.doFinal()
            val need = minOf(tPrev.size, length - okm.position())
            okm.put(tPrev, 0, need)
        }
        return okm.array()
    }
}
