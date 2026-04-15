package com.bankingsdk.security.crypto

import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets

/**
 * Deterministic byte sequence for ECDSA over the secure envelope (replay-resistant via nonce + timestamp).
 */
internal object CanonicalPayload {
    fun build(
        method: String,
        host: String,
        contentType: String,
        riskScore: Int,
        keyId: String,
        path: String,
        timestampMs: Long,
        nonce: ByteArray,
        payloadCipher: AesGcmCiphertext,
        wrappedDek: AesGcmCiphertext,
        ephemeralPublicSpki: ByteArray,
    ): ByteArray {
        val methodB = method.toByteArray(StandardCharsets.UTF_8)
        val hostB = host.toByteArray(StandardCharsets.UTF_8)
        val contentTypeB = contentType.toByteArray(StandardCharsets.UTF_8)
        val keyIdB = keyId.toByteArray(StandardCharsets.UTF_8)
        val pathB = path.toByteArray(StandardCharsets.UTF_8)
        val pay = payloadCipher.iv + payloadCipher.ciphertext + payloadCipher.tag
        val wrap = wrappedDek.iv + wrappedDek.ciphertext + wrappedDek.tag
        val sz =
            (4 + methodB.size) +
                (4 + hostB.size) +
                (4 + contentTypeB.size) +
                4 + // riskScore (u32)
                (4 + keyIdB.size) +
                4 + pathB.size + 8 + (4 + nonce.size) + (4 + pay.size) + (4 + wrap.size) + (4 + ephemeralPublicSpki.size)
        val bb = ByteBuffer.allocate(sz)
        putPrefixed(bb, methodB)
        putPrefixed(bb, hostB)
        putPrefixed(bb, contentTypeB)
        bb.putInt(riskScore.coerceIn(0, 100))
        putPrefixed(bb, keyIdB)
        putPrefixed(bb, pathB)
        bb.putLong(timestampMs)
        putPrefixed(bb, nonce)
        putPrefixed(bb, pay)
        putPrefixed(bb, wrap)
        putPrefixed(bb, ephemeralPublicSpki)
        return bb.array()
    }

    private fun putPrefixed(bb: ByteBuffer, data: ByteArray) {
        bb.putInt(data.size)
        bb.put(data)
    }
}
