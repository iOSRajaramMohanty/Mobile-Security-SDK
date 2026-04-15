package com.bankingsdk.security.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

class AesGcm256Test {
    @Test
    fun roundtrip() {
        val key = ByteArray(32) { it.toByte() }
        val plain = "banking-payload".toByteArray(Charsets.UTF_8)
        val sealed = AesGcm256.encrypt(key, plain)
        val out = AesGcm256.decrypt(key, sealed)
        assertArrayEquals(plain, out)
    }

    @Test
    fun hkdfMatchesLength() {
        val ikm = ByteArray(32) { 7 }
        val d = HkdfSha256.derive(ikm, null, "info", 32)
        assertEquals(32, d.size)
    }
}
