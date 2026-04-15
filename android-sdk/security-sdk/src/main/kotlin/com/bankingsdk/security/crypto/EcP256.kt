package com.bankingsdk.security.crypto

import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PublicKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec

internal object EcP256 {
    private const val CURVE = "secp256r1"

    fun generateEphemeralKeyPair(): KeyPair {
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec(CURVE))
        return kpg.generateKeyPair()
    }

    fun publicKeyFromSpki(spkiDer: ByteArray): ECPublicKey {
        val spec = X509EncodedKeySpec(spkiDer)
        return KeyFactory.getInstance("EC").generatePublic(spec) as ECPublicKey
    }

    fun encodePublicSpki(publicKey: PublicKey): ByteArray {
        return publicKey.encoded
    }
}
