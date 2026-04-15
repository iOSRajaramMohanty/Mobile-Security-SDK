package com.bankingsdk.security.crypto

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/**
 * ECDSA P-256 (SHA-256) signing key in Android Keystore — private key non-exportable.
 * Prefers StrongBox when available (API 28+).
 */
internal class AndroidKeystoreSigner(
    private val alias: String = "banking_sdk_signing_ec_p256",
) {
    init {
        ensureSigningKey()
    }

    fun signingPublicKeySpki(): ByteArray {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val entry = ks.getEntry(alias, null) as KeyStore.PrivateKeyEntry
        val pub = entry.certificate.publicKey as ECPublicKey
        return pub.encoded
    }

    fun sign(data: ByteArray): ByteArray {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val priv = (ks.getEntry(alias, null) as KeyStore.PrivateKeyEntry).privateKey
        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initSign(priv)
        sig.update(data)
        return sig.sign()
    }

    /**
     * Rotates the signing key: removes the current alias and generates a new hardware-backed pair.
     */
    fun rotateSigningKeys() {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        if (ks.containsAlias(alias)) {
            ks.deleteEntry(alias)
        }
        ensureSigningKey()
    }

    private fun ensureSigningKey() {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        if (ks.containsAlias(alias)) return
        try {
            generateEcKey(useStrongBox = Build.VERSION.SDK_INT >= 28)
        } catch (_: StrongBoxUnavailableException) {
            if (Build.VERSION.SDK_INT >= 28) {
                generateEcKey(useStrongBox = false)
            } else {
                throw IllegalStateException("Unable to create signing key in Keystore")
            }
        }
    }

    private fun generateEcKey(useStrongBox: Boolean) {
        val kpg = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            "AndroidKeyStore",
        )
        val builder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN,
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(false)
        if (Build.VERSION.SDK_INT >= 28) {
            builder.setIsStrongBoxBacked(useStrongBox)
        }
        kpg.initialize(builder.build())
        kpg.generateKeyPair()
    }
}
