package com.bankingsdk.security

import android.content.Context
import android.util.Base64
import com.bankingsdk.security.crypto.AndroidKeystoreSigner

/**
 * Hardware-backed signing key (P-256, non-exportable private key).
 */
class SecureKeyManager internal constructor(@Suppress("UNUSED_PARAMETER") context: Context) {
    private val signer = AndroidKeystoreSigner()

    /** SPKI DER, Base64. */
    fun getPublicKey(): String =
        Base64.encodeToString(signer.signingPublicKeySpki(), Base64.NO_WRAP)

    fun signingPublicKeySpki(): ByteArray = signer.signingPublicKeySpki()

    fun rotateKeys() {
        signer.rotateSigningKeys()
    }
}
