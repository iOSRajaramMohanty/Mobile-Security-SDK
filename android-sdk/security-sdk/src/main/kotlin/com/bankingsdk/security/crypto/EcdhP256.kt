package com.bankingsdk.security.crypto

import java.security.PrivateKey
import java.security.interfaces.ECPublicKey
import javax.crypto.KeyAgreement

internal object EcdhP256 {
    fun sharedSecret(ephemeralPrivate: PrivateKey, serverPublic: ECPublicKey): ByteArray {
        val ka = KeyAgreement.getInstance("ECDH")
        ka.init(ephemeralPrivate)
        ka.doPhase(serverPublic, true)
        return ka.generateSecret()
    }
}
