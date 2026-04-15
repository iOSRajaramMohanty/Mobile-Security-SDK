package com.bankingsdk.security.net

import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.X509Certificate
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSession
import javax.net.ssl.TrustManager
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/**
 * Minimal certificate pinning helper.
 *
 * This SDK does not perform networking; host applications can use these utilities
 * to enable TLS pinning when calling their backend.
 */
object CertificatePinning {

    /**
     * Returns base64(SHA-256(SPKI DER)).
     */
    fun spkiSha256Base64(cert: X509Certificate): String {
        val spki = cert.publicKey.encoded // SubjectPublicKeyInfo DER
        val md = MessageDigest.getInstance("SHA-256")
        val digest = md.digest(spki)
        return android.util.Base64.encodeToString(digest, android.util.Base64.NO_WRAP)
    }

    fun applyPinnedTlsDefaults(
        allowedLeafSpkiSha256Base64: Set<String>,
        hostnameVerifier: HostnameVerifier = DefaultHostnameVerifier,
    ) {
        val trustManager = PinnedTrustManager(allowedLeafSpkiSha256Base64)
        val sc = SSLContext.getInstance("TLS")
        sc.init(null, arrayOf<TrustManager>(trustManager), null)
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.socketFactory)
        HttpsURLConnection.setDefaultHostnameVerifier(hostnameVerifier)
    }

    object DefaultHostnameVerifier : HostnameVerifier {
        override fun verify(hostname: String?, session: SSLSession?): Boolean {
            // Default host verification should be handled by platform; this is a conservative fallback.
            return hostname != null && session != null && HttpsURLConnection.getDefaultHostnameVerifier()
                .verify(hostname, session)
        }
    }
}

private class PinnedTrustManager(
    private val allowedLeafSpkiSha256Base64: Set<String>,
) : X509TrustManager {

    private val delegate: X509TrustManager by lazy {
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        tmf.init(null as KeyStore?)
        tmf.trustManagers.filterIsInstance<X509TrustManager>().first()
    }

    override fun getAcceptedIssuers(): Array<X509Certificate> = delegate.acceptedIssuers

    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
        delegate.checkClientTrusted(chain, authType)
    }

    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
        delegate.checkServerTrusted(chain, authType)
        if (chain.isEmpty()) throw IllegalArgumentException("empty certificate chain")
        val leaf = chain[0]
        val pin = CertificatePinning.spkiSha256Base64(leaf)
        if (!allowedLeafSpkiSha256Base64.contains(pin)) {
            throw SecurityException("certificate pin mismatch")
        }
    }
}

