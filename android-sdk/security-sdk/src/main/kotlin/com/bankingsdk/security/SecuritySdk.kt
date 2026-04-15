package com.bankingsdk.security

import android.content.Context
import android.content.pm.ApplicationInfo
import android.os.Build
import android.os.Debug
import android.util.Base64
import androidx.annotation.Keep
import com.bankingsdk.security.crypto.AndroidKeystoreSigner
import com.bankingsdk.security.crypto.EcP256
import com.bankingsdk.security.crypto.HybridEnvelope
import java.io.File
import java.net.URI
import org.json.JSONObject

/**
 * Core Android security SDK facade. Cryptography runs only in native code; private keys stay in Keystore.
 */
@Keep
object SecuritySdk {

    @Volatile
    private var appContext: Context? = null

    @Volatile
    private var serverSpki: ByteArray? = null

    @Volatile
    private var keystoreSigner: AndroidKeystoreSigner? = null

    /**
     * Initializes hardware-backed signing (EC P-256, non-exportable) and encrypted installation identity.
     */
    fun init(context: Context): Result<Unit> = runCatching {
        val app = context.applicationContext
        appContext = app
        keystoreSigner = AndroidKeystoreSigner()
        DeviceIdentity.getOrCreateInstallationId(app)
    }

    fun configureServerPublicKey(spkiDer: ByteArray): Result<Unit> = runCatching {
        EcP256.publicKeyFromSpki(spkiDer)
        serverSpki = spkiDer.copyOf()
    }

    fun configureServerPublicKeyFromBase64(b64: String): Result<Unit> {
        val bytes = Base64.decode(b64, Base64.NO_WRAP)
        return configureServerPublicKey(bytes)
    }

    /** ECDSA P-256 signing public key (SPKI DER) as Base64 — for device registration. */
    fun getPublicKey(): Result<String> = runCatching {
        appContext ?: error("init(context) required")
        val signer = keystoreSigner ?: AndroidKeystoreSigner().also { keystoreSigner = it }
        Base64.encodeToString(signer.signingPublicKeySpki(), Base64.NO_WRAP)
    }

    /**
     * Rotates the hardware-backed signing key. Prior key material is invalidated in Keystore.
     */
    fun rotateKeys(): Result<Unit> = runCatching {
        appContext ?: error("init(context) required")
        val signer = keystoreSigner ?: AndroidKeystoreSigner().also { keystoreSigner = it }
        signer.rotateSigningKeys()
    }

    /**
     * Payload for server-side device registration (installation id + signing public key + platform).
     */
    fun getDeviceRegistrationPayload(): Result<Map<String, Any?>> = runCatching {
        val ctx = appContext ?: error("init(context) required")
        val signer = keystoreSigner ?: AndroidKeystoreSigner().also { keystoreSigner = it }
        val installationId = DeviceIdentity.getOrCreateInstallationId(ctx)
        val pubB64 = Base64.encodeToString(signer.signingPublicKeySpki(), Base64.NO_WRAP)
        mapOf(
            "installationId" to installationId,
            "signingPublicKeySpki" to pubB64,
            "platform" to "android",
        )
    }

    fun secureRequest(path: String, body: Map<String, Any?>): Result<SecureResponse> = runCatching {
        val ctx = appContext ?: error("init(context) required")
        val spki = serverSpki ?: error("configureServerPublicKey first")
        val signer = keystoreSigner ?: AndroidKeystoreSigner().also { keystoreSigner = it }
        val plain = bodyToJsonBytes(body)
        val (host, p) = parseHostAndPath(path)
        val risk = getSecurityStatus().riskScore
        val env = HybridEnvelope.build(
            method = "POST",
            host = host,
            contentType = "application/json",
            riskScore = risk,
            path = p,
            plaintext = plain,
            serverPublicSpki = spki,
            signer = signer,
        )
        SecureResponse(
            statusCode = 200,
            headers = mapOf("Content-Type" to "application/json"),
            body = env,
        )
    }

    fun sign(data: ByteArray): Result<ByteArray> = runCatching {
        val ctx = appContext ?: error("init(context) required")
        val signer = keystoreSigner ?: AndroidKeystoreSigner().also { keystoreSigner = it }
        signer.sign(data)
    }

    /** Stable installation identifier (encrypted at rest), for registration — not raw ANDROID_ID. */
    fun getDeviceId(): Result<String> = runCatching {
        val ctx = appContext ?: error("init(context) required")
        DeviceIdentity.getOrCreateInstallationId(ctx)
    }

    data class SecurityStatus(
        /** 0..100 (higher = riskier runtime). */
        val riskScore: Int,
        /** Array of stable string codes describing findings. */
        val findings: List<String>,
    )

    fun getSecurityStatus(): SecurityStatus {
        val ctx = appContext
        val findings = mutableListOf<String>()
        var score = 0

        val emulator = isProbablyEmulator()
        if (emulator) {
            findings.add("emulator")
            score += 30
        }

        val rooted = isProbablyRooted()
        if (rooted) {
            findings.add("root")
            score += 45
        }

        val debug = Debug.isDebuggerConnected() || Debug.waitingForDebugger()
        if (debug) {
            findings.add("debugger")
            score += 40
        }

        if (ctx != null && (ctx.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
            findings.add("debuggable_app")
            score += 10
        }

        val hooks = hasHookingIndicators()
        if (hooks) {
            findings.add("hooks")
            score += 50
        }

        return SecurityStatus(
            riskScore = score.coerceIn(0, 100),
            findings = findings.distinct(),
        )
    }

    fun keyManager(): SecureKeyManager? {
        val ctx = appContext ?: return null
        return SecureKeyManager(ctx)
    }

    data class SecureResponse(
        val statusCode: Int,
        val headers: Map<String, String>,
        val body: Map<String, Any?>,
    )

    private fun bodyToJsonBytes(body: Map<String, Any?>): ByteArray {
        val o = JSONObject()
        body.forEach { (k, v) ->
            when (v) {
                null -> o.put(k, JSONObject.NULL)
                is Map<*, *> -> throw IllegalArgumentException("nested maps not supported")
                is List<*> -> o.put(k, org.json.JSONArray(v))
                else -> o.put(k, v)
            }
        }
        return o.toString().toByteArray(Charsets.UTF_8)
    }

    private fun parseHostAndPath(input: String): Pair<String, String> {
        return try {
            val u = URI(input)
            val host = u.host ?: ""
            val path = buildString {
                append(u.rawPath ?: "")
                if (!u.rawQuery.isNullOrBlank()) append("?").append(u.rawQuery)
            }.ifBlank { input }
            host to path
        } catch (_: Throwable) {
            "" to input
        }
    }

    private fun isProbablyEmulator(): Boolean {
        val fingerprint = Build.FINGERPRINT.lowercase()
        val model = Build.MODEL.lowercase()
        val manufacturer = Build.MANUFACTURER.lowercase()
        val brand = Build.BRAND.lowercase()
        val device = Build.DEVICE.lowercase()
        val product = Build.PRODUCT.lowercase()

        return fingerprint.startsWith("generic") ||
            fingerprint.contains("vbox") ||
            fingerprint.contains("test-keys") ||
            model.contains("google_sdk") ||
            model.contains("emulator") ||
            model.contains("android sdk built for") ||
            manufacturer.contains("genymotion") ||
            brand.startsWith("generic") && device.startsWith("generic") ||
            product.contains("sdk") ||
            product.contains("emulator") ||
            product.contains("simulator")
    }

    private fun isProbablyRooted(): Boolean {
        // Fast heuristics; no single check is definitive.
        val tags = Build.TAGS ?: ""
        if (tags.contains("test-keys")) return true

        val paths = arrayOf(
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su",
        )
        if (paths.any { File(it).exists() }) return true

        return try {
            val p = Runtime.getRuntime().exec(arrayOf("su", "-c", "id"))
            val rc = p.waitFor()
            rc == 0
        } catch (_: Throwable) {
            false
        }
    }

    private fun hasHookingIndicators(): Boolean {
        // Look for known strings in loaded memory mappings (Frida/Xposed/Substrate).
        return try {
            val maps = File("/proc/self/maps")
            if (!maps.exists()) return false
            val txt = maps.readText()
            val t = txt.lowercase()
            t.contains("frida") ||
                t.contains("gadget") && t.contains("frida") ||
                t.contains("xposed") ||
                t.contains("substrate") ||
                t.contains("libhook") ||
                t.contains("magisk")
        } catch (_: Throwable) {
            false
        }
    }
}
