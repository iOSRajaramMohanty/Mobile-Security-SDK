package com.bankingsdk.security.rn

import com.bankingsdk.security.SecuritySdk
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import okhttp3.CertificatePinner
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import android.util.Base64
import org.json.JSONObject
import java.net.URL
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class SecureSDKModule(reactContext: ReactApplicationContext) :
    ReactContextBaseJavaModule(reactContext) {

    override fun getName(): String = "SecureSDK"

    private val maxBodyChars = 256 * 1024
    private val maxKeyChars = 8 * 1024
    @Volatile private var pinnedHost: String? = null
    @Volatile private var pinnedPins: List<String> = emptyList() // base64 pins (no sha256/ prefix)

    private fun rejectSafe(promise: Promise, code: String, t: Throwable?) {
        // Do not pass raw exceptions / stacks to JS.
        val msg = t?.message ?: "failed"
        promise.reject(code, msg, null)
    }

    @ReactMethod
    fun initialize(promise: Promise) {
        val result = SecuritySdk.init(reactApplicationContext.applicationContext)
        result.fold(
            onSuccess = { promise.resolve(null) },
            onFailure = { rejectSafe(promise, "E_INIT", it) },
        )
    }

    @ReactMethod
    fun getPublicKey(promise: Promise) {
        val result = SecuritySdk.getPublicKey()
        result.fold(
            onSuccess = { promise.resolve(it) },
            onFailure = { rejectSafe(promise, "E_PUBLIC_KEY", it) },
        )
    }

    @ReactMethod
    fun rotateKeys(promise: Promise) {
        val result = SecuritySdk.rotateKeys()
        result.fold(
            onSuccess = { promise.resolve(null) },
            onFailure = { rejectSafe(promise, "E_ROTATE", it) },
        )
    }

    @ReactMethod
    fun getDeviceRegistrationPayload(promise: Promise) {
        val result = SecuritySdk.getDeviceRegistrationPayload()
        result.fold(
            onSuccess = { map ->
                val o = JSONObject()
                map.forEach { (k, v) -> o.put(k, v) }
                promise.resolve(o.toString())
            },
            onFailure = { rejectSafe(promise, "E_REG", it) },
        )
    }

    @ReactMethod
    fun configureServerPublicKey(base64: String, promise: Promise) {
        if (base64.isBlank() || base64.length > maxKeyChars) {
            promise.reject("E_CONFIG", "invalid server public key", null)
            return
        }
        val result = SecuritySdk.configureServerPublicKeyFromBase64(base64)
        result.fold(
            onSuccess = { promise.resolve(null) },
            onFailure = { rejectSafe(promise, "E_CONFIG", it) },
        )
    }

    @ReactMethod
    fun configurePinning(configJson: String, promise: Promise) {
        if (configJson.length > maxBodyChars) {
            promise.reject("E_PIN", "config too large", null)
            return
        }
        val obj = try { JSONObject(configJson) } catch (_: Throwable) {
            promise.reject("E_PIN", "invalid JSON", null)
            return
        }
        val host = obj.optString("host", "").trim()
        val pinsArr = obj.optJSONArray("pins")
        if (host.isBlank() || pinsArr == null || pinsArr.length() == 0) {
            promise.reject("E_PIN", "invalid pinning config", null)
            return
        }
        val pins = mutableListOf<String>()
        for (i in 0 until pinsArr.length()) {
            val p = pinsArr.optString(i, "").trim()
            if (p.isBlank() || p.length > maxKeyChars) {
                promise.reject("E_PIN", "invalid pin", null)
                return
            }
            pins.add(p)
        }
        pinnedHost = host
        pinnedPins = pins
        promise.resolve(null)
    }

    @ReactMethod
    fun pinnedPost(url: String, headersJson: String, bodyJson: String, promise: Promise) {
        if (url.isBlank()) {
            promise.reject("E_HTTP", "invalid url", null)
            return
        }
        if (headersJson.length > maxBodyChars || bodyJson.length > maxBodyChars) {
            promise.reject("E_HTTP", "payload too large", null)
            return
        }
        try {
            val res = doPinnedPost(url, headersJson, bodyJson)
            promise.resolve(res)
        } catch (t: Throwable) {
            rejectSafe(promise, "E_HTTP", t)
        }
    }

    @ReactMethod
    fun secureRequestPinned(url: String, bodyJson: String, stepUpToken: String?, promise: Promise) {
        if (url.isBlank()) {
            promise.reject("E_REQUEST", "invalid url", null)
            return
        }
        if (bodyJson.length > maxBodyChars) {
            promise.reject("E_REQUEST", "body too large", null)
            return
        }
        val bodyObj = try { JSONObject(bodyJson) } catch (_: Throwable) {
            promise.reject("E_REQUEST", "invalid JSON body", null)
            return
        }
        val bodyMap = jsonObjectToMap(bodyObj)
        val env = SecuritySdk.secureRequest(url, bodyMap)
        env.fold(
            onSuccess = { secureRes ->
                val out = JSONObject()
                out.put("statusCode", secureRes.statusCode)
                val headersOut = JSONObject()
                secureRes.headers.forEach { (k, v) -> headersOut.put(k, v) }
                out.put("headers", headersOut)
                // Extract local-only DEK and strip it before network forwarding.
                val dekB64 = (secureRes.body["_clientDek"] as? String)?.trim()
                val bodyFiltered = secureRes.body.toMutableMap().also { it.remove("_clientDek") }
                out.put("body", mapToJsonObject(bodyFiltered))
                try {
                    val headers = JSONObject()
                    headers.put("Content-Type", "application/json")
                    if (!stepUpToken.isNullOrBlank()) headers.put("X-StepUp-Token", stepUpToken)
                    val raw = doPinnedPost(url, headers.toString(), out.toString())
                    // Expect encrypted gateway response; decrypt locally and return plaintext SecureResponse shape.
                    val rawObj = JSONObject(raw)
                    val ok = rawObj.optBoolean("ok", false)
                    if (!ok) {
                        promise.resolve(raw) // pass through error JSON
                        return@fold
                    }
                    val enc = rawObj.optJSONObject("enc")
                    if (enc == null || dekB64.isNullOrBlank()) {
                        promise.resolve(raw)
                        return@fold
                    }
                    val plain = decryptAesGcm(
                        dekB64,
                        enc.optString("aesIv", ""),
                        enc.optString("ciphertext", ""),
                        enc.optString("aesTag", ""),
                    )
                    val resp = JSONObject()
                    resp.put("statusCode", rawObj.optInt("statusCode", 200))
                    resp.put("headers", rawObj.optJSONObject("headers") ?: JSONObject())
                    resp.put("body", JSONObject(plain))
                    promise.resolve(resp.toString())
                } catch (t: Throwable) {
                    rejectSafe(promise, "E_REQUEST", t)
                }
            },
            onFailure = { rejectSafe(promise, "E_REQUEST", it) },
        )
    }

    @ReactMethod
    fun signStepUp(message: String, promise: Promise) {
        if (message.length > maxBodyChars) {
            promise.reject("E_SIGN", "message too large", null)
            return
        }
        val res = SecuritySdk.sign(message.toByteArray(Charsets.UTF_8))
        res.fold(
            onSuccess = { sig ->
                promise.resolve(Base64.encodeToString(sig, Base64.NO_WRAP))
            },
            onFailure = { rejectSafe(promise, "E_SIGN", it) },
        )
    }

    @ReactMethod
    fun secureRequest(path: String, bodyJson: String, promise: Promise) {
        if (path.isBlank()) {
            promise.reject("E_REQUEST", "invalid path", null)
            return
        }
        if (bodyJson.length > maxBodyChars) {
            promise.reject("E_REQUEST", "body too large", null)
            return
        }
        val bodyObj = try {
            JSONObject(bodyJson)
        } catch (_: Throwable) {
            promise.reject("E_REQUEST", "invalid JSON body", null)
            return
        }
        val bodyMap = jsonObjectToMap(bodyObj)
        val result = SecuritySdk.secureRequest(path, bodyMap)
        result.fold(
            onSuccess = { res ->
                val out = JSONObject()
                out.put("statusCode", res.statusCode)
                val headersJson = JSONObject()
                res.headers.forEach { (k, v) -> headersJson.put(k, v) }
                out.put("headers", headersJson)
                out.put("body", mapToJsonObject(res.body))
                promise.resolve(out.toString())
            },
            onFailure = { rejectSafe(promise, "E_REQUEST", it) },
        )
    }

    @ReactMethod
    fun getDeviceId(promise: Promise) {
        val result = SecuritySdk.getDeviceId()
        result.fold(
            onSuccess = { promise.resolve(it) },
            onFailure = { rejectSafe(promise, "E_DEVICE_ID", it) },
        )
    }

    @ReactMethod
    fun getSecurityStatus(promise: Promise) {
        val s = SecuritySdk.getSecurityStatus()
        val out = JSONObject()
        out.put("riskScore", s.riskScore)
        out.put("findings", org.json.JSONArray(s.findings))
        promise.resolve(out.toString())
    }

    private fun jsonObjectToMap(obj: JSONObject): Map<String, Any?> {
        val map = mutableMapOf<String, Any?>()
        val keys = obj.keys()
        while (keys.hasNext()) {
            val k = keys.next()
            map[k] = obj.get(k).takeUnless { it === JSONObject.NULL }
        }
        return map
    }

    private fun mapToJsonObject(body: Map<String, Any?>): JSONObject {
        val o = JSONObject()
        body.forEach { (k, v) ->
            when (v) {
                null -> o.put(k, JSONObject.NULL)
                is Map<*, *> -> o.put(k, mapToJsonObject(v as Map<String, Any?>))
                is Long -> o.put(k, v)
                is Int -> o.put(k, v)
                is Double -> o.put(k, v)
                is Float -> o.put(k, v.toDouble())
                is Boolean -> o.put(k, v)
                is String -> o.put(k, v)
                else -> o.put(k, v.toString())
            }
        }
        return o
    }

    private fun buildPinnedClient(host: String, pins: List<String>): OkHttpClient {
        val pinnerBuilder = CertificatePinner.Builder()
        pins.forEach { pin ->
            // OkHttp expects `sha256/<base64>`
            pinnerBuilder.add(host, "sha256/$pin")
        }
        return OkHttpClient.Builder()
            .certificatePinner(pinnerBuilder.build())
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(15, TimeUnit.SECONDS)
            .build()
    }

    private fun doPinnedPost(url: String, headersJson: String, bodyJson: String): String {
        val host = pinnedHost ?: throw IllegalStateException("pinning not configured")
        val pins = pinnedPins
        if (pins.isEmpty()) throw IllegalStateException("pinning not configured")

        val parsed = URL(url)
        if (!parsed.protocol.equals("https", ignoreCase = true)) throw IllegalArgumentException("https required")
        if (!parsed.host.equals(host, ignoreCase = true)) throw IllegalArgumentException("host mismatch")

        val headersObj = try { JSONObject(headersJson) } catch (_: Throwable) { JSONObject() }
        val reqBuilder = Request.Builder().url(url)
        val keys = headersObj.keys()
        while (keys.hasNext()) {
            val k = keys.next()
            val v = headersObj.optString(k, "")
            if (k.isNotBlank() && v.isNotBlank()) reqBuilder.addHeader(k, v)
        }

        val media = "application/json; charset=utf-8".toMediaType()
        val req = reqBuilder.post(bodyJson.toRequestBody(media)).build()
        val client = buildPinnedClient(host, pins)
        client.newCall(req).execute().use { resp ->
            val body = resp.body?.string() ?: ""
            if (!resp.isSuccessful) throw IllegalStateException("http_${resp.code}")
            return body
        }
    }

    private fun decryptAesGcm(keyB64: String, ivB64: String, ctB64: String, tagB64: String): String {
        val key = Base64.decode(keyB64, Base64.NO_WRAP)
        val iv = Base64.decode(ivB64, Base64.NO_WRAP)
        val ct = Base64.decode(ctB64, Base64.NO_WRAP)
        val tag = Base64.decode(tagB64, Base64.NO_WRAP)
        val combined = ByteArray(ct.size + tag.size)
        System.arraycopy(ct, 0, combined, 0, ct.size)
        System.arraycopy(tag, 0, combined, ct.size, tag.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
        val plain = cipher.doFinal(combined)
        return String(plain, Charsets.UTF_8)
    }
}
