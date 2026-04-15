package com.bankingsdk.security

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.util.UUID

/**
 * Stable installation identity for device registration (not raw ANDROID_ID).
 */
internal object DeviceIdentity {
    private const val PREFS = "banking_sdk_secure_prefs"
    private const val KEY_INSTALLATION_ID = "installation_id"

    private fun prefs(context: Context): SharedPreferences {
        val masterKey = MasterKey.Builder(context.applicationContext)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        return EncryptedSharedPreferences.create(
            context.applicationContext,
            PREFS,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    }

    fun getOrCreateInstallationId(context: Context): String {
        val p = prefs(context)
        val existing = p.getString(KEY_INSTALLATION_ID, null)
        if (existing != null) return existing
        val id = UUID.randomUUID().toString()
        p.edit().putString(KEY_INSTALLATION_ID, id).apply()
        return id
    }
}
