package com.example.smart_key.data

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

data class HomeAssistantConfig(
    val baseUrl: String,
    val token: String,
    val service: String,
    val entityId: String
)

class HomeAssistantSettings(context: Context) {

    private val prefs by lazy {
        val masterKey = MasterKey.Builder(context.applicationContext)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        EncryptedSharedPreferences.create(
            context.applicationContext,
            PREFS_NAME,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    fun load(): HomeAssistantConfig? {
        val baseUrl = prefs.getString(KEY_BASE_URL, null) ?: return null
        val token = prefs.getString(KEY_TOKEN, null) ?: return null
        val service = prefs.getString(KEY_SERVICE, null) ?: return null
        val entityId = prefs.getString(KEY_ENTITY_ID, null) ?: return null
        return HomeAssistantConfig(baseUrl, token, service, entityId)
    }

    fun save(config: HomeAssistantConfig) {
        prefs.edit()
            .putString(KEY_BASE_URL, config.baseUrl)
            .putString(KEY_TOKEN, config.token)
            .putString(KEY_SERVICE, config.service)
            .putString(KEY_ENTITY_ID, config.entityId)
            .apply()
    }

    private companion object {
        const val PREFS_NAME = "home_assistant_settings"
        const val KEY_BASE_URL = "base_url"
        const val KEY_TOKEN = "access_token"
        const val KEY_SERVICE = "service"
        const val KEY_ENTITY_ID = "entity_id"
    }
}