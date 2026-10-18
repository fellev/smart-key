package com.example.smart_key.data

import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL

object HomeAssistantClient {

    fun validate(config: HomeAssistantConfig) {
        require(config.baseUrl.isNotBlank()) { "Home Assistant URL is required" }
        require(config.token.isNotBlank()) { "Home Assistant token is required" }
        require(config.entityId.matches(ENTITY_ID_PATTERN)) { "Enter a valid entity ID" }
        require(config.service.matches(SERVICE_PATTERN)) {
            "Service must be in domain/service format"
        }
        val uri = URI.create(config.baseUrl)
        require(uri.scheme == "https" && uri.host != null && uri.userInfo == null &&
            uri.rawQuery == null && uri.rawFragment == null) {
            "Use a valid HTTPS Home Assistant URL"
        }
    }

    fun callService(config: HomeAssistantConfig) {
        validate(config)
        val (domain, service) = config.service.split('/')
        val url = URL("${config.baseUrl.trimEnd('/')}/api/services/$domain/$service")
        val connection = url.openConnection() as HttpURLConnection
        try {
            connection.requestMethod = "POST"
            connection.connectTimeout = TIMEOUT_MS
            connection.readTimeout = TIMEOUT_MS
            connection.doOutput = true
            connection.setRequestProperty("Authorization", "Bearer ${config.token}")
            connection.setRequestProperty("Content-Type", "application/json")
            connection.outputStream.bufferedWriter(Charsets.UTF_8).use { writer ->
                writer.write(JSONObject().put("entity_id", config.entityId).toString())
            }
            val status = connection.responseCode
            if (status !in 200..299) {
                throw IOException("Home Assistant returned HTTP $status")
            }
        } finally {
            connection.disconnect()
        }
    }

    private const val TIMEOUT_MS = 10_000
    private val SERVICE_PATTERN = Regex("^[a-z_]+/[a-z_]+$")
    private val ENTITY_ID_PATTERN = Regex("^[a-z0-9_]+\\.[a-z0-9_]+$")
}