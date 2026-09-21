package com.example.smart_key.data

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.example.smart_key.protocol.SmartKeyCrypto
import com.example.smart_key.protocol.SmartKeyProtocol
import org.json.JSONArray
import org.json.JSONObject

/**
 * Persistent storage for paired doors (pairing-spec.md §4).
 *
 * Records live in [EncryptedSharedPreferences], which is backed by an
 * AES-256-GCM key held in the Android Keystore, so the key material is
 * encrypted at rest and bound to this device.
 */
class CredentialStore(context: Context) {

    private val prefs: SharedPreferences = run {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        EncryptedSharedPreferences.create(
            context,
            PREFS_NAME,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    /**
     * The stable identity of this phone, shared by every door it pairs with.
     * Generated once on first launch.
     */
    val userId: ByteArray
        get() {
            prefs.getString(KEY_USER_ID, null)?.let { return it.hexToBytes() }
            val fresh = SmartKeyCrypto.randomBytes(SmartKeyProtocol.ID_SIZE)
            prefs.edit().putString(KEY_USER_ID, fresh.toHex()).apply()
            Log.i(TAG, "generated a new user identity")
            return fresh
        }

    /** All paired doors, newest first. */
    fun all(): List<Credential> {
        val raw = prefs.getString(KEY_CREDENTIALS, null) ?: return emptyList()
        return try {
            val array = JSONArray(raw)
            (0 until array.length())
                .map { fromJson(array.getJSONObject(it)) }
                .sortedByDescending { it.pairedAtEpochSeconds }
        } catch (e: Exception) {
            Log.e(TAG, "failed to read stored credentials", e)
            emptyList()
        }
    }

    fun find(lockId: ByteArray): Credential? =
        all().firstOrNull { it.lockId.contentEquals(lockId) }

    /**
     * Store a new credential, derived from the long term key. The caller must
     * wipe [ltk] afterwards: only the sub keys are persisted.
     */
    fun add(lockId: ByteArray, ltk: ByteArray, label: String): Credential {
        val subKeys = SmartKeyCrypto.deriveSubKeys(ltk, lockId, userId)
        val credential = Credential(
            lockId = lockId,
            userId = userId,
            kAuth = subKeys.kAuth,
            kBeacon = subKeys.kBeacon,
            label = label,
            pairedAtEpochSeconds = System.currentTimeMillis() / 1000
        )
        val remaining = all().filterNot { it.lockId.contentEquals(lockId) }
        persist(remaining + credential)
        Log.i(TAG, "stored credential for lock ${credential.shortId}")
        return credential
    }

    fun remove(lockId: ByteArray) {
        persist(all().filterNot { it.lockId.contentEquals(lockId) })
    }

    fun rename(lockId: ByteArray, label: String) {
        persist(
            all().map {
                if (it.lockId.contentEquals(lockId)) {
                    Credential(it.lockId, it.userId, it.kAuth, it.kBeacon, label,
                        it.pairedAtEpochSeconds)
                } else {
                    it
                }
            }
        )
    }

    fun clear() {
        prefs.edit().remove(KEY_CREDENTIALS).apply()
    }

    private fun persist(credentials: List<Credential>) {
        val array = JSONArray()
        credentials.forEach { array.put(toJson(it)) }
        prefs.edit().putString(KEY_CREDENTIALS, array.toString()).apply()
    }

    private fun toJson(credential: Credential) = JSONObject().apply {
        put(FIELD_LOCK_ID, credential.lockId.toHex())
        put(FIELD_USER_ID, credential.userId.toHex())
        put(FIELD_K_AUTH, credential.kAuth.toHex())
        put(FIELD_K_BEACON, credential.kBeacon.toHex())
        put(FIELD_LABEL, credential.label)
        put(FIELD_PAIRED_AT, credential.pairedAtEpochSeconds)
    }

    private fun fromJson(json: JSONObject) = Credential(
        lockId = json.getString(FIELD_LOCK_ID).hexToBytes(),
        userId = json.getString(FIELD_USER_ID).hexToBytes(),
        kAuth = json.getString(FIELD_K_AUTH).hexToBytes(),
        kBeacon = json.getString(FIELD_K_BEACON).hexToBytes(),
        label = json.optString(FIELD_LABEL, "Door"),
        pairedAtEpochSeconds = json.optLong(FIELD_PAIRED_AT, 0)
    )

    companion object {
        private const val TAG = "CredentialStore"
        private const val PREFS_NAME = "smartkey_credentials"
        private const val KEY_USER_ID = "user_id"
        private const val KEY_CREDENTIALS = "credentials"

        private const val FIELD_LOCK_ID = "lock_id"
        private const val FIELD_USER_ID = "user_id"
        private const val FIELD_K_AUTH = "k_auth"
        private const val FIELD_K_BEACON = "k_beacon"
        private const val FIELD_LABEL = "label"
        private const val FIELD_PAIRED_AT = "paired_at"
    }
}
