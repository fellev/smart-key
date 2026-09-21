package com.example.smart_key.data

import android.content.Context
import com.example.smart_key.ble.PresenceMode

/**
 * User preferences that are not secret.
 *
 * Deliberately plain [android.content.SharedPreferences] rather than the
 * encrypted store used for credentials: nothing here is key material, and
 * keeping it separate means reading a preference cannot fail because the
 * Keystore is unavailable.
 */
class Settings(context: Context) {

    private val prefs = context.applicationContext
        .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    /**
     * How the phone announces itself.
     *
     * Defaults to [PresenceMode.LISTEN_FIRST] so the phone stays radio-silent
     * until it actually hears a door. Users who want the sub-second LED
     * guarantee back can switch to [PresenceMode.ALWAYS_ADVERTISE].
     */
    var presenceMode: PresenceMode
        get() = runCatching {
            PresenceMode.valueOf(
                prefs.getString(KEY_PRESENCE_MODE, null) ?: DEFAULT_MODE.name
            )
        }.getOrDefault(DEFAULT_MODE)
        set(value) {
            prefs.edit().putString(KEY_PRESENCE_MODE, value.name).apply()
        }

    companion object {
        private const val PREFS_NAME = "smartkey_settings"
        private const val KEY_PRESENCE_MODE = "presence_mode"

        val DEFAULT_MODE = PresenceMode.LISTEN_FIRST
    }
}
