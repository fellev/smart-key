package com.example.smart_key.ble

import android.Manifest
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.util.Log
import androidx.core.content.ContextCompat
import com.example.smart_key.data.CredentialStore

/**
 * Automatically starts the [PresenceService] after device boot or app update
 * if all required permissions are granted and paired doors exist.
 */
class BootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action !in listOf(Intent.ACTION_BOOT_COMPLETED, Intent.ACTION_MY_PACKAGE_REPLACED)) {
            return
        }

        Log.i(TAG, "received ${intent.action}, checking permissions and paired doors")

        val requiredPermissions = listOf(
            Manifest.permission.BLUETOOTH_ADVERTISE,
            Manifest.permission.BLUETOOTH_CONNECT,
            Manifest.permission.BLUETOOTH_SCAN,
            Manifest.permission.POST_NOTIFICATIONS,
        )

        val hasPermissions = requiredPermissions.all {
            ContextCompat.checkSelfPermission(context, it) == PackageManager.PERMISSION_GRANTED
        }

        if (!hasPermissions) {
            Log.w(TAG, "boot completed but missing required permissions")
            return
        }

        val hasDoors = CredentialStore(context.applicationContext).all().isNotEmpty()
        if (!hasDoors) {
            Log.i(TAG, "boot completed but no paired doors found")
            return
        }

        Log.i(TAG, "starting PresenceService on boot")
        PresenceService.start(context.applicationContext)
    }

    companion object {
        private const val TAG = "BootReceiver"
    }
}
