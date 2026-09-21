package com.example.smart_key.ble

import android.Manifest
import android.annotation.SuppressLint
import android.app.PendingIntent
import android.bluetooth.BluetoothManager
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import androidx.core.content.ContextCompat
import com.example.smart_key.protocol.DoorBeacon
import com.example.smart_key.protocol.SmartKeyProtocol

/**
 * System-mediated listening for door beacons.
 *
 * Serves two purposes, both built on the same registration:
 *
 *  1. **Recovery** — restart [PresenceService] after the OS has killed it.
 *  2. **Listen-first detection** — in [PresenceMode.LISTEN_FIRST] this is the
 *     *only* thing running while no door is near, which is what lets the phone
 *     transmit nothing at all until a door is actually heard.
 *
 * ## Why this exists
 *
 * [PresenceService] is a foreground service, but that is not an absolute
 * guarantee: aggressive vendor battery managers (notably Samsung's "Deep
 * Sleeping" list) stop apps anyway. When that happens presence silently dies
 * and the user has to reopen the app by hand — the failure is invisible until
 * you are standing at a door that will not light up.
 *
 * This registers a *system-mediated* scan for the door's static beacon. The
 * registration lives in the Bluetooth stack rather than in our process, so it
 * survives our process being killed, and Android delivers a broadcast when a
 * door is seen. The receiver then restarts the service.
 *
 * ## Why it is not the fast path
 *
 * A low-power scan plus broadcast dispatch takes seconds — far outside the
 * sub-second LED budget. This is a safety net, not the mechanism: the normal
 * flow is still the door connecting to the phone's advertisement.
 *
 * ## Why it costs almost no battery
 *
 * The filter matches a fixed byte pattern (magic + version), so it is
 * eligible for hardware offloading into the Bluetooth controller. Between
 * matches the application processor stays asleep.
 */
object ScanRecovery {

    private const val TAG = "ScanRecovery"
    private const val REQUEST_CODE = 42

    /** True when the scan filter can run in the controller rather than the CPU. */
    fun isOffloadSupported(context: Context): Boolean {
        val adapter = context.getSystemService(BluetoothManager::class.java)?.adapter
            ?: return false
        return adapter.isOffloadedFilteringSupported
    }

    /**
     * Register the recovery scan. Safe to call repeatedly: re-registering with
     * the same [PendingIntent] simply replaces the previous request.
     */
    @SuppressLint("MissingPermission")
    fun register(context: Context): Boolean {
        if (!hasScanPermission(context)) {
            Log.w(TAG, "BLUETOOTH_SCAN not granted, recovery scan unavailable")
            return false
        }
        val scanner = context.getSystemService(BluetoothManager::class.java)
            ?.adapter
            ?.bluetoothLeScanner
        if (scanner == null) {
            Log.w(TAG, "no BLE scanner available")
            return false
        }

        val filter = ScanFilter.Builder()
            .setManufacturerData(
                SmartKeyProtocol.MANUFACTURER_ID,
                DoorBeacon.FILTER_DATA,
                DoorBeacon.FILTER_MASK
            )
            .build()

        val settings = ScanSettings.Builder()
            // Latency does not matter here, battery does. Even in listen-first
            // mode this stays LOW_POWER: the door beacon is receivable far
            // beyond LED range, so a slow duty cycle still catches it during
            // the user's approach.
            .setScanMode(ScanSettings.SCAN_MODE_LOW_POWER)
            // FIRST_MATCH plus STICKY means one wake-up per arrival rather
            // than a stream of duplicates while the user stands at the door.
            .setCallbackType(ScanSettings.CALLBACK_TYPE_FIRST_MATCH)
            .setMatchMode(ScanSettings.MATCH_MODE_STICKY)
            .setNumOfMatches(ScanSettings.MATCH_NUM_ONE_ADVERTISEMENT)
            .build()

        return try {
            val result = scanner.startScan(listOf(filter), settings, pendingIntent(context))
            if (result == 0) {
                Log.i(
                    TAG,
                    "recovery scan registered (offloaded=${isOffloadSupported(context)})"
                )
                true
            } else {
                Log.w(TAG, "recovery scan rejected with code $result")
                false
            }
        } catch (e: IllegalStateException) {
            // Bluetooth was turned off between the adapter check and the call.
            Log.w(TAG, "recovery scan could not start: ${e.message}")
            false
        }
    }

    @SuppressLint("MissingPermission")
    fun unregister(context: Context) {
        if (!hasScanPermission(context)) return
        val scanner = context.getSystemService(BluetoothManager::class.java)
            ?.adapter
            ?.bluetoothLeScanner ?: return
        runCatching { scanner.stopScan(pendingIntent(context)) }
    }

    private fun pendingIntent(context: Context): PendingIntent {
        val intent = Intent(context, ScanRecoveryReceiver::class.java).apply {
            action = ScanRecoveryReceiver.ACTION_DOOR_SEEN
        }
        // Must be mutable: the Bluetooth stack fills in the scan results.
        var flags = PendingIntent.FLAG_UPDATE_CURRENT
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            flags = flags or PendingIntent.FLAG_MUTABLE
        }
        return PendingIntent.getBroadcast(
            context.applicationContext,
            REQUEST_CODE,
            intent,
            flags
        )
    }

    private fun hasScanPermission(context: Context): Boolean =
        Build.VERSION.SDK_INT < Build.VERSION_CODES.S ||
            ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.BLUETOOTH_SCAN
            ) == PackageManager.PERMISSION_GRANTED
}
