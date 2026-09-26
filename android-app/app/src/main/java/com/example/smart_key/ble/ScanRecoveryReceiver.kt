package com.example.smart_key.ble

import android.bluetooth.le.BluetoothLeScanner
import android.bluetooth.le.ScanResult
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log
import androidx.core.content.ContextCompat
import com.example.smart_key.data.CredentialStore
import com.example.smart_key.protocol.DoorBeacon
import com.example.smart_key.protocol.SmartKeyProtocol

/**
 * Wakes the presence service when a door beacon is seen.
 *
 * Delivered by the Bluetooth stack via a `PendingIntent` scan registered in
 * [ScanRecovery], so it still arrives after our process has been killed —
 * which is exactly the situation it is meant to repair.
 *
 * Deliberately minimal: validate, start the service, return. Any real work
 * here would run on the main thread of a cold-started process.
 */
class ScanRecoveryReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != ACTION_DOOR_SEEN) return

        val errorCode = intent.getIntExtra(BluetoothLeScanner.EXTRA_ERROR_CODE, -1)
        if (errorCode != -1) {
            // The registration itself failed (commonly: Bluetooth turned off).
            Log.w(TAG, "recovery scan reported error $errorCode")
            return
        }

        val beacon = findDoorBeacon(intent) ?: return

        // Only act if the user actually has a door paired, otherwise the
        // service would immediately stop itself again.
        val paired = CredentialStore(context.applicationContext).all().any {
            it.lockId.copyOfRange(0, SmartKeyProtocol.DOOR_ID_SIZE).contentEquals(beacon.lockId)
        }
        if (!paired) {
            Log.d(TAG, "unpaired door beacon seen, ignoring")
            return
        }

        // Two distinct jobs, both delivered by the same broadcast:
        //
        //  - service stopped  -> this is the recovery case, start it;
        //  - service running  -> this is listen-first detection, tell it to
        //                        break radio silence.
        //
        // Both are a startForegroundService() with a different action, so a
        // cold start and a warm notification take the same path.
        Log.i(TAG, "door beacon seen, sending ${PresenceService.ACTION_DOOR_SEEN}")

        val start = Intent(context, PresenceService::class.java).apply {
            action = PresenceService.ACTION_DOOR_SEEN
            putExtra(PresenceService.EXTRA_DOOR_ID_PREFIX, beacon.lockId)
            putExtra(PresenceService.EXTRA_DOOR_EPOCH, beacon.localEpoch)
        }
        ContextCompat.startForegroundService(context.applicationContext, start)
    }

    /**
     * Confirm the broadcast really carries a SmartKey door beacon.
     *
     * The offloaded filter already matched magic + version, but the results
     * are re-parsed here rather than trusted: a malformed or spoofed
     * advertisement must not be able to drive our service lifecycle.
     */
    private fun findDoorBeacon(intent: Intent): DoorBeacon? {
        val results = extractResults(intent) ?: return null
        for (result in results) {
            val raw = result.scanRecord
                ?.getManufacturerSpecificData(SmartKeyProtocol.MANUFACTURER_ID)
                ?: continue
            DoorBeacon.parseWithoutCompanyId(raw)?.let { return it }
        }
        return null
    }

    @Suppress("DEPRECATION")
    private fun extractResults(intent: Intent): List<ScanResult>? =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getParcelableArrayListExtra(
                BluetoothLeScanner.EXTRA_LIST_SCAN_RESULT,
                ScanResult::class.java
            )
        } else {
            intent.getParcelableArrayListExtra(BluetoothLeScanner.EXTRA_LIST_SCAN_RESULT)
        }

    companion object {
        private const val TAG = "ScanRecoveryRx"
        const val ACTION_DOOR_SEEN = "com.example.smart_key.DOOR_SEEN"
    }
}
