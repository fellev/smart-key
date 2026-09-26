package com.example.smart_key.ble

import android.annotation.SuppressLint
import android.bluetooth.BluetoothManager
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.BluetoothLeAdvertiser
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.util.Log
import com.example.smart_key.data.Credential
import com.example.smart_key.protocol.SmartKeyAdvertisement
import com.example.smart_key.protocol.SmartKeyCrypto
import com.example.smart_key.protocol.SmartKeyProtocol

/**
 * Broadcasts the rolling presence beacon (protocol-spec.md §2.1, §2.2).
 *
 * The phone advertises rather than scans: Android throttles background
 * scanning, which would make the "< 1 s LED" requirement impossible, while
 * advertising from a foreground service runs at the requested rate.
 *
 * The payload is rebuilt whenever the 15 s pseudonym epoch changes, so the
 * beacon stays unlinkable.
 */
@SuppressLint("MissingPermission") // checked by PresenceService before starting
class SmartKeyAdvertiser(context: Context) {

    private val advertiser: BluetoothLeAdvertiser? =
        (context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager)
            .adapter?.bluetoothLeAdvertiser

    private val handler = Handler(Looper.getMainLooper())
    private var credentials: List<Credential> = emptyList()
    private var currentEpoch = -1L
    private var running = false
    private var doorEpoch: DoorEpoch? = null

    private class DoorEpoch(
        val credential: Credential,
        val epoch: Long,
        val receivedAtMs: Long
    )

    /** Extra state bits folded into the beacon flags. */
    var screenOn: Boolean = true
    var deviceUnlocked: Boolean = true
    var batteryPercent: Int = SmartKeyProtocol.BATTERY_UNKNOWN

    private val callback = object : AdvertiseCallback() {
        override fun onStartFailure(errorCode: Int) {
            Log.e(TAG, "advertising failed to start, error $errorCode")
        }
    }

    /** Refresh the epoch ticker whenever the beacon must change. */
    private val ticker = object : Runnable {
        override fun run() {
            if (!running) return
            val epoch = currentDoorEpoch()
            if (epoch != currentEpoch) {
                currentEpoch = epoch
                restartAdvertising(epoch)
            }
            handler.postDelayed(this, TICK_MS)
        }
    }

    /**
     * Start (or update) advertising for the given credentials.
     *
     * A legacy advertisement can only carry one pseudonym, so with several
     * paired doors the beacons are rotated: each door sees its own pseudonym
     * within a couple of advertising intervals, which is still far inside the
     * timing budget.
     */
    fun start(credentials: List<Credential>) {
        this.credentials = credentials
        doorEpoch = doorEpoch?.takeIf { target ->
            credentials.any { it.lockId.contentEquals(target.credential.lockId) }
        }
        if (credentials.isEmpty()) {
            stop()
            return
        }
        if (advertiser == null) {
            Log.e(TAG, "this device cannot advertise over BLE")
            return
        }
        running = true
        currentEpoch = -1
        handler.removeCallbacks(ticker)
        handler.post(ticker)
    }

    /** Target the saved door that supplied [epoch], advancing it by elapsed time. */
    fun setDoorEpoch(credential: Credential, epoch: Long) {
        doorEpoch = DoorEpoch(credential, epoch, SystemClock.elapsedRealtime())
        currentEpoch = -1L
    }

    fun stop() {
        running = false
        handler.removeCallbacks(ticker)
        runCatching { advertiser?.stopAdvertising(callback) }
        Log.i(TAG, "advertising stopped")
    }

    /** Rebuild the payload and restart the advertisement. */
    private fun restartAdvertising(epoch: Long) {
        val credential = doorEpoch?.credential ?: credentials.firstOrNull() ?: return
        runCatching { advertiser?.stopAdvertising(callback) }

        val beacon = SmartKeyAdvertisement.forEpoch(
            kBeacon = credential.kBeacon,
            epoch = epoch,
            screenOn = screenOn,
            deviceUnlocked = deviceUnlocked,
            batteryPercent = batteryPercent
        )

        val settings = AdvertiseSettings.Builder()
            // LOW_LATENCY ~100 ms interval: the door unit must see us quickly.
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_MEDIUM)
            .setConnectable(true)
            .setTimeout(0)
            .build()

        val data = AdvertiseData.Builder()
            .setIncludeDeviceName(false)
            .setIncludeTxPowerLevel(false)
            .addManufacturerData(
                SmartKeyProtocol.MANUFACTURER_ID,
                beacon.toManufacturerData()
            )
            .build()

        advertiser?.startAdvertising(settings, data, callback)
        Log.d(TAG, "advertising epoch $epoch for lock ${credential.shortId}")
    }

    private fun currentDoorEpoch(): Long {
        val target = doorEpoch ?: return SmartKeyCrypto.currentEpoch()
        val elapsedEpochs =
            (SystemClock.elapsedRealtime() - target.receivedAtMs) /
                (SmartKeyCrypto.BEACON_EPOCH_SECONDS * 1000)
        return target.epoch + elapsedEpochs
    }

    companion object {
        private const val TAG = "SmartKeyAdvertiser"
        /** Poll a bit faster than the epoch so the switch is never late. */
        private const val TICK_MS = 1000L
    }
}
