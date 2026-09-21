package com.example.smart_key.pairing

import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.util.Log
import com.example.smart_key.protocol.Frame
import com.example.smart_key.protocol.SmartKeyProtocol

/**
 * Drives one pairing attempt over BLE (pairing-spec.md §1-2).
 *
 * Here the roles are reversed compared to normal operation: the door unit
 * advertises a pairing beacon and acts as GATT server, and the phone is the
 * central that connects to it.
 */
@SuppressLint("MissingPermission") // the UI requests the permissions first
class PairingClient(
    private val context: Context,
    private val session: PairingSession,
    private val listener: Listener
) {
    interface Listener {
        fun onProgress(message: String)
        fun onSuccess(lockId: ByteArray, ltk: ByteArray, slot: Int)
        fun onFailure(message: String)
    }

    private val adapter =
        (context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager).adapter
    private val handler = Handler(Looper.getMainLooper())

    private var gatt: BluetoothGatt? = null
    private var pairingCharacteristic: BluetoothGattCharacteristic? = null
    private var finished = false

    private val timeout = Runnable {
        fail("Timed out looking for a door unit in pairing mode")
    }

    /** Scan for a pairing beacon, then run the exchange. */
    fun start() {
        val scanner = adapter?.bluetoothLeScanner ?: run {
            fail("Bluetooth is not available")
            return
        }
        listener.onProgress("Looking for a door unit in pairing mode...")

        // Match only SmartKey pairing beacons: magic, version, PAIRING_BEACON flag.
        val mask = byteArrayOf(0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte())
        val prefix = byteArrayOf(
            SmartKeyProtocol.ADV_MAGIC,
            SmartKeyProtocol.VERSION,
            SmartKeyProtocol.FLAG_PAIRING_BEACON.toByte()
        )
        val filter = ScanFilter.Builder()
            .setManufacturerData(SmartKeyProtocol.MANUFACTURER_ID, prefix, mask)
            .build()
        val settings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            .build()

        scanner.startScan(listOf(filter), settings, scanCallback)
        handler.postDelayed(timeout, TIMEOUT_MS)
    }

    fun cancel() {
        cleanUp()
        session.cancel()
    }

    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            if (finished) return
            stopScan()
            listener.onProgress("Door unit found, connecting...")
            gatt = result.device.connectGatt(
                context, false, gattCallback, BluetoothDevice.TRANSPORT_LE
            )
        }

        override fun onScanFailed(errorCode: Int) {
            fail("Bluetooth scan failed (error $errorCode)")
        }
    }

    private val gattCallback = object : BluetoothGattCallback() {

        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                gatt.requestMtu(SmartKeyProtocol.MAX_FRAME + 3)
            } else if (!finished) {
                fail("Lost the connection to the door unit")
            }
        }

        override fun onMtuChanged(gatt: BluetoothGatt, mtu: Int, status: Int) {
            gatt.discoverServices()
        }

        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            val characteristic = gatt.getService(SmartKeyProtocol.SERVICE_UUID)
                ?.getCharacteristic(SmartKeyProtocol.PAIRING_UUID)
            if (characteristic == null) {
                fail("This device is not a SmartKey door unit")
                return
            }
            pairingCharacteristic = characteristic

            // Subscribe before sending anything, so no reply can be missed.
            gatt.setCharacteristicNotification(characteristic, true)
            val cccd = characteristic.getDescriptor(SmartKeyProtocol.CCCD_UUID)
            if (cccd != null) {
                gatt.writeDescriptor(cccd, BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE)
            } else {
                send(session.start())
            }
        }

        override fun onDescriptorWrite(
            gatt: BluetoothGatt,
            descriptor: BluetoothGattDescriptor,
            status: Int
        ) {
            listener.onProgress("Exchanging keys...")
            send(session.start())
        }

        override fun onCharacteristicChanged(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            value: ByteArray
        ) {
            handleStep(session.onFrame(value))
        }
    }

    /** Act on one step of the pairing state machine. */
    private fun handleStep(step: PairingSession.Step) {
        when (step) {
            is PairingSession.Step.Send -> {
                listener.onProgress("Confirming the pairing code...")
                send(step.frame)
            }
            is PairingSession.Step.Success -> {
                handler.removeCallbacks(timeout)
                finished = true
                listener.onSuccess(step.lockId, step.ltk, step.slot)
                cleanUp()
            }
            is PairingSession.Step.Failure -> fail(step.message)
            PairingSession.Step.Waiting -> Unit
        }
    }

    private fun send(frame: Frame) {
        val characteristic = pairingCharacteristic ?: return
        gatt?.writeCharacteristic(
            characteristic,
            frame.encode(),
            BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
        )
    }

    private fun fail(message: String) {
        if (finished) return
        finished = true
        Log.w(TAG, "pairing failed: $message")
        listener.onFailure(message)
        session.cancel()
        cleanUp()
    }

    private fun stopScan() {
        runCatching { adapter?.bluetoothLeScanner?.stopScan(scanCallback) }
    }

    private fun cleanUp() {
        handler.removeCallbacks(timeout)
        stopScan()
        runCatching {
            gatt?.disconnect()
            gatt?.close()
        }
        gatt = null
        pairingCharacteristic = null
    }

    companion object {
        private const val TAG = "PairingClient"
        private const val TIMEOUT_MS = 30_000L
    }
}
