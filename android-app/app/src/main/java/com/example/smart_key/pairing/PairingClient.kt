package com.example.smart_key.pairing

import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.BluetoothStatusCodes
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
    private var negotiatedMtu = 0

    private val timeout = Runnable {
        fail("Timed out looking for a door unit in pairing mode")
    }

    /** Scan for a pairing beacon, then run the exchange. */
    fun start() {
        if (adapter?.isEnabled != true) {
            fail("Turn Bluetooth on to pair a door")
            return
        }
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

        // startScan() throws if Bluetooth is turned off between the check above
        // and this call, or if the app has hit Android's scan rate limit.
        val started = runCatching {
            scanner.startScan(listOf(filter), settings, scanCallback)
        }
        if (started.isFailure) {
            Log.w(TAG, "startScan failed", started.exceptionOrNull())
            fail("Could not start scanning for door units")
            return
        }
        handler.postDelayed(timeout, TIMEOUT_MS)
    }

    fun cancel() {
        cleanUp()
        session.cancel()
    }

    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            if (finished) return
            // A LOW_LATENCY scan can deliver several results before stopScan()
            // takes effect; without this guard we would call connectGatt()
            // repeatedly and leak every GATT client but the last.
            if (gatt != null) return
            handler.removeCallbacks(timeout)
            stopScan()
            listener.onProgress("Door unit found, connecting...")

            val connected = runCatching {
                result.device.connectGatt(
                    context, false, gattCallback, BluetoothDevice.TRANSPORT_LE
                )
            }.getOrNull()

            if (connected == null) {
                fail("Could not open a connection to the door unit")
                return
            }
            gatt = connected
        }

        override fun onScanFailed(errorCode: Int) {
            fail("Bluetooth scan failed (error $errorCode)")
        }
    }

    private val gattCallback = object : BluetoothGattCallback() {

        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            if (finished) return
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                if (status != BluetoothGatt.GATT_SUCCESS) {
                    fail("Connection to the door unit failed (status $status)")
                    return
                }
                if (!gatt.requestMtu(SmartKeyProtocol.MAX_FRAME + 3)) {
                    // No callback will arrive, and the default 23 byte MTU is
                    // too small for the pairing frames, so this is fatal rather
                    // than something to continue through.
                    fail("Could not negotiate a large enough BLE packet size")
                }
            } else {
                fail("Lost the connection to the door unit")
            }
        }

        override fun onMtuChanged(gatt: BluetoothGatt, mtu: Int, status: Int) {
            if (finished) return
            Log.i(TAG, "ATT MTU is now $mtu (status $status)")
            negotiatedMtu = mtu

            // The pairing frames are not fragmented: PAIR_RESPONSE alone is
            // 100 bytes. With the default 23 byte MTU only 20 bytes of payload
            // fit per notification, so the frame arrives truncated and decoding
            // fails with a confusing "malformed response".
            //
            // Fail here with an accurate message instead.
            if (mtu < MIN_REQUIRED_MTU) {
                fail(
                    "The phone and door unit could only agree on a $mtu byte MTU; " +
                        "pairing needs at least $MIN_REQUIRED_MTU"
                )
                return
            }
            gatt.discoverServices()
        }

        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            if (finished) return
            if (status != BluetoothGatt.GATT_SUCCESS) {
                fail("Could not read the door unit's services (status $status)")
                return
            }
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
                startExchange()
            }
        }

        override fun onDescriptorWrite(
            gatt: BluetoothGatt,
            descriptor: BluetoothGattDescriptor,
            status: Int
        ) {
            if (finished) return
            if (status != BluetoothGatt.GATT_SUCCESS) {
                fail("Could not subscribe to the door unit (status $status)")
                return
            }
            startExchange()
        }

        override fun onCharacteristicWrite(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            status: Int
        ) {
            writeInFlight = false

            if (status != BluetoothGatt.GATT_SUCCESS) {
                fail("The door unit rejected the pairing request (status $status)")
                return
            }

            writeNext()
        }

        override fun onCharacteristicChanged(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            value: ByteArray
        ) {
            if (finished) return
            // session.onFrame() is internally guarded, but handleStep() and the
            // listener are not: an exception escaping here lands on a binder
            // thread with no handler and takes the whole process down.
            runCatching { handleStep(session.onFrame(value)) }.onFailure {
                Log.e(TAG, "pairing step failed", it)
                fail("Pairing failed unexpectedly")
            }
        }
    }

    /** Kick off the key exchange, guarding against a throwing session. */
    private fun startExchange() {
        listener.onProgress("Exchanging keys...")
        val frame = runCatching { session.start() }.getOrElse {
            Log.e(TAG, "could not build PAIR_START", it)
            fail("Could not start pairing")
            return
        }
        send(frame)
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

    private var writeInFlight = false
    private var pendingWrite: Frame? = null

    private fun send(frame: Frame) {
        check(pendingWrite == null) { "pairing attempted concurrent writes" }
        pendingWrite = frame
        writeNext()
    }

    private fun writeNext() {
        if (writeInFlight || finished) return

        val frame = pendingWrite ?: return
        val characteristic = pairingCharacteristic ?: return
        val active = gatt ?: return

        writeInFlight = true
        pendingWrite = null

        val started = active.writeCharacteristic(
            characteristic,
            frame.encode(),
            BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
        )
        if (started != BluetoothStatusCodes.SUCCESS) {
            writeInFlight = false
            fail("Could not send the pairing request")
        }
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
        writeInFlight = false
        pendingWrite = null
    }

    companion object {
        private const val TAG = "PairingClient"
        private const val TIMEOUT_MS = 30_000L

        /**
         * Smallest ATT MTU that can carry the pairing frames unfragmented.
         *
         * PAIR_RESPONSE is the largest at 4 + 96 = 100 bytes, and ATT spends 3
         * bytes on its own header, so 103 is the true floor. Anything less and
         * the notification is silently truncated.
         */
        private const val MIN_REQUIRED_MTU =
            SmartKeyProtocol.HEADER_SIZE + SmartKeyProtocol.PAIR_RESPONSE_SIZE + 3
    }
}
