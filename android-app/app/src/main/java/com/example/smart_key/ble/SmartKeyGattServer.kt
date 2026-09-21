package com.example.smart_key.ble

import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.content.Context
import android.util.Log
import com.example.smart_key.data.Credential
import com.example.smart_key.protocol.Frame
import com.example.smart_key.protocol.SmartKeyProtocol

/**
 * GATT server hosting the SmartKey service (protocol-spec.md §2.3).
 *
 * The door unit is the client: it writes frames to CONTROL and receives our
 * answers as notifications on STATUS.
 */
@SuppressLint("MissingPermission") // permissions are checked by PresenceService
class SmartKeyGattServer(
    private val context: Context,
    private val listener: Listener
) {
    /** Events the service layer cares about. */
    interface Listener {
        fun onAuthenticated(credential: Credential)
        fun onDisconnected()
        fun onUnlock(result: Int)
        fun onWarning(message: String)
    }

    private var gattServer: BluetoothGattServer? = null
    private var statusCharacteristic: BluetoothGattCharacteristic? = null
    private var pairingCharacteristic: BluetoothGattCharacteristic? = null
    private var connectedDevice: BluetoothDevice? = null

    private var engine = HandshakeEngine(emptyList())

    /** Optional hook used while pairing; see PairingClient. */
    var pairingHandler: ((ByteArray) -> Unit)? = null

    fun updateCredentials(credentials: List<Credential>) {
        engine = HandshakeEngine(credentials)
    }

    fun start(credentials: List<Credential>) {
        updateCredentials(credentials)
        val manager = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
        val server = manager.openGattServer(context, callback) ?: run {
            Log.e(TAG, "could not open the GATT server")
            return
        }
        gattServer = server

        val service = BluetoothGattService(
            SmartKeyProtocol.SERVICE_UUID,
            BluetoothGattService.SERVICE_TYPE_PRIMARY
        )
        val control = BluetoothGattCharacteristic(
            SmartKeyProtocol.CONTROL_UUID,
            BluetoothGattCharacteristic.PROPERTY_WRITE or
                BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE,
            BluetoothGattCharacteristic.PERMISSION_WRITE
        )
        val status = notifyCharacteristic(SmartKeyProtocol.STATUS_UUID, writable = false)
        val pairing = notifyCharacteristic(SmartKeyProtocol.PAIRING_UUID, writable = true)

        service.addCharacteristic(control)
        service.addCharacteristic(status)
        service.addCharacteristic(pairing)
        server.addService(service)

        statusCharacteristic = status
        pairingCharacteristic = pairing
        Log.i(TAG, "GATT server started")
    }

    /** Build a notify characteristic with the mandatory CCCD descriptor. */
    private fun notifyCharacteristic(
        uuid: java.util.UUID,
        writable: Boolean
    ): BluetoothGattCharacteristic {
        var properties = BluetoothGattCharacteristic.PROPERTY_NOTIFY
        var permissions = BluetoothGattCharacteristic.PERMISSION_READ
        if (writable) {
            properties = properties or BluetoothGattCharacteristic.PROPERTY_WRITE
            permissions = permissions or BluetoothGattCharacteristic.PERMISSION_WRITE
        }
        return BluetoothGattCharacteristic(uuid, properties, permissions).apply {
            addDescriptor(
                BluetoothGattDescriptor(
                    SmartKeyProtocol.CCCD_UUID,
                    BluetoothGattDescriptor.PERMISSION_READ or
                        BluetoothGattDescriptor.PERMISSION_WRITE
                )
            )
        }
    }

    fun stop() {
        engine.reset()
        connectedDevice = null
        runCatching { gattServer?.close() }
        gattServer = null
        Log.i(TAG, "GATT server stopped")
    }

    /** Send a frame to the connected door unit as a STATUS notification. */
    fun notifyStatus(frame: Frame): Boolean = notify(statusCharacteristic, frame)

    /** Send a frame on the PAIRING characteristic. */
    fun notifyPairing(frame: Frame): Boolean = notify(pairingCharacteristic, frame)

    private fun notify(characteristic: BluetoothGattCharacteristic?, frame: Frame): Boolean {
        val device = connectedDevice ?: return false
        val chr = characteristic ?: return false
        val server = gattServer ?: return false
        return server.notifyCharacteristicChanged(device, chr, false, frame.encode()) ==
            BluetoothGatt.GATT_SUCCESS
    }

    private val callback = object : BluetoothGattServerCallback() {

        override fun onConnectionStateChange(device: BluetoothDevice, status: Int, newState: Int) {
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                Log.i(TAG, "door unit connected")
                connectedDevice = device
            } else {
                Log.i(TAG, "door unit disconnected")
                connectedDevice = null
                engine.reset()
                listener.onDisconnected()
            }
        }

        override fun onCharacteristicWriteRequest(
            device: BluetoothDevice,
            requestId: Int,
            characteristic: BluetoothGattCharacteristic,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray
        ) {
            if (responseNeeded) {
                gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, null)
            }
            when (characteristic.uuid) {
                SmartKeyProtocol.CONTROL_UUID -> handleControl(value)
                SmartKeyProtocol.PAIRING_UUID -> pairingHandler?.invoke(value)
                else -> Log.d(TAG, "write to an unexpected characteristic")
            }
        }

        override fun onDescriptorWriteRequest(
            device: BluetoothDevice,
            requestId: Int,
            descriptor: BluetoothGattDescriptor,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray
        ) {
            // Accept the CCCD write with which the door unit enables notifications.
            if (responseNeeded) {
                gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, null)
            }
        }
    }

    /** Run one CONTROL frame through the handshake engine and act on the result. */
    private fun handleControl(value: ByteArray) {
        when (val outcome = engine.onFrame(value)) {
            is HandshakeEngine.Outcome.Reply -> notifyStatus(outcome.frame)

            is HandshakeEngine.Outcome.Authenticated ->
                listener.onAuthenticated(outcome.credential)

            is HandshakeEngine.Outcome.Unlock -> {
                notifyStatus(outcome.reply)
                listener.onUnlock(outcome.result)
            }

            is HandshakeEngine.Outcome.Abort -> {
                Log.w(TAG, "aborting: ${outcome.reason}")
                if (outcome.alarming) {
                    listener.onWarning(outcome.reason)
                }
                connectedDevice?.let { gattServer?.cancelConnection(it) }
                engine.reset()
            }

            HandshakeEngine.Outcome.Ignore -> Unit
        }
    }

    companion object {
        private const val TAG = "SmartKeyGattServer"
    }
}
