package com.example.smart_key.ble

import android.app.KeyguardManager
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.PowerManager
import android.os.SystemClock
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.lifecycle.LifecycleService
import com.example.smart_key.MainActivity
import com.example.smart_key.R
import com.example.smart_key.data.Credential
import com.example.smart_key.data.CredentialStore
import com.example.smart_key.data.Settings
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * Foreground service that keeps the presence beacon and GATT server alive.
 *
 * A foreground service of type `connectedDevice` is what allows the app to
 * keep advertising with the screen off, which is required to meet the
 * sub-second LED target (protocol-spec.md §8).
 */
class PresenceService : LifecycleService(), SmartKeyGattServer.Listener {

    /**
     * What the UI shows.
     *
     * [LISTENING] is the listen-first resting state: the service is running
     * but the phone is transmitting nothing at all, waiting to hear a door.
     */
    enum class State { STOPPED, LISTENING, ADVERTISING, CONNECTED, UNLOCKED }

    private lateinit var store: CredentialStore
    private lateinit var settings: Settings
    private lateinit var advertiser: SmartKeyAdvertiser
    private lateinit var gattServer: SmartKeyGattServer
    private lateinit var gate: PresenceGate

    private val handler = Handler(Looper.getMainLooper())

    /** Stops advertising again once the linger window has expired. */
    private val silenceRunnable = Runnable { applyGate() }

    override fun onCreate() {
        super.onCreate()
        store = CredentialStore(applicationContext)
        settings = Settings(applicationContext)
        advertiser = SmartKeyAdvertiser(applicationContext)
        gattServer = SmartKeyGattServer(applicationContext, this)
        gate = PresenceGate(settings.presenceMode)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        super.onStartCommand(intent, flags, startId)
        when (intent?.action) {
            ACTION_STOP -> {
                stopPresence()
                return START_NOT_STICKY
            }
            ACTION_DOOR_SEEN -> {
                // A door beacon was picked up by the offloaded scan. In
                // listen-first mode this is what breaks radio silence.
                onDoorSeen()
                return START_STICKY
            }
        }
        startPresence()
        // Restart if the system kills us: presence must survive memory pressure.
        return START_STICKY
    }

    private fun startPresence() {
        val credentials = store.all()
        if (credentials.isEmpty()) {
            Log.w(TAG, "no paired doors, nothing to advertise")
            stopSelf()
            return
        }
        // Re-read: the user may have changed it since the service was created.
        gate = PresenceGate(settings.presenceMode)
        gate.start()

        startForeground(NOTIFICATION_ID, buildNotification(idleNotificationText()))

        refreshDeviceFlags()
        // The GATT server is passive — it costs nothing until a door connects,
        // and it must already be up when one does, so it runs in both modes.
        gattServer.start(credentials)

        // Listening is what wakes us in listen-first mode, and what repairs us
        // after an OS kill in either mode.
        ScanRecovery.register(applicationContext)

        applyGate()
        Log.i(
            TAG,
            "presence started for ${credentials.size} door(s), mode=${gate.mode}"
        )
    }

    /**
     * Start or stop the advertiser to match the gate.
     *
     * Every transmit/silence decision funnels through here, so there is one
     * place where "is the phone radiating?" is decided.
     */
    private fun applyGate() {
        handler.removeCallbacks(silenceRunnable)
        if (!gate.isRunning) return

        val now = SystemClock.elapsedRealtime()
        val credentials = store.all()
        if (credentials.isEmpty()) {
            stopPresence()
            return
        }

        if (gate.shouldTransmit(now)) {
            advertiser.start(credentials)
            if (_state.value != State.CONNECTED && _state.value != State.UNLOCKED) {
                _state.value = State.ADVERTISING
            }
            // Schedule the return to silence at the exact expiry moment
            // instead of polling for it.
            gate.msUntilSilent(now)?.let { handler.postDelayed(silenceRunnable, it) }
        } else {
            advertiser.stop()
            _state.value = State.LISTENING
            updateNotification(idleNotificationText())
            Log.i(TAG, "radio silent, waiting to hear a door")
        }
    }

    /** A door beacon was seen; break radio silence if we are listening. */
    private fun onDoorSeen() {
        if (!gate.isRunning) {
            startPresence()
            return
        }
        gate.onDoorSeen(SystemClock.elapsedRealtime())
        applyGate()
    }

    private fun idleNotificationText(): String =
        if (gate.mode == PresenceMode.LISTEN_FIRST) {
            "Listening for your door"
        } else {
            "Looking for your door"
        }

    /**
     * Stop presence because the *user* asked for it.
     *
     * The recovery scan is unregistered here: a door beacon must not silently
     * resurrect a service the user deliberately turned off. Note the contrast
     * with [onDestroy], which leaves it registered on purpose.
     */
    private fun stopPresence() {
        handler.removeCallbacks(silenceRunnable)
        gate.stop()
        advertiser.stop()
        gattServer.stop()
        ScanRecovery.unregister(applicationContext)
        _state.value = State.STOPPED
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    /** Fold the current screen / keyguard state into the beacon flags. */
    private fun refreshDeviceFlags() {
        val power = getSystemService(Context.POWER_SERVICE) as PowerManager
        val keyguard = getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        advertiser.screenOn = power.isInteractive
        advertiser.deviceUnlocked = !keyguard.isDeviceLocked
    }

    /**
     * Torn down, possibly by the OS rather than by the user.
     *
     * The recovery scan is deliberately left registered: this is precisely the
     * case it exists for. It lives in the Bluetooth stack, not in this
     * process, so it keeps working after we are gone. A user-initiated stop
     * goes through [stopPresence], which unregisters it first.
     */
    override fun onDestroy() {
        handler.removeCallbacks(silenceRunnable)
        advertiser.stop()
        gattServer.stop()
        _state.value = State.STOPPED
        super.onDestroy()
    }

    override fun onBind(intent: Intent): IBinder? {
        super.onBind(intent)
        return null
    }

    // ------------------------------------------- SmartKeyGattServer.Listener

    override fun onAuthenticated(credential: Credential) {
        // Pin transmission for the duration of the session: going silent with
        // a door mid-handshake would drop the session it is relying on.
        gate.onConnectedChanged(true, SystemClock.elapsedRealtime())
        handler.removeCallbacks(silenceRunnable)

        _state.value = State.CONNECTED
        _lastDoor.value = credential.label
        updateNotification("At ${credential.label} - press the button to open")
    }

    override fun onDisconnected() {
        if (_state.value == State.STOPPED) return
        // Releases the pin and restarts the linger countdown, so the phone
        // keeps advertising briefly while the user walks away and then goes
        // quiet again on its own.
        gate.onConnectedChanged(false, SystemClock.elapsedRealtime())
        applyGate()
    }

    override fun onUnlock(result: Int) {
        _state.value = State.UNLOCKED
        _lastUnlockResult.value = result
        updateNotification(if (result == 0) "Door opened" else "The door could not be opened")
    }

    override fun onWarning(message: String) {
        Log.w(TAG, "security warning: $message")
        _warnings.value = message
    }

    // ----------------------------------------------------------- notification

    private fun buildNotification(text: String): Notification {
        createChannel()
        val openApp = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_idle_lock)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setContentIntent(openApp)
            .build()
    }

    private fun updateNotification(text: String) {
        getSystemService(NotificationManager::class.java)
            .notify(NOTIFICATION_ID, buildNotification(text))
    }

    private fun createChannel() {
        val manager = getSystemService(NotificationManager::class.java)
        if (manager.getNotificationChannel(CHANNEL_ID) != null) return
        manager.createNotificationChannel(
            NotificationChannel(
                CHANNEL_ID,
                "Door presence",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Keeps SmartKey ready so the door recognises you"
                setShowBadge(false)
            }
        )
    }

    companion object {
        private const val TAG = "PresenceService"
        private const val CHANNEL_ID = "smartkey_presence"
        private const val NOTIFICATION_ID = 1001

        const val ACTION_START = "com.example.smart_key.START_PRESENCE"
        const val ACTION_STOP = "com.example.smart_key.STOP_PRESENCE"
        /** A door beacon was heard; breaks radio silence in listen-first mode. */
        const val ACTION_DOOR_SEEN = "com.example.smart_key.DOOR_SEEN_SERVICE"

        private val _state = MutableStateFlow(State.STOPPED)
        val state: StateFlow<State> = _state

        private val _lastDoor = MutableStateFlow<String?>(null)
        val lastDoor: StateFlow<String?> = _lastDoor

        private val _lastUnlockResult = MutableStateFlow<Int?>(null)
        val lastUnlockResult: StateFlow<Int?> = _lastUnlockResult

        private val _warnings = MutableStateFlow<String?>(null)
        val warnings: StateFlow<String?> = _warnings

        fun start(context: Context) {
            context.startForegroundService(
                Intent(context, PresenceService::class.java).setAction(ACTION_START)
            )
        }

        fun stop(context: Context) {
            context.startService(
                Intent(context, PresenceService::class.java).setAction(ACTION_STOP)
            )
        }
    }
}
