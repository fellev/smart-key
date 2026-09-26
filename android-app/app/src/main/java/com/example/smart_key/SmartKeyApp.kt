package com.example.smart_key

import android.app.Application
import android.util.Log
import java.io.File
import java.io.PrintWriter
import java.io.StringWriter
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Application entry point, installed only to capture crashes.
 *
 * ## Why this exists
 *
 * When an uncaught exception kills the process, the only thing left in logcat
 * is often a `DeadObjectException` from `system_server` complaining that it
 * could not reach our windows. That trace contains no frames from this app and
 * is logged *after* the fact, so it identifies nothing.
 *
 * Worse, the real stack trace is easy to lose: it is emitted moments before
 * the process dies, and any logcat filter or buffer wrap hides it.
 *
 * So the handler below does two things the default one does not:
 *
 *  1. logs the trace under a single, greppable tag;
 *  2. writes it to a file that survives the process, so it can be recovered
 *     afterwards with adb even if logcat was not being watched.
 *
 * It then delegates to the previous handler, so the normal crash reporting and
 * process teardown still happen — this observes, it does not swallow.
 */
class SmartKeyApp : Application() {

    override fun onCreate() {
        super.onCreate()
        installCrashHandler()
    }

    private fun installCrashHandler() {
        val previous = Thread.getDefaultUncaughtExceptionHandler()

        Thread.setDefaultUncaughtExceptionHandler { thread, error ->
            // Wrapped in runCatching: a handler that throws would replace the
            // real crash with a confusing one from in here.
            runCatching { report(thread, error) }

            // Delegate so the platform still logs and terminates normally.
            previous?.uncaughtException(thread, error)
        }
    }

    private fun report(thread: Thread, error: Throwable) {
        val stack = StringWriter().also { error.printStackTrace(PrintWriter(it)) }.toString()
        val when_ = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())

        val text = buildString {
            appendLine("SmartKey crash at $when_")
            appendLine("thread : ${thread.name}")
            appendLine("type   : ${error.javaClass.name}")
            appendLine("message: ${error.message}")
            appendLine()
            append(stack)
        }

        // Log first: if the file write fails we still want the trace somewhere.
        Log.e(TAG, text)

        runCatching {
            File(filesDir, CRASH_FILE).writeText(text)
        }
    }

    companion object {
        /** Grep for this tag: `adb logcat -s SmartKeyCrash`. */
        private const val TAG = "SmartKeyCrash"
        const val CRASH_FILE = "last_crash.txt"
    }
}
