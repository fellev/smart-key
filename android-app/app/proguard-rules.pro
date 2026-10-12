# ProGuard rules for Smart Key app

# Keep Android Security Crypto & Tink classes
-keep class com.google.crypto.tink.** { *; }
-keep class androidx.security.crypto.** { *; }

# Ignore warnings for optional Tink HTTP/Annotation/Joda dependencies
-dontwarn com.google.api.client.**
-dontwarn javax.annotation.**
-dontwarn org.joda.time.**

# Keep BLE Presence Service, Scan Recovery Receiver, and Boot Receiver
-keep class com.example.smart_key.ble.PresenceService { *; }
-keep class com.example.smart_key.ble.ScanRecoveryReceiver { *; }
-keep class com.example.smart_key.ble.BootReceiver { *; }

# Keep ViewBinding generated classes
-keep class com.example.smart_key.databinding.** { *; }

# Keep Kotlin Coroutines internal reflection if needed
-dontwarn kotlinx.coroutines.**
