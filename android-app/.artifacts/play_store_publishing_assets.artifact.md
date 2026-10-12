# Google Play Store Publishing Package for Smart Key

This document contains all store listing texts, policy compliance declarations, privacy policy, and step-by-step submission instructions required to publish **Smart Key** to the Google Play Store.

---

## 1. Store Listing Metadata

### App Title
`Smart Key`

### Short Description (72 / 80 characters)
`Secure digital key for effortless, low-latency Bluetooth door unlock.`

### Full Description
```text
Smart Key turns your smartphone into a secure, fast, and reliable digital key for your smart doors and locks.

Key Features:
• Seamless Hands-Free Unlock: Automatically detects paired doors via low-energy Bluetooth (BLE) as you approach.
• Ultra-Fast Proximity Presence: Designed for instant door detection so your door is unlocked in under a second.
• On-Device Security & Encryption: Smart Key stores all credentials securely using Android EncryptedSharedPreferences and hardware-backed keystore elements.
• Fully Offline & Private: No external servers or cloud accounts required. Your digital keys never leave your phone.
• Easy Door Pairing: Pair new smart door hardware in seconds with simple interactive pairing.

How It Works:
Smart Key runs a continuous low-power Bluetooth presence beacon in the background. When you approach a paired smart lock, your phone communicates over encrypted BLE payloads to authenticate and grant access instantly.
```

---

## 2. Policy Compliance & Declarations

### A. Foreground Service Declaration (`CONNECTED_DEVICE`)
Google Play Console requires a policy review justification when declaring `FOREGROUND_SERVICE_CONNECTED_DEVICE`. Use the response below:

> **Selected Use Case**: Connected Devices (`CONNECTED_DEVICE`)
> **Video / Explanation Summary**:
> Smart Key uses a low-power Bluetooth Low Energy (BLE) background service (`PresenceService`) to continuously advertise and listen for paired smart door locks when the user's screen is off. This continuous background connection is essential to achieve sub-second door unlock latency when approaching a physical lock without requiring the user to wake their phone or open the app manually.

---

### B. Data Safety Questionnaire Answers

- **Does your app collect or share any user data?**
  `No`. Smart Key does not collect or transmit any user data to external servers.
- **Is all data encrypted in transit?**
  `Yes`. Bluetooth communication between the app and the smart lock uses AES-128-GCM encryption.
- **Can users request data deletion?**
  `Yes`. Users can delete paired doors and reset all local credentials directly inside the app at any time.

---

## 3. Privacy Policy Template

*Copy and host the text below on GitHub Pages, Notion, or your website to obtain a Privacy Policy URL required by Google Play Console:*

```markdown
# Privacy Policy for Smart Key

**Effective Date:** May 2026

Smart Key ("we", "our", or "app") is committed to protecting user privacy. This Privacy Policy outlines how your information is handled when using the Smart Key Android application.

### 1. Data Collection & Processing
Smart Key operates entirely on-device and offline. We do not collect, store, or transmit any personal data, identifiers, location data, or analytics to any remote servers.

### 2. Bluetooth & Device Permissions
The app uses Bluetooth Low Energy (BLE) permissions (`BLUETOOTH_CONNECT`, `BLUETOOTH_ADVERTISE`, `BLUETOOTH_SCAN`) solely to discover and communicate with paired physical door hardware. Bluetooth scan data is processed locally on your device and is never transmitted off-device.

### 3. Data Storage & Security
All cryptographic keys and paired door identifiers are stored locally on your device using Android's `EncryptedSharedPreferences` backed by the hardware Keystore.

### 4. Data Deletion
You can remove paired door credentials and clear all application data at any time through the app settings or Android App Management.

### 5. Contact Us
If you have any questions regarding this privacy policy, please contact support@smartkey.app.
```

---

## 4. Play Console Release Upload Instructions

1. **Log in to [Google Play Console](https://play.google.com/console)**.
2. Select your app or click **Create app** (Name: `Smart Key`, Default language: `English`, App, Free).
3. Under **App Content**:
   - Submit the **Privacy Policy URL**.
   - Complete the **Data Safety** section using the answers in Section 2B.
   - Complete the **Foreground Services** declaration using Section 2A.
4. Under **Main Store Listing**:
   - Paste the **Short Description** and **Full Description** from Section 1.
   - Upload App Icon (512x512 px) and Feature Graphic (1024x500 px).
   - Upload phone screenshots.
5. Under **Release > Internal testing** (or **Production**):
   - Click **Create new release**.
   - Drag & drop the generated Android App Bundle:
     `app/build/outputs/bundle/release/app-release.aab`
   - Review and rollout release!
