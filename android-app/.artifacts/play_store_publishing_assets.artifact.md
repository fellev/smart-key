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
• On-Device Security & Encryption: Smart Key stores paired credentials and settings in encrypted preferences protected by the Android Keystore.
• Optional Home Assistant Integration: Send an authenticated open request to the Home Assistant instance you configure.
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

### B. Data Safety Questionnaire

Complete the Play Console questionnaire based on the final release and the developer's actual data practices; do not use a blanket "No" answer without review. Smart Key has no developer-operated backend, but when Home Assistant is configured, the app sends an HTTPS request directly to the configured Home Assistant endpoint. The request includes the saved access token in the authorization header and the configured service and entity ID. Depending on the URL, that endpoint may be self-hosted or operated by a third party. The app also communicates with paired door hardware over BLE.

Confirm which data types and purposes must be declared under current Play Console rules, and verify the deletion and encryption answers against the shipped app and hosting configuration before submission.

---

## 3. Privacy Policy

The privacy policy is hosted at:
https://fellev.github.io/smart-key/privacy-policy/

The same URL is linked from the app's main screen.

---

## 4. Play Console Release Upload Instructions

1. **Log in to [Google Play Console](https://play.google.com/console)**.
2. Select your app or click **Create app** (Name: `Smart Key`, Default language: `English`, App, Free).
3. Under **App Content**:
   - Submit `https://fellev.github.io/smart-key/privacy-policy/` as the **Privacy Policy URL**.
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
