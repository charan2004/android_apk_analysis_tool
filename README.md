# OWASP MASTG Generic Android Static Analyzer

This directory contains a standalone, modular static analysis tool for Android APKs, built to follow the **OWASP Mobile Application Security Testing Guide (MASTG)**. It is designed to be fully generic, supporting any decompiled directory from either **Apktool** or **JADX**.

## 🚀 Getting Started

### Prerequisites
- **Python 3.x**
- **[Apktool](https://ibotpeaches.github.io/Apktool/install/)** (for decompiling APKs)

### Usage
Run the scanner from the project root:
```bash
python3 mastg_scanner/main.py <path_to_decompiled_apk>
```

---

## 🔍 Security Rules Deep Dive

The scanner implements 10 core MASTG checks, categorized for clarity:

### 🛡️ Platform Security
- **Debuggable Flag Disabled (MASTG-BEST-0007)**: Checks if `android:debuggable` is set to `true` in the Manifest, which would allow code injection and runtime manipulation.
- **Exported Components Restricted (MASTG-PLATFORM-0001)**: Scans for Activities, Services, and Receivers that are `android:exported="true"`. It separates first-party from third-party components to highlight risky app-specific entry points.
- **WebView Debugging Disabled (MASTG-BEST-0008)**: Detects if `setWebContentsDebuggingEnabled(true)` is called without being properly guarded by a debug build check.
- **Disable Content Provider Access (MASTG-BEST-0013)**: Identifies if WebViews allow risky access to Content Providers while also enabling JavaScript and universal file access.
- **Secure File Loading in WebViews (MASTG-BEST-0011)**: Audits file access settings in WebViews, specifically looking for insecure combinations that allow local file exfiltration through malicious HTML.

### 📦 Storage & Privacy
- **Exclude Sensitive Data from Backups (MASTG-BEST-0004)**: Verifies if the app enables backups without defining rules to exclude sensitive directories like `shared_prefs` or `databases`.
- **Sensitive Data in Notifications (MASTG-BEST-0027)**: Scans source code for sensitive keywords (OTP, PIN, Password) being used in Notifications and checks if they are visible on the lockscreen.
- **WebView Cache Cleanup (MASTG-BEST-0028)**: Checks if WebView storage (cookies, cache, DOM storage) is enabled without corresponding cleanup or "no cache" modes.

### 🌐 Network Security
- **Cleartext Traffic Configuration (MASTG-TEST-0235)**: Audits both the `AndroidManifest.xml` and `network_security_config.xml` for settings that allow unencrypted HTTP traffic.

### 🔐 Cryptography
- **Secure Encryption Modes (MASTG-BEST-0005)**: Scans for insecure symmetric encryption modes, specifically **ECB (Electronic Codebook)**, which is known to leak plaintext patterns.

---

## 📂 Project Architecture

The tool is organized for modularity and ease of maintenance:

- **`main.py`**: The entry point. Handles setup, component detection, and reporting.
- **`engine/runner.py`**: Orchestrates the execution of all rules in an exception-safe manner.
- **`rules/`**: Contains self-contained logic for each security check. Adding a new rule is as simple as adding a new file here.
- **`utils/`**: Shared helpers for filesystem detection (`fs_utils`), XML parsing (`xml_utils`), and Manifest analysis (`manifest_utils`).
- **`config.py`**: Centralized configuration for severity weights, namespaces, and display settings.

---

## 📈 Scoring & Reporting
The tool provides a severity-weighted score out of 100:
- **PASS**: 0-weighted credit if high/medium risk is avoided.
- **FAIL**: Deducts points based on the severity weight (High = 3, Medium = 2, Low = 1).
- **Summary**: Provides a category-wise breakdown (Platform, Network, etc.) to identify the weakest areas of the app.

---
*Built for the OWASP MASTG security standards.*
