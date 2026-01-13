This **README.md** is designed for your enhanced LoRa Encrypted Messenger project. It highlights the security features, hardware configuration, and operational logic built into your code.

---

# 🔐 ESP32 LoRa Encrypted Messenger (v2.0)

A secure, off-grid, long-range messaging solution using ESP32 and LoRa radio technology. This project provides a mobile-friendly web interface to send and receive encrypted messages without relying on cellular networks or internet infrastructure.

## 🚀 Features

* **End-to-End Encryption:** Uses industry-standard **AES-128 (CTR Mode)** for privacy.
* **Message Integrity:** **HMAC-SHA256** signatures ensure messages haven't been tampered with or "spoofed."
* **Reliable Delivery:** Implements a message queue with **Automatic Retries** and **ACK (Acknowledgment)** tracking.
* **Power Optimized:** * Automatic WiFi timeout (AP shuts down after 5 mins of inactivity).
* Physical "Wake" button to restore WiFi.
* EMA-filtered battery voltage monitoring.


* **Web Interface:** Responsive UI for messaging, system logs, and real-time delivery status.
* **Persistent Settings:** Save LoRa frequency, power, and encryption keys directly to ESP32 Flash memory.

---

## 🛠 Hardware Requirements

1. **ESP32 Development Board** (e.g., DevKit V1).
2. **LoRa Module:** Designed for Ebyte **E32** or **E22** series (UART-based with M0/M1/AUX pins).
3. **Antenna:** 433MHz, 868MHz, or 915MHz (depending on your module and local regulations).
4. **Push Button:** Connected to GPIO 0 (Boot Button) for WiFi wake and factory reset.
5. **Battery:** 3.7V LiPo with a voltage divider connected to GPIO 34 for monitoring.

### 📌 Pin Mapping

| ESP32 Pin | LoRa Module Pin | Function |
| --- | --- | --- |
| **GPIO 16** | TXD | UART RX (Serial2) |
| **GPIO 17** | RXD | UART TX (Serial2) |
| **GPIO 4** | M0 | Mode Control 0 |
| **GPIO 5** | M1 | Mode Control 1 |
| **GPIO 15** | AUX | Busy/Status Signal |
| **GPIO 0** | - | Wake WiFi / Factory Reset |
| **GPIO 34** | - | Battery ADC (Voltage Divider) |

---

## 🔐 Security Architecture

The system employs a "Encrypt-then-MAC" approach to ensure maximum security over the air:

1. **Nonce (16-bytes):** Every packet generates a random nonce to ensure the same message never looks the same twice on the radio spectrum.
2. **AES-128-CTR:** The message body is encrypted using the provided AES key.
3. **HMAC-SHA256 Tag:** An 8-byte authentication tag is appended to verify that the sender possesses the correct secret key.
4. **Sync Word (0xAA):** A hardware-level sync word filters out urban radio noise before the decryption engine even starts.

---

## 📥 Installation

1. **Libraries:** Ensure you have the ESP32 Board Manager installed in your Arduino IDE. No external crypto libraries are needed as this project utilizes the built-in `mbedtls` framework.
2. **Upload:** Flash the provided `.ino` code to your ESP32.
3. **Initial Setup:**
* Connect to the WiFi Access Point: `Denny2` (Password: `emergency-me345`).
* Navigate to `http://192.168.4.1` in your browser.
* Go to **Settings** and update your **AES** and **HMAC** keys. **Both devices must have identical keys to communicate.**



---

## 📱 Usage Guide

### Messaging

* Open the web UI. Your messages will show as "Sending" (⏳) until the remote device sends back an encrypted Acknowledgment (ACK).
* Once confirmed, the status changes to "Delivered" (✓).

### Power Management

* **WiFi Sleep:** After 5 minutes, the WiFi AP will turn off to save battery. The LoRa radio stays active in the background to receive messages.
* **Waking Up:** Press the **BOOT button (GPIO 0)** to turn the WiFi back on for 5 minutes.
* **Factory Reset:** Hold the **BOOT button** for more than 3 seconds during power-up to wipe all saved settings and keys.

---

## ⚠️ Disclaimer

*Check your local regulations regarding LoRa frequency usage and encryption. This tool is intended for educational and emergency communication purposes.*
