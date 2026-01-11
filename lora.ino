/*
 * ESP32 LoRa Encrypted Messenger - Enhanced Version
 */

#include <WiFi.h>
#include <WebServer.h>
#include <Preferences.h>
#include <mbedtls/aes.h>
#include <mbedtls/md.h>
#include <esp_task_wdt.h>

// ========================
// PIN DEFINITIONS
// ========================
#define LORA_RX 16
#define LORA_TX 17
#define M0_PIN 4
#define M1_PIN 5
#define AUX_PIN 15
#define WIFI_WAKE_BTN 0    // Boot button to wake WiFi
#define BATTERY_PIN 34     // Analog pin for battery voltage
#define MAX_ENCRYPTED_SIZE 300

// ========================
// CONFIGURATION DEFAULTS
// ========================
struct Config {
  char ap_ssid[32];
  char ap_password[32];
  uint8_t aes_key[16];
  uint8_t hmac_key[32];
  uint8_t lora_channel;
  uint8_t lora_power;
  uint16_t lora_rate;
  uint8_t lora_address;
  uint8_t network_id;
  uint8_t max_retries;
  uint16_t retry_delay_ms;
  uint16_t ack_timeout_ms;
  bool enable_queue;
};

// Default configuration
Config config = {
  .ap_ssid = "Denny2",
  .ap_password = "emergency-me345",
  .aes_key = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
              0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c},
  .hmac_key = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
               0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
               0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78,
               0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0},
  .lora_channel = 23,
  .lora_power = 20,
  .lora_rate = 2400,
  .lora_address = 1,
  .network_id = 76,
  .max_retries = 3,
  .retry_delay_ms = 5000,
  .ack_timeout_ms = 3000,
  .enable_queue = false
};

// ========================
// MESSAGE QUEUE
// ========================
#define MAX_QUEUE_SIZE 20
#define MAX_LOG_SIZE 39

enum MessageStatus {
  MSG_PENDING,
  MSG_SENT,
  MSG_ACKED,
  MSG_FAILED
};

enum MessageType {
  MSG_DATA,
  MSG_ACK
};

struct QueuedMessage {
  String content;
  uint8_t* encrypted_binary;
  size_t encrypted_len;
  uint32_t msgId;
  MessageStatus status;
  uint8_t retries;
  unsigned long lastTry;
  unsigned long timestamp;

  QueuedMessage() : encrypted_binary(nullptr), encrypted_len(0) {}
  ~QueuedMessage() {
    if (encrypted_binary) {
      delete[] encrypted_binary;
      encrypted_binary = nullptr;
    }
  }
};

QueuedMessage messageQueue[MAX_QUEUE_SIZE];
int queueHead = 0;
int queueTail = 0;
int queueCount = 0;

String messageLog[MAX_LOG_SIZE];
int logIndex = 0;
int logCount = 0;

uint32_t nextMsgId = 1;

// Battery & WiFi Management
float currentBattery = 0.0;
unsigned long wifiStartTime = 0;
bool wifiActive = true;
const unsigned long WIFI_TIMEOUT = 300000; // 5 minutes
float smoothedVoltage = 0.0;

// ========================
// GLOBAL OBJECTS
// ========================
WebServer server(80);
Preferences preferences;
mbedtls_aes_context aes_ctx;
mbedtls_md_context_t hmac_ctx;

// ========================
// FORWARD DECLARATIONS
// ========================
String encryptMessage(String plaintext);
String decryptMessage(String ciphertext);
String signMessage(String message);
void signMessageBytes(const uint8_t* data, size_t len, uint8_t* output);
bool verifySignatureBytes(const uint8_t* data, size_t len, const uint8_t* signature);
bool verifySignature(String message, String signature);
void saveConfig();
void loadConfig();

// ========================
// LORA CONTROL FUNCTIONS
// ========================

// Battery Helper
float getBatteryVoltage() {
  int raw = 0;
  for(int i=0; i<10; i++) raw += analogRead(BATTERY_PIN); // Take 10 samples
  float currentSample = ((raw / 10.0) / 4095.0) * 3.3 * 2.0;

  // EMA Filter: 90% old value, 10% new value
  if (smoothedVoltage < 1.0) smoothedVoltage = currentSample; // Initialize
  smoothedVoltage = (smoothedVoltage * 0.9) + (currentSample * 0.1);
  
  return smoothedVoltage;
}

int getBatteryPercentage() {
  float v = getBatteryVoltage();
  // Simple estimation for LiPo (3.2V - 4.2V)
  int pct = map((long)(v * 100), 320, 420, 0, 100);
  return constrain(pct, 0, 100);
}

void setLoRaNormalMode() {
  digitalWrite(M0_PIN, LOW);
  digitalWrite(M1_PIN, LOW);
  delay(100);
}

void setLoRaConfigMode() {
  digitalWrite(M0_PIN, HIGH);
  digitalWrite(M1_PIN, LOW);
  delay(100);
}

void initLoRaModule() {
  Serial.println("\n[LoRa] Initializing module...");
  
  setLoRaConfigMode();
  delay(200);
  
  while (Serial2.available()) Serial2.read();
  
  // Test communication
  Serial2.println("AT");
  delay(100);
  String response = "";
  unsigned long start = millis();
  while (millis() - start < 500 && Serial2.available()) {
    response += (char)Serial2.read();
  }
  
  if (response.indexOf("OK") >= 0) {
    Serial.println("[LoRa] Module responding");
  } else {
    Serial.println("[LoRa] Warning: No response");
  }
  
  // Apply configuration
  Serial2.println("AT+ADDRESS=" + String(config.lora_address));
  delay(100);
  
  Serial2.println("AT+NETWORKID=" + String(config.network_id));
  delay(100);
  
  Serial2.println("AT+CHANNEL=" + String(config.lora_channel));
  delay(100);
  
  Serial2.println("AT+POWER=" + String(config.lora_power));
  delay(100);
  
  Serial2.println("AT+UART=9600,8,1,0,0");
  delay(100);
  
  setLoRaNormalMode();
  
  Serial.println("[LoRa] Configuration applied");
  Serial.println("  Address: " + String(config.lora_address));
  Serial.println("  Network: " + String(config.network_id));
  Serial.println("  Channel: " + String(config.lora_channel));
  Serial.println("  Power: " + String(config.lora_power) + " dBm");
}

// ========================
// CRYPTOGRAPHY FUNCTIONS
// ========================



// Helper for HMAC calculation
void calcHMAC(const uint8_t* data, size_t len, uint8_t* output) {
  mbedtls_md_init(&hmac_ctx);
  mbedtls_md_setup(&hmac_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
  mbedtls_md_hmac_starts(&hmac_ctx, config.hmac_key, 32);
  mbedtls_md_hmac_update(&hmac_ctx, data, len);
  mbedtls_md_hmac_finish(&hmac_ctx, output);
  mbedtls_md_free(&hmac_ctx);
}

size_t encryptMessage(
  const uint8_t* plaintext,
  size_t plaintext_len,
  uint8_t* output
) {
  if (plaintext_len > 240) return 0;

  // 1. Generate Nonce
  uint8_t nonce[16];
  for (int i = 0; i < 16; i++) {
    nonce[i] = esp_random() & 0xFF;
  }

  // 2. We need a temporary copy of the nonce because CTR mode MODIFIES the nonce/counter
  uint8_t working_nonce[16];
  memcpy(working_nonce, nonce, 16);

  uint8_t stream_block[16] = {0};
  size_t nc_off = 0;

  mbedtls_aes_init(&aes_ctx);
  mbedtls_aes_setkey_enc(&aes_ctx, config.aes_key, 128);

  // Encrypt directly into the output buffer at offset 16
  mbedtls_aes_crypt_ctr(&aes_ctx, plaintext_len, &nc_off, working_nonce, stream_block, plaintext, output + 16);
  mbedtls_aes_free(&aes_ctx);

  // 3. Put original nonce at the start
  memcpy(output, nonce, 16);
  
  // 4. Calculate MAC over (Nonce + Ciphertext)
  uint8_t mac[32];
  calcHMAC(output, 16 + plaintext_len, mac);
  memcpy(output + 16 + plaintext_len, mac, 8); // Attach 8-byte tag

  return 16 + plaintext_len + 8;
}

bool decryptMessage(
  const uint8_t* packet,
  size_t packet_len,
  uint8_t* plaintext,
  size_t* plaintext_len
) {
  if (packet_len < 16 + 8) return false;

  size_t cipher_len = packet_len - 16 - 8;

  // 1. MAC CHECK (Always check this before decrypting!)
  uint8_t mac[32];
  calcHMAC(packet, 16 + cipher_len, mac);
  if (memcmp(mac, packet + 16 + cipher_len, 8) != 0) {
    Serial.println("[Crypto] MAC Mismatch!");
    return false;
  }

  // 2. CRITICAL: Copy the Nonce to a local buffer. 
  // AES-CTR will modify this buffer during decryption. 
  // If you point it at the original packet, it corrupts the read process.
  uint8_t working_nonce[16];
  memcpy(working_nonce, packet, 16);

  uint8_t stream_block[16] = {0};
  size_t nc_off = 0;

  mbedtls_aes_init(&aes_ctx);
  mbedtls_aes_setkey_enc(&aes_ctx, config.aes_key, 128);
  
  // Decrypt ciphertext (at packet + 16) into plaintext
  mbedtls_aes_crypt_ctr(&aes_ctx, cipher_len, &nc_off, working_nonce, stream_block, packet + 16, plaintext);
  
  mbedtls_aes_free(&aes_ctx);

  *plaintext_len = cipher_len;
  plaintext[cipher_len] = '\0'; // Safety null-terminator
  return true;
}

size_t base64_decode(String encoded, uint8_t* output) {
  const char* base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  size_t out_len = 0;
  uint32_t val = 0;
  int bits = -8;
  
  for (size_t i = 0; i < encoded.length(); i++) {
    char c = encoded[i];
    if (c == '=') break;
    
    const char* p = strchr(base64_chars, c);
    if (!p) continue;
    
    val = (val << 6) | (p - base64_chars);
    bits += 6;
    
    if (bits >= 0) {
      output[out_len++] = (val >> bits) & 0xFF;
      bits -= 8;
    }
  }
  
  return out_len;
}


String base64_encode(const uint8_t* data, size_t length) {
  const char* base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  String encoded = "";
  encoded.reserve((length * 4 / 3) + 4); // Pre-allocate for efficiency
  
  for (size_t i = 0; i < length; i += 3) {
    uint32_t octet_a = i < length ? data[i] : 0;
    uint32_t octet_b = i + 1 < length ? data[i + 1] : 0;
    uint32_t octet_c = i + 2 < length ? data[i + 2] : 0;
    
    uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;
    
    encoded += base64_chars[(triple >> 18) & 0x3F];
    encoded += base64_chars[(triple >> 12) & 0x3F];
    encoded += (i + 1 < length) ? base64_chars[(triple >> 6) & 0x3F] : '=';
    encoded += (i + 2 < length) ? base64_chars[triple & 0x3F] : '=';
  }
  
  return encoded;
}

void signMessageBytes(const uint8_t* data, size_t len, uint8_t* output) {
  uint8_t hmac_result[32];
  calcHMAC(data, len, hmac_result);
  memcpy(output, hmac_result, 16); // Use first 16 bytes
}


bool verifySignatureBytes(const uint8_t* data, size_t len, const uint8_t* signature) {
  uint8_t computed[16];
  signMessageBytes(data, len, computed);
  return memcmp(computed, signature, 16) == 0;
}



String signMessage(String message) {
  // Kept for backward compat with message parsing logic if needed,
  // but we are correctly using HMAC in the transport layer now.
  // The inner signature is still useful for end-to-end non-repudiation if we want.
  uint8_t hmac_result[32];
  calcHMAC((uint8_t*)message.c_str(), message.length(), hmac_result);
  return base64_encode(hmac_result, 16);
}

bool verifySignature(String message, String signature) {
  String computed = signMessage(message);
  return computed == signature;
}

// ========================
// MESSAGE QUEUE FUNCTIONS
// ========================

void addToQueue(String content) {
  if (queueCount >= MAX_QUEUE_SIZE) {
    Serial.println("[Queue] Full! Dropping oldest message");
      
      // Free memory of oldest message
    QueuedMessage* oldMsg = &messageQueue[queueHead];
    if (oldMsg->encrypted_binary) {
      delete[] oldMsg->encrypted_binary;
      oldMsg->encrypted_binary = nullptr;
      oldMsg->encrypted_len = 0;
    }

    queueHead = (queueHead + 1) % MAX_QUEUE_SIZE;
    queueCount--;
  }
  
  QueuedMessage* msg = &messageQueue[queueTail];
  msg->content = content;
  msg->msgId = nextMsgId++;
  msg->status = MSG_PENDING;
  msg->retries = 0;
  msg->lastTry = 0;
  msg->timestamp = millis();

  // Build signature input: "msgId|content"
  char sig_input[256];
  snprintf(sig_input, sizeof(sig_input), "%u|%s", msg->msgId, content.c_str());
  
  // Generate signature (16 raw bytes)
  uint8_t signature_bytes[16];
  signMessageBytes((uint8_t*)sig_input, strlen(sig_input), signature_bytes);
  
  // Convert signature to base64 for message format
  String signature_b64 = base64_encode(signature_bytes, 16);

  char full_body[256];
  snprintf(full_body, sizeof(full_body), "D|%u|%s|%s", msg->msgId, signature_b64.c_str(), content.c_str());

  // ✅ Use strlen() instead of .length()
  size_t body_len = strlen(full_body);
  msg->encrypted_len = body_len + 40;  // Estimate: plaintext + nonce(16) + MAC(8) + padding

  if (msg->encrypted_binary) delete[] msg->encrypted_binary;
  msg->encrypted_binary = new uint8_t[msg->encrypted_len];

  // Encrypt
  msg->encrypted_len = encryptMessage((uint8_t*)full_body, body_len, msg->encrypted_binary);

  if (msg->encrypted_len == 0) {
    Serial.println("[Queue] Encryption failed!");
    delete[] msg->encrypted_binary;
    msg->encrypted_binary = nullptr;
    return; // Don't add to queue
  }

  queueTail = (queueTail + 1) % MAX_QUEUE_SIZE;
  queueCount++;

  Serial.println("[Queue] Added msg #" + String(msg->msgId) + " (size: " + String(msg->encrypted_len) + " bytes)");
}

void clearMessageBuffer(QueuedMessage* msg) {
  if (msg->encrypted_binary != nullptr) {
    delete[] msg->encrypted_binary;
    msg->encrypted_binary = nullptr; // Prevents double-deletion crashes
    msg->encrypted_len = 0;
  }
}

void waitForAUX() {
  // If AUX is LOW, the LoRa module is busy.
  // We wait (with a timeout) for it to go HIGH.
  unsigned long start = millis();
  while (digitalRead(AUX_PIN) == LOW && (millis() - start < 1000)) {
    esp_task_wdt_reset(); // Feed the dog while waiting
    delay(1);
  }
}

// Unifies logic: If enable_queue is FALSE, we still track status but don't retry after timeout.
void processQueue() {
  if (queueCount == 0) return;
  
  unsigned long now = millis();
  
  for (int i = 0; i < queueCount; i++) {
    int idx = (queueHead + i) % MAX_QUEUE_SIZE;
    QueuedMessage* msg = &messageQueue[idx];
    
    if (msg->status == MSG_ACKED || msg->status == MSG_FAILED) continue;
    
    // Check if it's time to retry or send for the first time
    if (msg->status == MSG_PENDING || 
        (msg->status == MSG_SENT && now - msg->lastTry >= config.retry_delay_ms)) {
      
      // If this is a RETRY attempt (status is SENDING)
      if (msg->status == MSG_SENT) {
         // If Queue disabled, we do NOT retry. Fail immediately on timeout.
         if (!config.enable_queue) {
            msg->status = MSG_FAILED;
            Serial.println("[Queue] No ACK received (Retries disabled). Marked FAILED.");
            continue;
         }
         
         // If Queue enabled, check retry limit
         if (msg->retries >= config.max_retries) {
            msg->status = MSG_FAILED;
            clearMessageBuffer(msg);
            Serial.println("[Queue] Message #" + String(msg->msgId) + " failed after " + 
                          String(msg->retries) + " retries");
            continue;
         }
      }
      
      // Send message
      waitForAUX();
      Serial2.write(0xAA);             // Sync Word: "Attention!"
      Serial2.write(msg->encrypted_len); // Length: "Here is how much to read"
      Serial2.write(msg->encrypted_binary, msg->encrypted_len); // Payload
      msg->status = MSG_SENT;
      msg->lastTry = now;
      msg->retries++;
      
      if (msg->retries == 1) {
         Serial.println("[Queue] Sent msg #" + String(msg->msgId));
      } else {
         Serial.println("[Queue] Retrying msg #" + String(msg->msgId) + 
                    " (attempt " + String(msg->retries) + "/" + String(config.max_retries) + ")");
      }
    }
  }
}


void markMessageSent(uint32_t msgId) {
  for (int i = 0; i < queueCount; i++) {
    int idx = (queueHead + i) % MAX_QUEUE_SIZE;
    if (messageQueue[idx].msgId == msgId) {
      messageQueue[idx].status = MSG_ACKED;
      clearMessageBuffer(&messageQueue[idx]);
      Serial.println("[Queue] Message #" + String(msgId) + " confirmed delivered!");
      return;
    }
  }
}

void retryMessage(uint32_t msgId) {
  for (int i = 0; i < queueCount; i++) {
    int idx = (queueHead + i) % MAX_QUEUE_SIZE;
    if (messageQueue[idx].msgId == msgId) {
      messageQueue[idx].status = MSG_PENDING;
      messageQueue[idx].retries = 0;
      Serial.println("[Queue] Manually retrying message #" + String(msgId));
      return;
    }
  }
}


String getQueueStatus() {
  String json = "[";
  
  for (int i = 0; i < queueCount; i++) {
    int idx = (queueHead + i) % MAX_QUEUE_SIZE;
    QueuedMessage* msg = &messageQueue[idx];
    
    if (i > 0) json += ",";
    
    json += "{\"id\":" + String(msg->msgId) + ",";
    json += "\"content\":\"" + msg->content + "\",";
    json += "\"status\":\"";
    
    switch(msg->status) {
      case MSG_PENDING: json += "pending"; break;
      case MSG_SENT: json += "sent"; break;
      case MSG_ACKED: json += "acked"; break;
      case MSG_FAILED: json += "failed"; break;
    }
    
    json += "\",\"retries\":" + String(msg->retries) + "}";
  }
  
  json += "]";
  return json;
}

// ========================
// MESSAGE LOG FUNCTIONS
// ========================

void addToLog(String message) {
  messageLog[logIndex] = message;
  logIndex = (logIndex + 1) % MAX_LOG_SIZE;
  if (logCount < MAX_LOG_SIZE) logCount++;
}

String getLogMessages() {
  String result = "[";
  
  if (logCount == 0) {
    result += "]";
    return result;
  }
  
  int startIndex = (logCount < MAX_LOG_SIZE) ? 0 : logIndex;
  
  for (int i = 0; i < logCount; i++) {
    int idx = (startIndex + i) % MAX_LOG_SIZE;
    if (i > 0) result += ",";
    
    String msg = messageLog[idx];
    msg.replace("\"", "\\\"");
    msg.replace("\n", "\\n");
    
    result += "\"" + msg + "\"";
  }
  
  result += "]";
  return result;
}

void clearLog() {
  logIndex = 0;
  logCount = 0;
}

// ========================
// LORA MESSAGE HANDLING
// ========================

void sendMessage(String content) {
  // Always add to queue structure to track ACK/Status
  addToQueue(content);
  
  // Add to local log immediately
  String timestamp = String(millis() / 1000);
  addToLog("You [" + timestamp + "s]: " + content);
}

void sendAck(uint32_t msgId) {
  // Build signature input
  char sig_input[32];
  int sig_len = snprintf(sig_input, sizeof(sig_input), "%u", msgId);
  
  // Generate signature (raw bytes)
  uint8_t signature_bytes[16];
  signMessageBytes((uint8_t*)sig_input, sig_len, signature_bytes);
  
  // Convert to base64
  String signature_b64 = base64_encode(signature_bytes, 16);
  
  // Build ACK body
  char ackBody[128];
  snprintf(ackBody, sizeof(ackBody), "A|%u|%s|ACK", msgId, signature_b64.c_str());
  
  // Encrypt
  uint8_t ackBin[128];
  size_t ackLen = encryptMessage((uint8_t*)ackBody, strlen(ackBody), ackBin);
  
  waitForAUX();
  Serial2.write(0xAA);
  Serial2.write((uint8_t)ackLen);
  Serial2.write(ackBin, ackLen); // SEND BINARY ACK
}

void processIncomingLoRa() {
  // 1. Look for the SYNC WORD (0xAA) to filter out urban noise
  if (Serial2.available() < 2) return; 
  if (Serial2.peek() != 0xAA) {
    Serial2.read(); // Discard noise byte
    return;
  }
  Serial2.read(); // Discard the Sync Word

  // 2. Read the LENGTH prefix
  uint8_t expectedLen = Serial2.read();

  // 3. Wait for the full packet to arrive
  uint8_t rxBuffer[256];
  unsigned long startWait = millis();
  size_t bytesRead = 0;

  while (bytesRead < expectedLen && (millis() - startWait < 500)) {
    if (Serial2.available()) {
      rxBuffer[bytesRead++] = Serial2.read();
    }
  }

  if (bytesRead < expectedLen) return; // Packet timed out/incomplete

  // 4. Decrypt Binary
  uint8_t decrypted[256];
  size_t decrypted_len = 0;
  if (!decryptMessage(rxBuffer, bytesRead, decrypted, &decrypted_len)) {
    Serial.println("[RX] Integrity/MAC Failed");
    return;
  }

  // 5. Zero-Copy Parsing (No String Objects)
  char* body = (char*)decrypted;
  char* type = strtok(body, "|");
  char* msgIdStr = strtok(NULL, "|");
  char* signature_b64 = strtok(NULL, "|");
  char* content = strtok(NULL, "|");

  if (!type || !msgIdStr || !signature_b64) return;

  uint32_t msgId = atol(msgIdStr);

  // 6. Build verification buffer
  char verifyBuf[256];
  size_t verifyLen;
  
  if (strcmp(type, "D") == 0) {
    if (!content) return;
    verifyLen = snprintf(verifyBuf, sizeof(verifyBuf), "%u|%s", msgId, content);
  } else {
    verifyLen = snprintf(verifyBuf, sizeof(verifyBuf), "%u", msgId);
  }
  
  // 7. ✅ OPTIMIZED: Decode signature from base64 to raw bytes
  uint8_t signature_bytes[16];
  size_t sig_decoded_len = base64_decode(String(signature_b64), signature_bytes);
  
  if (sig_decoded_len != 16) {
    Serial.println("[RX] Invalid signature length");
    return;
  }
  
  // 8. ✅ OPTIMIZED: Verify using raw bytes (no String allocation!)
  if (!verifySignatureBytes((uint8_t*)verifyBuf, verifyLen, signature_bytes)) {
    Serial.println("[RX] Signature verification failed");
    return;
  }


  // 7. Handle Logic
  if (strcmp(type, "D") == 0) {
    sendAck(msgId);
    addToLog("Them: " + String(content));
    Serial.printf("[RX] Message #%d: %s\n", msgId, String(content));
  } else if (strcmp(type, "A") == 0) {
    markMessageSent(msgId);
    Serial.print("[RX] ACK for message #" +  String(msgId));
  }
}

// ========================
// CONFIGURATION FUNCTIONS
// ========================

void saveConfig() {
  if (!preferences.begin("lora", false)) { 
    Serial.println("[Config] Error: Could not open Preferences");
    return;
  }
  preferences.putString("ap_ssid", config.ap_ssid);
  preferences.putString("ap_pass", config.ap_password);
  preferences.putBytes("aes_key", config.aes_key, 16);
  preferences.putBytes("hmac_key", config.hmac_key, 32);
  preferences.putUChar("channel", config.lora_channel);
  preferences.putUChar("power", config.lora_power);
  preferences.putUShort("rate", config.lora_rate);
  preferences.putUChar("address", config.lora_address);
  preferences.putUChar("net_id", config.network_id);
  preferences.putUChar("max_retry", config.max_retries);
  preferences.putUShort("retry_delay", config.retry_delay_ms);
  preferences.putUShort("ack_timeout", config.ack_timeout_ms);
  preferences.putBool("queue_en", config.enable_queue);
  
  preferences.end();
  
  Serial.println("[Config] Saved to flash");
}

void loadConfig() {
  preferences.begin("lora", true);
  
  if (preferences.isKey("ap_ssid")) {
    preferences.getString("ap_ssid").toCharArray(config.ap_ssid, 32);
    preferences.getString("ap_pass", "").toCharArray(config.ap_password, 32);
    preferences.getBytes("aes_key", config.aes_key, 16);
    preferences.getBytes("hmac_key", config.hmac_key, 32);
    config.lora_channel = preferences.getUChar("channel", 23);
    config.lora_power = preferences.getUChar("power", 20);
    config.lora_rate = preferences.getUShort("rate", 2400);
    config.lora_address = preferences.getUChar("address", 1);
    config.network_id = preferences.getUChar("net_id", 0);
    config.max_retries = preferences.getUChar("max_retry", 3);
    config.retry_delay_ms = preferences.getUShort("retry_delay", 5000);
    config.ack_timeout_ms = preferences.getUShort("ack_timeout", 3000);
    config.enable_queue = preferences.getBool("queue_en", true);
    
    Serial.println("[Config] Loaded from flash");
  } else {
    Serial.println("[Config] Using defaults");
  }
  
  preferences.end();
}

// ========================
// WEB SERVER HANDLERS
// ========================

void handleRoot() {
  wifiStartTime = millis();
  String html = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <meta charset="UTF-8">
  <title>🔐 LoRa Messenger</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { 
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      padding: 10px;
    }
    .container {
      max-width: 600px;
      margin: 0 auto;
      background: white;
      border-radius: 15px;
      box-shadow: 0 10px 40px rgba(0,0,0,0.3);
      overflow: hidden;
      display: flex;
      flex-direction: column;
      height: calc(100vh - 20px);
    }
    .header {
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      padding: 15px 20px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .header h1 { font-size: 20px; }
    .header .status { font-size: 11px; opacity: 0.9; margin-top: 3px; }
    .messages {
      flex: 1;
      overflow-y: auto;
      padding: 15px;
      background: #f5f5f5;
    }
    .message {
      margin-bottom: 12px;
      padding: 10px 15px;
      border-radius: 18px;
      max-width: 85%;
      word-wrap: break-word;
      animation: slideIn 0.3s ease;
    }
    @keyframes slideIn {
      from { opacity: 0; transform: translateY(10px); }
      to { opacity: 1; transform: translateY(0); }
    }
    .message.sent { background: #667eea; color: white; margin-left: auto; text-align: right; }
    .message.received { background: white; color: #333; border: 1px solid #e0e0e0; }
    .message .time { font-size: 10px; opacity: 0.7; margin-top: 4px; }
    .message .status {
      font-size: 9px;
      margin-top: 3px;
      opacity: 0.8;
    }
    .message.sending { opacity: 0.7; }
    .message.failed { opacity: 0.5; background: #ff6b6b; }
    .input-area {
      display: flex;
      padding: 12px;
      background: white;
      border-top: 1px solid #e0e0e0;
      gap: 8px;
    }
    #messageInput {
      flex: 1;
      padding: 12px 15px;
      border: 2px solid #e0e0e0;
      border-radius: 25px;
      font-size: 15px;
      outline: none;
    }
    #messageInput:focus { border-color: #667eea; }
    .btn {
      padding: 12px 20px;
      border: none;
      border-radius: 25px;
      font-size: 15px;
      font-weight: bold;
      cursor: pointer;
      transition: all 0.3s;
    }
    .btn-send { background: #667eea; color: white; }
    .btn-send:active { background: #5568d3; transform: scale(0.95); }
    .btn-settings { background: #ffa726; color: white; font-size: 13px; padding: 8px 16px; }
    .btn-clear { background: #ff6b6b; color: white; font-size: 13px; padding: 8px 16px; }
    .controls {
      padding: 10px 12px;
      background: #fafafa;
      border-top: 1px solid #e0e0e0;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 8px;
    }
    .controls .info { font-size: 11px; color: #666; }
    .empty-state { text-align: center; padding: 40px 20px; color: #999; }
    .empty-state .icon { font-size: 48px; margin-bottom: 10px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div>
        <h1>🔐 LoRa Messenger</h1>
        <div class="status">🔒 Encrypted + Signed</div>
      </div>
    </div>
    
    <div class="messages" id="messages">
      <div class="empty-state">
        <div class="icon">📭</div>
        <div>No messages yet</div>
      </div>
    </div>
    
    <div class="controls">
      <div class="info"><span id="msgCount">0</span> messages</div>
      <div style="display: flex; gap: 8px;">
        <button class="btn btn-settings" onclick="location.href='/settings'">⚙️ Settings</button>
        <button class="btn btn-clear" onclick="clearLog()">🗑️ Clear</button>
      </div>
    </div>
    
    <div class="input-area">
      <input type="text" id="messageInput" placeholder="Type a message..." 
             onkeypress="if(event.key==='Enter') sendMessage()">
      <button class="btn btn-send" onclick="sendMessage()">Send</button>
    </div>
  </div>
  
  <script>
    let lastMessageCount = 0;
    let messageIds = new Map();
    
    function sendMessage() {
      const input = document.getElementById('messageInput');
      const msg = input.value.trim();
      if (msg === '') return;
      
      fetch('/send?msg=' + encodeURIComponent(msg))
        .then(() => {
          input.value = '';
          updateMessages();
        });
    }
    
    function updateMessages() {
      Promise.all([
        fetch('/messages').then(r => r.json()),
        fetch('/queue').then(r => r.json()),
      ]).then(([messages, queue]) => {
        
        const container = document.getElementById('messages');
        const msgCount = document.getElementById('msgCount');
        
        if (messages.length === 0) {
          container.innerHTML = '<div class="empty-state"><div class="icon">📭</div><div>No messages yet</div></div>';
          msgCount.textContent = '0';
          return;
        }
        
        if (messages.length !== lastMessageCount) {
          container.innerHTML = '';
          
          messages.forEach(msg => {
            const div = document.createElement('div');
            const isSent = msg.startsWith('You ');
            div.className = 'message ' + (isSent ? 'sent' : 'received');
            
            const match = msg.match(/\[(.*?)\]: (.+)/);
            if (match) {
              const time = match[1];
              const text = match[2];
              div.innerHTML = `<div>${text}</div><div class="time">${time}</div>`;
              
              // Add status for sent messages
              if (isSent) {
                const queueItem = queue.find(q => q.content === text);
                if (queueItem) {
                  let statusText = '';
                  if (queueItem.status === 'sending') statusText = `⏳ Sending (${queueItem.retries})`;
                  else if (queueItem.status === 'sent') statusText = '✓ Delivered';
                  else if (queueItem.status === 'failed') statusText = '✗ Failed';
                  
                  if (statusText) {
                    div.innerHTML += `<div class="status">${statusText}</div>`;
                    div.classList.add(queueItem.status);
                  }
                }
              }
            } else {
              div.textContent = msg;
            }
            
            container.appendChild(div);
          });
          
          container.scrollTop = container.scrollHeight;
          msgCount.textContent = messages.length;
          lastMessageCount = messages.length;
        }
      });
    }
    
    function clearLog() {
      if (confirm('Clear all messages?')) {
        fetch('/clear').then(() => updateMessages());
      }
    }
    
    setInterval(updateMessages, 1000);
    updateMessages();
  </script>
</body>
</html>
)rawliteral";
  
  server.send(200, "text/html", html);
}

void handleFactoryReset() {
  if (server.method() == HTTP_POST) {
    preferences.begin("lora", false);
    preferences.clear();
    preferences.end();
    
    String html = "<html><head><meta http-equiv='refresh' content='5;url=/'></head><body><h1>Factory Reset!</h1><p>Device is restarting... Please reconnect to default WiFi.</p></body></html>";
    server.send(200, "text/html", html);
    
    delay(1000);
    ESP.restart();
  }
}

void handleSettings() {
  if (server.method() == HTTP_POST) {
    Serial.println("[Settings] POST Received");
    wifiStartTime = millis();
    
    // Update configuration from form
    if (server.hasArg("channel")) config.lora_channel = server.arg("channel").toInt();
    if (server.hasArg("power")) config.lora_power = server.arg("power").toInt();
    if (server.hasArg("rate")) config.lora_rate = server.arg("rate").toInt();
    if (server.hasArg("max_retries")) config.max_retries = server.arg("max_retries").toInt();
    if (server.hasArg("retry_delay")) config.retry_delay_ms = server.arg("retry_delay").toInt();
    
    // Update Boolean flags - Checkboxes only send value if checked
    // Using hasArg() is unsafe if the browser sends ?enable_queue=false (not standard but possible in some frameworks)
    // but standard forms send nothing OR send the value (usually "on" or "true").
    
    bool new_queue = server.hasArg("enable_queue");
    config.enable_queue = new_queue;
    // Handle key updates
    if (server.hasArg("aes_key")) {
      String keyStr = server.arg("aes_key");
      if (keyStr.length() == 32) { // 16 bytes in hex
        for (int i = 0; i < 16; i++) {
          String byteStr = keyStr.substring(i*2, i*2+2);
          config.aes_key[i] = strtol(byteStr.c_str(), NULL, 16);
        }
      }
    }
    
    if (server.hasArg("hmac_key")) {
      String keyStr = server.arg("hmac_key");
      if (keyStr.length() == 64) { // 32 bytes in hex
        for (int i = 0; i < 32; i++) {
          String byteStr = keyStr.substring(i*2, i*2+2);
          config.hmac_key[i] = strtol(byteStr.c_str(), NULL, 16);
        }
      }
    }
    
    saveConfig();
    initLoRaModule();
    
    server.send(200, "text/plain", "Settings saved! Restart recommended.");
    return;
  }
  
  
  // Convert keys to hex for display
  String aesHex = "";
  for (int i = 0; i < 16; i++) {
    if (config.aes_key[i] < 16) aesHex += "0";
    aesHex += String(config.aes_key[i], HEX);
  }
  
  String hmacHex = "";
  for (int i = 0; i < 32; i++) {
    if (config.hmac_key[i] < 16) hmacHex += "0";
    hmacHex += String(config.hmac_key[i], HEX);
  }
  
  String html = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>⚙️ Settings</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      padding: 20px;
    }
    .container {
      max-width: 600px;
      margin: 0 auto;
      background: white;
      border-radius: 15px;
      padding: 20px;
      box-shadow: 0 10px 40px rgba(0,0,0,0.3);
    }
    h1 { color: #667eea; margin-bottom: 20px; }
    .section { margin-bottom: 25px; }
    .section h2 { font-size: 16px; color: #666; margin-bottom: 10px; border-bottom: 2px solid #eee; padding-bottom: 5px; }
    label { display: block; margin: 10px 0 5px; font-size: 14px; color: #333; }
    input, select {
      width: 100%;
      padding: 10px;
      border: 2px solid #e0e0e0;
      border-radius: 8px;
      font-size: 14px;
    }
    input:focus, select:focus { border-color: #667eea; outline: none; }
    .checkbox-group { display: flex; align-items: center; gap: 10px; }
    .checkbox-group input { width: auto; }
    .btn {
      padding: 12px 24px;
      border: none;
      border-radius: 25px;
      font-size: 15px;
      font-weight: bold;
      cursor: pointer;
      margin-right: 10px;
    }
    .btn-save { background: #4CAF50; color: white; }
    .btn-back { background: #999; color: white; }
    .warning {
      background: #fff3cd;
      border: 1px solid #ffc107;
      padding: 10px;
      border-radius: 5px;
      font-size: 13px;
      margin-bottom: 15px;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>⚙️ Settings</h1>
    
    <div class="warning">
      ⚠️ Both devices must have matching encryption keys and channel settings to communicate!
    </div>
    
    <form method="POST">
      <div class="section">
        <h2>📡 LoRa Configuration</h2>
        
        <label>Channel (0-83)</label>
        <input type="number" name="channel" value=")rawliteral" + String(config.lora_channel) + R"rawliteral(" min="0" max="83">
        
        <label>Transmission Power (10-20 dBm)</label>
        <input type="number" name="power" value=")rawliteral" + String(config.lora_power) + R"rawliteral(" min="10" max="20">
        
        <label>Air Data Rate (bps)</label>
        <select name="rate">
          <option value="1200")rawliteral" + (config.lora_rate == 1200 ? " selected" : "") + R"rawliteral(">1200</option>
          <option value="2400")rawliteral" + (config.lora_rate == 2400 ? " selected" : "") + R"rawliteral(">2400</option>
          <option value="4800")rawliteral" + (config.lora_rate == 4800 ? " selected" : "") + R"rawliteral(">4800</option>
        </select>
      </div>
      
      <div class="section">
        <h2>🔐 Security</h2>
        
        <label>AES Encryption Key (32 hex chars)</label>
        <input type="text" name="aes_key" value=")rawliteral" + aesHex + R"rawliteral(" maxlength="32" pattern="[0-9a-fA-F]{32}">
        
        <label>HMAC Signing Key (64 hex chars)</label>
        <input type="text" name="hmac_key" value=")rawliteral" + hmacHex + R"rawliteral(" maxlength="64" pattern="[0-9a-fA-F]{64}">
      </div>
      
      <div class="section">
        <h2>🔄 Message Queue</h2>
        
        <div class="checkbox-group">
          <input type="checkbox" name="enable_queue" %QUEUE_CHECKED%>
          <label style="margin: 0;">Enable message queue and retry</label>
        </div>
        
        <label>Max Retry Attempts</label>
        <input type="number" name="max_retries" value=")rawliteral" + String(config.max_retries) + R"rawliteral(" min="1" max="10">
        
        <label>Retry Delay (ms)</label>
        <input type="number" name="retry_delay" value=")rawliteral" + String(config.retry_delay_ms) + R"rawliteral(" min="1000" max="30000" step="1000">
      </div>
      
      <div style="margin-top: 20px;">
        <button type="submit" class="btn btn-save">💾 Save Settings</button>
        <button type="button" class="btn btn-back" onclick="location.href='/'">← Back</button>
      </div>
    </form>
    
    <div style="margin-top: 30px; border-top: 1px solid #eee; padding-top: 20px;">
      <form action="/reset_config" method="POST" onsubmit="return confirm('Use Factory Defaults? This will wipe all settings and restart.')">
         <button type="submit" class="btn" style="background: #ff4757; color: white;">⚠️ Factory Reset</button>
      </form>
    </div>
  </div>
</body>
</html>
)rawliteral";
    html.replace("%QUEUE_CHECKED%", config.enable_queue ? "checked" : "");
  server.send(200, "text/html", html);
}

void handleSend() {
  wifiStartTime = millis();
  if (server.hasArg("msg")) {
    sendMessage(server.arg("msg"));
    server.send(200, "text/plain", "OK");
  } else {
    server.send(400, "text/plain", "No message");
  }
}

void handleMessages() {
  wifiStartTime = millis();
  server.send(200, "application/json", getLogMessages());
}

void handleQueue() {
  wifiStartTime = millis();
  server.send(200, "application/json", getQueueStatus());
}

void handleRetry() {
  wifiStartTime = millis();
  if (server.hasArg("id")) {
    uint32_t msgId = server.arg("id").toInt();
    retryMessage(msgId);
    server.send(200, "text/plain", "OK");
  } else {
    server.send(400, "text/plain", "No message ID");
  }
}

void handleClear() {
  wifiStartTime = millis();
  clearLog();
  server.send(200, "text/plain", "OK");
}

// ========================
// SETUP
// ========================

void setup() {
  Serial.begin(115200);
  delay(1000);

  esp_task_wdt_config_t twdt_config = {
      .timeout_ms = 30000,    // 30 seconds (it now uses Milliseconds, not Seconds)
      .idle_core_mask = 0,    // Watch Core 0
      .trigger_panic = true   // Reboot on hang
  };
  
  esp_task_wdt_init(&twdt_config); // Initialize with struct
  esp_task_wdt_add(NULL);          // Add current task (loop)
  
  Serial.println("\n\n================================");
  Serial.println("  LoRa Encrypted Messenger v2.0");
  Serial.println("================================\n");
  
  // Configure pins
  pinMode(M0_PIN, OUTPUT);
  pinMode(M1_PIN, OUTPUT);
  pinMode(AUX_PIN, INPUT);
  
  pinMode(WIFI_WAKE_BTN, INPUT_PULLUP);
  
  // Hardware Factory Reset Check
  // If button is held during boot for >3 seconds
  if (digitalRead(WIFI_WAKE_BTN) == LOW) {
    Serial.println("[Setup] Boot button held... Waiting 3s for Factory Reset");
    unsigned long startHold = millis();
    bool reset = false;
    while (digitalRead(WIFI_WAKE_BTN) == LOW) {
      if (millis() - startHold > 3000) {
        reset = true;
        break;
      }
      delay(100);
    }
    
    if (reset) {
      Serial.println("[Setup] !!! FACTORY RESET TRIGGERED !!!");
      preferences.begin("lora", false);
      preferences.clear();
      preferences.end();
      // Blink to indicate done
      for(int i=0; i<5; i++) {
        digitalWrite(LORA_TX, HIGH); delay(100);
        digitalWrite(LORA_TX, LOW); delay(100);
      }
      Serial.println("[Setup] Config cleared. Restarting...");
      ESP.restart();
    }
  }

  // Load configuration
  loadConfig();
  // ADC pin doesn't need specific init for analogRead usually, but good practice
  // adcAttachPin(BATTERY_PIN); // Optional depending on core version
  
  setLoRaNormalMode();
  
  // Initialize LoRa
  Serial2.begin(9600, SERIAL_8N1, LORA_RX, LORA_TX);
  Serial.println("[Serial] LoRa UART @ 9600 baud");
  
  delay(500);
  initLoRaModule();
  
  // Create WiFi AP with reduced power for battery saving
  Serial.println("\n[WiFi] Creating Access Point...");
  WiFi.softAP(config.ap_ssid, config.ap_password);
  WiFi.setTxPower(WIFI_POWER_11dBm); // Reduce WiFi power
  
  IPAddress IP = WiFi.softAPIP();
  Serial.println("[WiFi] SSID: " + String(config.ap_ssid));
  Serial.println("[WiFi] IP: " + IP.toString());
  
  wifiStartTime = millis();
  wifiActive = true;
  
  // Configure web server
  server.on("/", handleRoot);
  server.on("/settings", handleSettings);
  server.on("/send", handleSend);
  server.on("/messages", handleMessages);
  server.on("/queue", handleQueue);
  server.on("/retry", handleRetry);
  server.on("/clear", handleClear);
  server.on("/reset_config", handleFactoryReset);
  
  server.begin();
  Serial.println("[Web] Server started");
  
  Serial.println("\n================================");
  Serial.println("✅ System Ready!");
  Serial.println("================================");
  Serial.println("\n📱 Connect: " + String(config.ap_ssid));
  Serial.println("🌐 Browse: http://" + IP.toString());
  Serial.println("🔐 Encryption: AES-128 + HMAC-SHA256");
  Serial.println("📡 Channel: " + String(config.lora_channel));
  Serial.println("🔋 Battery optimized");
  Serial.println("================================\n");
}

// ========================
// MAIN LOOP
// ========================

void loop() {
  // Deadman watch
  esp_task_wdt_reset();
  // WiFi Power Management
  if (wifiActive) {
    // Check timeout
    if (millis() - wifiStartTime > WIFI_TIMEOUT) {
      Serial.println("[Power] WiFi Timeout - Turning OFF");
      WiFi.softAPdisconnect(true);
      WiFi.mode(WIFI_OFF);
      wifiActive = false;
    } else {
      // Handle web requests if active
      server.handleClient();
    }
  }
  
  // Check Wake Button
  if (digitalRead(WIFI_WAKE_BTN) == LOW) { // Active Low
    if (!wifiActive) {
       Serial.println("[Power] Wake Button - Turning WiFi ON");
       WiFi.mode(WIFI_AP);
       WiFi.softAP(config.ap_ssid, config.ap_password);
       WiFi.setTxPower(WIFI_POWER_11dBm);
       wifiActive = true;
    }
    wifiStartTime = millis(); // Reset timer on press
    delay(200); // Debounce
  }
  
  // Process incoming LoRa messages
  processIncomingLoRa();
  
  // Process message queue
  processQueue();
  
  // Small delay to prevent CPU thrashing
  delay(10);
}
