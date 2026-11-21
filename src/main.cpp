// ============================================================
//  SpoolmanScale – Bambu NFC Tag Reader & Decoder
//  Board:   WT32-SC01 Plus (ESP32-S3)
//  Version: v0.8.3
//
//  Reads Bambu Lab MIFARE Classic tags, derives keys via KDF
//  (HKDF/SHA256, master key from Bambu-Research-Group/RFID-Tag-Guide),
//  displays all decoded data on screen and queries
//  Spoolman for weight + last_dried after each scan.
//
//  Wiring:
//    Pin 1 (+5V)  -> PN532 VCC
//    Pin 2 (GND)  -> PN532 GND
//    Pin 3 (IO1)  -> PN532 SDA (GPIO 10)
//    Pin 4 (IO2)  -> PN532 SCL (GPIO 11)
//    Pin 7 (IO5)  -> PN532 RSTO (brown) - module OUTPUT, not driven
//
//  PN532 DIP-Switches: SW1=ON, SW2=OFF -> I2C mode
//
//  Libraries:
//    - Adafruit PN532    by Adafruit
//    - Adafruit BusIO    by Adafruit
//    - LovyanGFX         by lovyan03
//    - lvgl              by lvgl (Version 8.3.11!)
//    - ArduinoJson       by Benoit Blanchon (Version 7.x)
//  mbedTLS + WiFi + HTTPClient are included in the ESP32 framework.
// ============================================================

#include <Arduino.h>
#include <esp_ota_ops.h>
#include "app/app_boot.h"
#include "app/app_loop.h"

// Arduino-ESP32 3.3.x otherwise confirms the image before setup() runs.
extern "C" bool verifyRollbackLater(void) { return true; }

// The Arduino loop task defaults to 8 kB. Everything in this firmware runs on
// it, and the deepest paths are LVGL button callbacks: loop() calls
// lv_timer_handler(), which dispatches touch input, which calls the callback,
// which may build a whole screen or do HTTP with JSON parsing. That nesting
// has overflowed the stack before, see the deferred lookups in spool_flow.cpp.
// Doubling it costs internal RAM once and removes a whole class of panic
// reboots. The heartbeat logs the watermark so the real usage stays visible.
SET_LOOP_TASK_STACK_SIZE(16 * 1024);

#include "hardware/sd_logger.h"

void setup() {
  // Before anything that logs, so the ring holds the whole boot.
  logRingInit();
  appSetup();
}

void loop() {
  appLoop();

  // Confirm a candidate only after setup completed and the application loop
  // has been healthy for 30 seconds. Do not depend on network availability.
  static uint32_t first_healthy_loop_ms = 0;
  static uint32_t completed_loops = 0;
  static bool validation_finished = false;
  if (validation_finished) return;
  if (first_healthy_loop_ms == 0) first_healthy_loop_ms = millis();
  if (completed_loops < 10) ++completed_loops;
  if (completed_loops < 10 ||
      (uint32_t)(millis() - first_healthy_loop_ms) < 30000UL) return;

  const esp_partition_t *running = esp_ota_get_running_partition();
  esp_ota_img_states_t state = ESP_OTA_IMG_UNDEFINED;
  const esp_err_t status = esp_ota_get_state_partition(running, &state);
  if (status != ESP_OK || state != ESP_OTA_IMG_PENDING_VERIFY) {
    validation_finished = true;
    return;
  }
  const esp_err_t confirmed = esp_ota_mark_app_valid_cancel_rollback();
  if (confirmed == ESP_OK) {
    Serial.println("OTA: application healthy; image confirmed");
    validation_finished = true;
  } else {
    Serial.printf("OTA: confirmation failed (0x%x); will retry\n", (unsigned)confirmed);
    delay(1000);
  }
}
