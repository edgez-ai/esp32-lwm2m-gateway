/*
 * BLE client / scanner abstraction extracted from main2.c
 * Provides a single entry point to initialize BLE stack, register callbacks,
 * start extended scanning, parse periodic advertising payloads containing
 * LwM2M protobuf messages, and perform a lightweight GATT challenge handshake.
 */

#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize BLE controller, Bluedroid stack, register GAP & GATTC callbacks,
 * and start extended scanning. Safe to call once; subsequent calls return ESP_OK.
 */
esp_err_t ble_client_init_and_start(void);

/* Stop extended scanning (if running). Returns ESP_OK if command queued. */
esp_err_t ble_client_stop_scan(void);

/* Returns true once the GATT handshake (challenge/response + final OK write) has completed. */
bool ble_client_handshake_done(void);

#ifdef __cplusplus
}
#endif
