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

/* Returns the current number of pending device challenges */
uint32_t ble_client_get_pending_challenges_count(void);

/* Clean up stale challenges that have exceeded timeout */
void ble_client_cleanup_stale_challenges(void);

/* Find pending challenge by BLE address */
bool ble_client_find_challenge_by_address(const uint8_t *addr, uint32_t *serial_out, uint32_t *model_out);

/* ChaCha20-Poly1305 decryption function */
bool chacha20_poly1305_decrypt_with_nonce(const uint8_t *in, size_t in_len,
                                         uint8_t *out, size_t out_cap,
                                         uint32_t nonce32, const uint8_t *peer_pub,
                                         size_t peer_pub_len);

#ifdef __cplusplus
}
#endif
