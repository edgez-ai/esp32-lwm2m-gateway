#ifndef LORA_H
#define LORA_H

#include "esp_err.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize LoRa module and start scanning for devices
 * Similar to ble_client_init_and_start()
 * 
 * @return esp_err_t ESP_OK on success, error code otherwise
 */
esp_err_t lora_client_init_and_start(void);

/**
 * @brief Stop LoRa scanning and communication
 * Similar to ble_client_stop_scan()
 * 
 * @return esp_err_t ESP_OK on success, error code otherwise
 */
esp_err_t lora_client_stop_scan(void);

/**
 * @brief Check if LoRa handshake with a device is completed
 * Similar to ble_client_handshake_done()
 * 
 * @return true if handshake completed, false otherwise
 */
bool lora_client_handshake_done(void);

/**
 * @brief Get count of pending device challenges
 * Similar to ble_client_get_pending_challenges_count()
 * 
 * @return uint32_t Number of pending challenges
 */
uint32_t lora_client_get_pending_challenges_count(void);

/**
 * @brief Clean up stale challenges that have exceeded timeout
 * Similar to ble_client_cleanup_stale_challenges()
 */
void lora_client_cleanup_stale_challenges(void);

/**
 * @brief Find pending challenge by device address
 * Similar to ble_client_find_challenge_by_address()
 * 
 * @param addr Device address (LoRa device ID)
 * @param serial_out Output parameter for device serial
 * @param model_out Output parameter for device model
 * @return true if challenge found, false otherwise
 */
bool lora_client_find_challenge_by_address(uint32_t addr, uint32_t *serial_out, uint32_t *model_out);

/**
 * @brief Send a raw message via LoRa
 * 
 * @param message The message to send
 * @return esp_err_t ESP_OK on success, error code otherwise
 */
esp_err_t lora_send_message(const char* message);

/**
 * @brief Send protobuf data via LoRa
 * 
 * @param data Protobuf data buffer
 * @param data_len Length of data
 * @param target_addr Target device address (0 for broadcast)
 * @return esp_err_t ESP_OK on success, error code otherwise
 */
esp_err_t lora_send_protobuf_data(const uint8_t *data, size_t data_len, uint32_t target_addr);

/**
 * @brief Set LoRa parameters (frequency, bandwidth, spreading factor, etc.)
 * 
 * @param frequency Frequency in MHz (e.g. 433.0, 868.0, 915.0)
 * @param bandwidth Bandwidth in kHz (e.g. 125, 250, 500)
 * @param spreading_factor Spreading factor (6-12)
 * @param coding_rate Coding rate (5-8, representing 4/5 to 4/8)
 * @return esp_err_t ESP_OK on success, error code otherwise
 */
esp_err_t lora_set_parameters(float frequency, float bandwidth, uint8_t spreading_factor, uint8_t coding_rate);

/**
 * @brief Get LoRa signal quality of last received packet
 * 
 * @param rssi Output parameter for RSSI
 * @param snr Output parameter for SNR
 * @return esp_err_t ESP_OK on success, error code otherwise
 */
esp_err_t lora_get_signal_quality(float *rssi, float *snr);

#ifdef __cplusplus
}
#endif

#endif // LORA_H