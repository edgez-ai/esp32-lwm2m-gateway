#ifndef LORA_H
#define LORA_H

#include "esp_err.h"

#ifdef CONFIG_ENABLE_LORA

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Callback function type for received LoRa messages
 * 
 * @param data Received data
 * @param length Length of received data
 * @param rssi Signal strength in dBm
 * @param snr Signal-to-noise ratio in dB
 */
typedef void (*lora_receive_callback_t)(const uint8_t* data, size_t length, float rssi, float snr);

/**
 * @brief Initialize LoRa module
 * 
 * @return esp_err_t ESP_OK on success, error code otherwise
 */
esp_err_t lora_init(void);

/**
 * @brief Start LoRa communication task with listen-before-send pattern
 * 
 * @param receive_callback Callback function for received messages (optional, can be NULL)
 * @return esp_err_t ESP_OK on success, error code otherwise
 */
esp_err_t lora_start_task(lora_receive_callback_t receive_callback);

/**
 * @brief Send a message via LoRa (will listen first, then send when channel is clear)
 * 
 * @param message The message to send
 * @return esp_err_t ESP_OK on success, error code otherwise
 */
esp_err_t lora_send_message(const char* message);

/**
 * @brief Send a message via LoRa with custom listen timeout
 * 
 * @param message The message to send
 * @param listen_timeout_ms Time to listen before sending (ms)
 * @return esp_err_t ESP_OK on success, error code otherwise
 */
esp_err_t lora_send_message_with_timeout(const char* message, uint32_t listen_timeout_ms);

/**
 * @brief Send binary data via LoRa (will listen first, then send when channel is clear)
 * 
 * @param data Binary data to send
 * @param length Length of data in bytes
 * @return esp_err_t ESP_OK on success, error code otherwise
 */
esp_err_t lora_send_binary(const uint8_t* data, size_t length);

/**
 * @brief Send binary data via LoRa with custom listen timeout
 * 
 * @param data Binary data to send
 * @param length Length of data in bytes
 * @param listen_timeout_ms Time to listen before sending (ms)
 * @return esp_err_t ESP_OK on success, error code otherwise
 */
esp_err_t lora_send_binary_with_timeout(const uint8_t* data, size_t length, uint32_t listen_timeout_ms);

/**
 * @brief Check if LoRa channel is busy (receiving a signal)
 * 
 * @return true if channel is busy, false if clear
 */
bool lora_is_channel_busy(void);

/**
 * @brief Stop LoRa task
 */
void lora_stop_task(void);

#ifdef __cplusplus
}
#endif

#endif // CONFIG_ENABLE_LORA

#endif // LORA_H