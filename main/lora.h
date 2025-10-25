#ifndef LORA_H
#define LORA_H

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize LoRa module
 * 
 * @return esp_err_t ESP_OK on success, error code otherwise
 */
esp_err_t lora_init(void);

/**
 * @brief Start LoRa communication task
 * 
 * @return esp_err_t ESP_OK on success, error code otherwise
 */
esp_err_t lora_start_task(void);

/**
 * @brief Send a message via LoRa
 * 
 * @param message The message to send
 * @return esp_err_t ESP_OK on success, error code otherwise
 */
esp_err_t lora_send_message(const char* message);

/**
 * @brief Stop LoRa task
 */
void lora_stop_task(void);

#ifdef __cplusplus
}
#endif

#endif // LORA_H