/*
   LoRa Module for ESP32 LwM2M Gateway
   
   This module handles LoRa communication using RadioLib.
   Hardware configuration for Heltec ESP32S3 LoRa V3.2
*/

// include the library
#include <RadioLib.h>

// include the hardware abstraction layer
#include "EspHal.h"
#include "lora.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "lora";

// create a new instance of the HAL class for Heltec ESP32S3 LoRa V3.2
// Verified SPI pins for Heltec ESP32S3 LoRa V3.2: SCK=9, MISO=11, MOSI=10
static EspHal* hal = nullptr;

// now we can create the radio module for Heltec ESP32S3 LoRa V3.2 (SX1262)
// Verified pins for Heltec ESP32S3 LoRa V3.2:
// NSS pin:   8
// DIO1 pin:  14  
// NRST pin:  12
// BUSY pin:  13
static SX1262* radio = nullptr;

// Task handle for LoRa communication task
static TaskHandle_t lora_task_handle = nullptr;

// LoRa communication task
static void lora_task(void *pvParameters) {
    ESP_LOGI(TAG, "LoRa communication task started");
    
    // loop forever
    for(;;) {
        // send a packet
        ESP_LOGI(TAG, "[SX1262] Transmitting packet ... ");
        int state = radio->transmit("Hello World!");
        if(state == RADIOLIB_ERR_NONE) {
            // the packet was successfully transmitted
            ESP_LOGI(TAG, "success!");
        } else {
            ESP_LOGI(TAG, "failed, code %d", state);
        }

        // wait for a second before transmitting again
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

extern "C" esp_err_t lora_init(void) {
    ESP_LOGI(TAG, "Starting LoRa initialization...");
    
    // Create HAL instance
    hal = new EspHal(9, 11, 10);
    if (hal == nullptr) {
        ESP_LOGE(TAG, "Failed to create HAL instance");
        return ESP_ERR_NO_MEM;
    }
    
    // Initialize the HAL first
    ESP_LOGI(TAG, "Initializing HAL...");
    hal->init();
    
    // Add a delay to let the system stabilize
    hal->delay(100);
    
    // Create radio instance
    radio = new SX1262(new Module(hal, 8, 14, 12, 13));
    if (radio == nullptr) {
        ESP_LOGE(TAG, "Failed to create radio instance");
        delete hal;
        hal = nullptr;
        return ESP_ERR_NO_MEM;
    }
    
    // initialize just like with Arduino
    ESP_LOGI(TAG, "[SX1262] Initializing ... ");
    
    // Add some debug output
    ESP_LOGI(TAG, "SPI pins - SCK: 9, MISO: 11, MOSI: 10");
    ESP_LOGI(TAG, "LoRa pins - NSS: 8, DIO1: 14, RST: 12, BUSY: 13");
    
    int state = radio->begin();
    if (state != RADIOLIB_ERR_NONE) {
        ESP_LOGE(TAG, "SX1262 initialization failed, code %d", state);
        delete radio;
        delete hal;
        radio = nullptr;
        hal = nullptr;
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "SX1262 initialization success!");
    
    return ESP_OK;
}

extern "C" esp_err_t lora_start_task(void) {
    if (radio == nullptr || hal == nullptr) {
        ESP_LOGE(TAG, "LoRa not initialized. Call lora_init() first.");
        return ESP_ERR_INVALID_STATE;
    }
    
    // Create the LoRa communication task
    BaseType_t xReturned = xTaskCreate(
        lora_task,              // Function that implements the task
        "lora_task",            // Text name for the task
        4096,                   // Stack size in words, not bytes
        NULL,                   // Parameter passed into the task
        5,                      // Priority at which the task is created
        &lora_task_handle       // Used to pass back a handle by which the created task can be referenced
    );
    
    if (xReturned != pdPASS) {
        ESP_LOGE(TAG, "Failed to create LoRa task");
        return ESP_FAIL;
    }
    
    ESP_LOGI(TAG, "LoRa task started successfully");
    return ESP_OK;
}

extern "C" esp_err_t lora_send_message(const char* message) {
    if (radio == nullptr || hal == nullptr) {
        ESP_LOGE(TAG, "LoRa not initialized");
        return ESP_ERR_INVALID_STATE;
    }
    
    if (message == nullptr) {
        ESP_LOGE(TAG, "Message is null");
        return ESP_ERR_INVALID_ARG;
    }
    
    ESP_LOGI(TAG, "[SX1262] Transmitting message: %s", message);
    int state = radio->transmit(message);
    
    if (state == RADIOLIB_ERR_NONE) {
        ESP_LOGI(TAG, "Message sent successfully!");
        return ESP_OK;
    } else {
        ESP_LOGE(TAG, "Failed to send message, code %d", state);
        return ESP_FAIL;
    }
}

extern "C" void lora_stop_task(void) {
    if (lora_task_handle != nullptr) {
        vTaskDelete(lora_task_handle);
        lora_task_handle = nullptr;
        ESP_LOGI(TAG, "LoRa task stopped");
    }
    
    // Cleanup resources
    if (radio != nullptr) {
        delete radio;
        radio = nullptr;
    }
    
    if (hal != nullptr) {
        hal->term();
        delete hal;
        hal = nullptr;
    }
    
    ESP_LOGI(TAG, "LoRa module cleaned up");
}