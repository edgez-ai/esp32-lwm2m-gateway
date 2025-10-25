/* BSD Socket API Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_random.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/portable.h"
#include "freertos/task.h"
#include "nvs_flash.h"
#include "protocol_examples_common.h"
#include <esp_timer.h>
#include <string.h>
#include <strings.h>
#include <sys/param.h>
#include "esp_wifi.h"
#include "esp_sleep.h" // Required for esp_sleep_enable_ext0_wakeup
#include "driver/temp_sensor.h"
/* BLE logic moved to ble.c/ble.h */
#include "ble.h"
/* LoRa logic moved to lora.cpp/lora.h */
#include "lora.h"

 #include "lwip/err.h"
 #include "lwip/sockets.h"
 #include "lwip/sys.h"
 #include <lwip/netdb.h>
 #include "flash.h"
#include "lwm2m_client.h"
#include "device.h"
#include "lwm2m_helpers.h"
#include "crypto_test.h"

#include "liblwm2m.h"
#include "lwm2mclient.h"
extern lwm2m_object_t *objArray[6];

//#define LWM2M_SERVER_URI "coaps://192.168.10.148:5685"
static const char *TAG = "main";
static float tsens_out; /* local temperature reading passed to lwm2m module */
/* BLE GAP/GATT logic removed; now handled inside ble.c */

extern uint8_t public_key[64];
extern uint8_t private_key[64];
extern size_t public_key_len;
extern size_t private_key_len;
extern char pinCode[32];
extern char psk_key[64];
extern char server[128];

// Add prototypes for external functions if not already included
// These should match the actual signatures in ble.h and lora.h
// Protobuf-based implementation for ble_get_challenge_message (matches ble.c logic)
#include "pb_encode.h"
#include "lwm2m.pb.h"
#include <esp_random.h>

void ble_get_challenge_message(const uint8_t **buf, size_t *len) {
    static uint8_t challenge_buf[128];
    lwm2m_LwM2MDeviceChallenge challenge = lwm2m_LwM2MDeviceChallenge_init_zero;
    // Generate a random 32-bit nonce (avoid zero)
    uint32_t nonce = 0;
    do {
        nonce = esp_random();
    } while (nonce == 0);
    challenge.nounce = nonce;
    // Copy public key
    extern uint8_t public_key[64];
    extern size_t public_key_len;
    size_t pk_len = public_key_len > sizeof(challenge.public_key.bytes) ? sizeof(challenge.public_key.bytes) : public_key_len;
    memcpy(challenge.public_key.bytes, public_key, pk_len);
    challenge.public_key.size = pk_len;

    pb_ostream_t stream = pb_ostream_from_buffer(challenge_buf, sizeof(challenge_buf));
    bool status = pb_encode(&stream, lwm2m_LwM2MDeviceChallenge_fields, &challenge);
    if (status) {
        *buf = challenge_buf;
        *len = stream.bytes_written;
    } else {
        *buf = NULL;
        *len = 0;
    }
}

// Weak/test implementation for lora_send_message_bin
void lora_send_message_bin(const uint8_t *data, size_t len) {
    // For now, just log the data as hex and as string (if printable)
    ESP_LOGI(TAG, "lora_send_message_bin called with %d bytes", (int)len);
    ESP_LOG_BUFFER_HEX_LEVEL(TAG, data, len, ESP_LOG_INFO);
    // Optionally, send as string if printable
    bool is_printable = true;
    for (size_t i = 0; i < len; i++) {
        if (data[i] < 32 && data[i] != '\0' && data[i] != '\n' && data[i] != '\r') {
            is_printable = false;
            break;
        }
    }
    if (is_printable && len > 0) {
        char* str_copy = malloc(len + 1);
        if (str_copy) {
            memcpy(str_copy, data, len);
            str_copy[len] = '\0';
            lora_send_message(str_copy);
            free(str_copy);
        }
    }
    // Otherwise, just log (real implementation should send binary over LoRa)
}
void lora_message_received(const uint8_t* data, size_t length, float rssi, float snr) {
    ESP_LOGI(TAG, "🎯 LoRa message callback triggered!");
    ESP_LOGI(TAG, "   Length: %d bytes", length);
    ESP_LOGI(TAG, "   RSSI: %.2f dBm", rssi);
    ESP_LOGI(TAG, "   SNR: %.2f dB", snr);
    
    // Print as hex for binary data
    ESP_LOG_BUFFER_HEX_LEVEL(TAG, data, length, ESP_LOG_INFO);
    
    // Try to print as string if it appears to be text
    bool is_printable = true;
    for (size_t i = 0; i < length; i++) {
        if (data[i] < 32 && data[i] != '\0' && data[i] != '\n' && data[i] != '\r') {
            is_printable = false;
            break;
        }
    }
    
    if (is_printable && length > 0) {
        char* str_copy = malloc(length + 1);
        if (str_copy) {
            memcpy(str_copy, data, length);
            str_copy[length] = '\0';
            ESP_LOGI(TAG, "   Text: %s", str_copy);
            free(str_copy);
        }
    }
    
    // Signal quality assessment
    if (rssi > -80) {
        ESP_LOGI(TAG, "   Signal quality: Excellent");
    } else if (rssi > -100) {
        ESP_LOGI(TAG, "   Signal quality: Good");
    } else if (rssi > -120) {
        ESP_LOGI(TAG, "   Signal quality: Fair");
    } else {
        ESP_LOGI(TAG, "   Signal quality: Poor");
    }
}


// Periodically send BLE challenge protobuf message over LoRa
void lora_challenge_task(void *pvParameters) {
    while (1) {
        // Get the challenge protobuf message from BLE logic
        // Assume ble_get_challenge_message() returns pointer to buffer and length
        const uint8_t *challenge_buf = NULL;
        size_t challenge_len = 0;
        ble_get_challenge_message(&challenge_buf, &challenge_len);
        if (challenge_buf && challenge_len > 0) {
            lora_send_message_bin(challenge_buf, challenge_len);
            ESP_LOGI(TAG, "Sent challenge protobuf message over LoRa (%d bytes)", (int)challenge_len);
        } else {
            ESP_LOGW(TAG, "No challenge message available from BLE");
        }
        vTaskDelay(pdMS_TO_TICKS(15000)); // 15 seconds
    }
}


void app_main(void)
{
        // Default config
    temp_sensor_config_t temp_sensor = TSENS_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(temp_sensor_set_config(temp_sensor));
    ESP_ERROR_CHECK(temp_sensor_start());
    objArray[2] = get_object_device();
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    ESP_ERROR_CHECK(read_factory_and_parse(pinCode, sizeof(pinCode), psk_key, sizeof(psk_key), server, sizeof(server)));

    ESP_ERROR_CHECK(example_connect());
    /* DTLS log level now set inside lwm2m_client_start() */
    ESP_ERROR_CHECK(temp_sensor_read_celsius(&tsens_out));
    ESP_LOGI(TAG, "Temperature: %.2f °C", tsens_out);

    /* Initialize device ring buffer with persistence */
    ESP_ERROR_CHECK(device_ring_buffer_init_with_persistence());

    /* Example: Add some test devices to demonstrate ring buffer functionality */
    ESP_LOGI(TAG, "Demonstrating device ring buffer functionality...");
        
    device_ring_buffer_print_status();

    /* Start LwM2M client task (moved to lwm2m_client.c) */
    lwm2m_client_start();
    
    /* Test ECDH with real key generation (using CORRECTED implementation) */
    test_ecdh_crypto_with_keygen();

    /* Start BLE client (scanning + handshake) */
    esp_err_t ble_ret = ble_client_init_and_start();
    if (ble_ret != ESP_OK) {
        ESP_LOGE(TAG, "BLE init failed: %s", esp_err_to_name(ble_ret));
    }

    /* Initialize and start LoRa module with listen-before-send pattern */
    esp_err_t lora_ret = lora_init();
    if (lora_ret != ESP_OK) {
        ESP_LOGE(TAG, "LoRa init failed: %s", esp_err_to_name(lora_ret));
    } else {
        lora_ret = lora_start_task(lora_message_received);
        if (lora_ret != ESP_OK) {
            ESP_LOGE(TAG, "LoRa task start failed: %s", esp_err_to_name(lora_ret));
        } else {
            ESP_LOGI(TAG, "LoRa module initialized and task started successfully");
            ESP_LOGI(TAG, "🎯 LoRa is now listening with callback support");

            // Start periodic LoRa challenge message task
            xTaskCreate(lora_challenge_task, "lora_challenge_task", 4096, NULL, 5, NULL);
        }
    }
}

