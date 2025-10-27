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
#include <pb_decode.h>
#include <pb_encode.h>
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

/* Conditional minimal crypto support for ChaCha20-Poly1305 */
#if defined(CONFIG_MBEDTLS_CHACHA20_C) && defined(CONFIG_MBEDTLS_POLY1305_C)
#include "mbedtls/chacha20.h"
#include "mbedtls/poly1305.h"
#define HAS_CHACHA20_POLY1305 1
#else
#define HAS_CHACHA20_POLY1305 0
#endif

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

// Add global variables for signature verification
static uint32_t current_challenge_nonce = 0;
extern uint8_t vendor_public_key[32];

// Add prototypes for external functions if not already included
// These should match the actual signatures in ble.h and lora.h
// Protobuf-based implementation for ble_get_challenge_message (matches ble.c logic)
#include "pb_encode.h"
#include "lwm2m.pb.h"
#include <esp_random.h>

void ble_get_challenge_message(const uint8_t **buf, size_t *len) {
    static uint8_t challenge_buf[128];
    lwm2m_LwM2MMessage message = lwm2m_LwM2MMessage_init_zero;
    message.which_body = lwm2m_LwM2MMessage_device_challenge_tag;
    uint32_t nonce = 0;
    do {
        nonce = esp_random();
    } while (nonce == 0);
    message.body.device_challenge.nounce = nonce;
    current_challenge_nonce = nonce; // Store for verification
    // Copy public key
    extern uint8_t public_key[64];
    extern size_t public_key_len;
    size_t pk_len = public_key_len > sizeof(message.body.device_challenge.public_key.bytes) ? sizeof(message.body.device_challenge.public_key.bytes) : public_key_len;
    memcpy(message.body.device_challenge.public_key.bytes, public_key, pk_len);
    message.body.device_challenge.public_key.size = pk_len;

    pb_ostream_t stream = pb_ostream_from_buffer(challenge_buf, sizeof(challenge_buf));
    bool status = pb_encode(&stream, lwm2m_LwM2MMessage_fields, &message);
    if (status) {
        *buf = challenge_buf;
        *len = stream.bytes_written;
    } else {
        *buf = NULL;
        *len = 0;
    }
}

// Proper implementation for lora_send_message_bin using the new binary LoRa function
void lora_send_message_bin(const uint8_t *data, size_t len) {
    ESP_LOGI(TAG, "lora_send_message_bin called with %d bytes", (int)len);
    ESP_LOG_BUFFER_HEX_LEVEL(TAG, data, len, ESP_LOG_INFO);

    // Use the proper binary LoRa send function instead of escaping
    esp_err_t ret = lora_send_binary(data, len);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to send binary data via LoRa: %s", esp_err_to_name(ret));
    }
}


/* LoRa receive callback function */
void lora_message_received(const uint8_t* data, size_t length, float rssi, float snr) {
    ESP_LOGI(TAG, "🎯 LoRa message callback triggered!");
    ESP_LOGI(TAG, "   Length: %d bytes", length);
    ESP_LOGI(TAG, "   RSSI: %.2f dBm", rssi);
    ESP_LOGI(TAG, "   SNR: %.2f dB", snr);
    
    // Print as hex for binary data
    ESP_LOG_BUFFER_HEX_LEVEL(TAG, data, length, ESP_LOG_INFO);

    // No need to unescape since we're using proper binary transmission now
    // Try to decode as LwM2MMessage protobuf message directly
    if (length > 0) {
        pb_istream_t istream = pb_istream_from_buffer(data, length);
        lwm2m_LwM2MMessage message = lwm2m_LwM2MMessage_init_zero;

        if (pb_decode(&istream, lwm2m_LwM2MMessage_fields, &message)) {
            ESP_LOGI(TAG, "✅ Successfully decoded LwM2MMessage!");
            ESP_LOGI(TAG, "   Model: %ld, Serial: %ld", message.model, message.serial);
            
            // For any message from a known device, update RSSI for connection monitoring
            lwm2m_LwM2MDevice *existing_device = device_ring_buffer_find_by_serial(message.serial);
            if (existing_device != NULL) {
                ESP_LOGI(TAG, "Message from known device (serial: %ld), updating RSSI", message.serial);
                lwm2m_update_device_rssi(existing_device->instance_id, (int)rssi);
            }
            
            // Check which message type was received
            if (message.which_body == lwm2m_LwM2MMessage_device_challenge_tag) {
                ESP_LOGI(TAG, "   Received device challenge message");
                ESP_LOGI(TAG, "   Nonce: %u", message.body.device_challenge.nounce);
                ESP_LOGI(TAG, "   Public Key Length: %d bytes", message.body.device_challenge.public_key.size);
                if (message.body.device_challenge.public_key.size > 0) {
                    ESP_LOG_BUFFER_HEX_LEVEL(TAG, message.body.device_challenge.public_key.bytes, 
                                           message.body.device_challenge.public_key.size, ESP_LOG_INFO);
                }
            } else if (message.which_body == lwm2m_LwM2MMessage_device_challenge_answer_tag) {
                ESP_LOGI(TAG, "   Received device challenge answer");
                ESP_LOGI(TAG, "   Public Key Length: %d bytes", message.body.device_challenge_answer.public_key.size);
                ESP_LOGI(TAG, "   Signature Length: %d bytes", message.body.device_challenge_answer.signature.size);
                
                // Check if the device is already known and update RSSI for connection monitoring
                lwm2m_LwM2MDevice *existing_device = device_ring_buffer_find_by_public_key(
                        message.body.device_challenge_answer.public_key.bytes,
                        message.body.device_challenge_answer.public_key.size);
                
                if (existing_device != NULL) {
                    ESP_LOGI(TAG, "Device already known (serial: %ld), updating RSSI and skipping verification", existing_device->serial);
                    
                    // Update connectivity monitoring RSSI for existing device
                    lwm2m_update_device_rssi(existing_device->instance_id, (int)rssi);
                    
                    return;
                }
                if (message.body.device_challenge_answer.signature.size > 0) {
                    ESP_LOG_BUFFER_HEX_LEVEL(TAG, message.body.device_challenge_answer.signature.bytes, 
                                           message.body.device_challenge_answer.signature.size, ESP_LOG_INFO);
                }
                
                // verify signature using factory public key
                if (message.body.device_challenge_answer.signature.size > 0 && current_challenge_nonce != 0) {
                    if (message.body.device_challenge_answer.public_key.size < 32) {
                        ESP_LOGE(TAG, "Challenge answer missing peer public key (size=%u)",
                                 (unsigned)message.body.device_challenge_answer.public_key.size);
                    } else if (message.body.device_challenge_answer.signature.size <= 16) {
                        ESP_LOGE(TAG, "Challenge answer signature too short (%u)",
                                 (unsigned)message.body.device_challenge_answer.signature.size);
                    } else {
                        uint8_t decrypted_signature[64]; // Buffer to hold decrypted factory signature
                        size_t decrypted_len = message.body.device_challenge_answer.signature.size - 16; // Remove tag length

                        if (decrypted_len > sizeof(decrypted_signature)) {
                            ESP_LOGE(TAG, "Decrypted signature would overflow buffer (%u)",
                                     (unsigned)decrypted_len);
                    } else {
                        ESP_LOGI(TAG, "Decrypting signature (%u bytes) using nonce %u", 
                                 (unsigned)message.body.device_challenge_answer.signature.size, (unsigned)current_challenge_nonce);
                        
                        // Note: chacha20_poly1305_decrypt_with_nonce function needs to be available
                        // For now, assuming it's implemented elsewhere or we need to copy it
                        bool decrypt_success = chacha20_poly1305_decrypt_with_nonce(message.body.device_challenge_answer.signature.bytes, 
                                                                                    message.body.device_challenge_answer.signature.size, 
                                                                                    decrypted_signature, 
                                                                                    sizeof(decrypted_signature),
                                                                                    current_challenge_nonce,
                                                                                    message.body.device_challenge_answer.public_key.bytes,
                                                                                    message.body.device_challenge_answer.public_key.size);
                        
                        if (decrypt_success) {
                            ESP_LOGI(TAG, "Successfully decrypted signature (%u bytes)", (unsigned)decrypted_len);
                            ESP_LOG_BUFFER_HEX_LEVEL(TAG, decrypted_signature, decrypted_len, ESP_LOG_INFO);

                            if (message.body.device_challenge_answer.public_key.size != 32) {
                                ESP_LOGE(TAG, "Unexpected public key length %u in challenge answer",
                                         (unsigned)message.body.device_challenge_answer.public_key.size);
                            } else if (decrypted_len != 64) {
                                ESP_LOGE(TAG, "Unexpected factory signature length: %u", (unsigned)decrypted_len);
                            } else {

                                            /* Construct message as: serial_string + device_public_key (like Java) */
                                char serial_str[32];
                                snprintf(serial_str, sizeof(serial_str), "%ld", message.serial);
                                size_t serial_len = strlen(serial_str);
                                
                                /* Allocate buffer for full message */
                                size_t full_msg_len = serial_len + message.body.device_challenge_answer.public_key.size;
                                uint8_t *full_message = malloc(full_msg_len);
                                int verify_ret = -1;
                                
                                if (full_message) {
                                    memcpy(full_message, serial_str, serial_len);
                                    memcpy(full_message + serial_len, message.body.device_challenge_answer.public_key.bytes, message.body.device_challenge_answer.public_key.size);
                                    
                                    ESP_LOGI(TAG, "Verifying signature with message: '%s' + device_key (%u bytes total)", 
                                            serial_str, (unsigned)full_msg_len);
                                    // For LoRa, we don't have a serial, so verify against device public key only
                                    int verify_ret = lwm2m_ed25519_verify_signature(vendor_public_key,
                                                                                    sizeof(vendor_public_key),
                                                                                    full_message,
                                                                                    full_msg_len,
                                                                                    decrypted_signature,
                                                                                    decrypted_len);
                                    
                                    memset(decrypted_signature, 0, decrypted_len);

                                    if (verify_ret != 0) {
                                        ESP_LOGE(TAG, "Factory signature verification failed (err=%d)", verify_ret);
                                    } else {
                                        ESP_LOGI(TAG, "Factory signature verified successfully!");
                                        // when verified, add device to ring buffer or known devices
                                        device_ring_buffer_add_device(
                                            message.body.device_challenge_answer.public_key.bytes,
                                            message.body.device_challenge_answer.public_key.size,
                                            message.model,
                                            message.serial,
                                            lwm2m_ConnectionType_CONNECTION_LORA
                                        );
                                    }
                                }
                            }
                        } else {
                            ESP_LOGE(TAG, "Failed to decrypt signature");
                        }
                    }
                }
            } else {
                ESP_LOGW(TAG, "No signature to verify or no current challenge nonce");
                }
            } else if (message.which_body == lwm2m_LwM2MMessage_status_report_tag) {
                ESP_LOGI(TAG, "   Received status report from device serial %ld", message.serial);
                ESP_LOGI(TAG, "   Battery Level: %ld", message.body.status_report.battery_level);
                ESP_LOGI(TAG, "   Uptime: %ld seconds", message.body.status_report.uptime);
                // Additional status report processing could be added here
            } else {
                ESP_LOGI(TAG, "   Received other message type: %d", (int)message.which_body);
            }        } else {
            ESP_LOGW(TAG, "❌ Failed to decode as LwM2MMessage: %s", PB_GET_ERROR(&istream));
            
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

