/*
 * LoRa Client Module for ESP32 LwM2M Gateway
 * 
 * This module provides LoRa functionality similar to the BLE client implementation.
 * It handles device discovery, challenge-response authentication, and protobuf messaging
 * over LoRa radio using RadioLib.
 * 
 * Hardware configuration for Heltec ESP32S3 LoRa V3.2
 */

#include <RadioLib.h>
#include "EspHal.h"
#include "lora.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "esp_err.h"
#include "esp_random.h"

#include "pb_decode.h"
#include "pb_encode.h"
#include "lwm2m.pb.h"
#include "lwm2m_helpers.h"

#include "device.h"
#include "lwm2m_client.h"

/* Include LwM2M gateway object definitions */
#include "../components/wakaama/examples/client/object_gateway.h"
#include "../components/wakaama/examples/client/lwm2mclient.h"

/* External declarations for lwm2m objects */
extern lwm2m_object_t *objArray[11];

/* Conditional minimal crypto support */
#ifdef CONFIG_MBEDTLS_AES_C
#include "mbedtls/aes.h"
#else
typedef struct { int dummy; } mbedtls_aes_context; 
static void mbedtls_aes_init(mbedtls_aes_context *c){(void)c;} 
static void mbedtls_aes_free(mbedtls_aes_context *c){(void)c;} 
static int mbedtls_aes_setkey_enc(mbedtls_aes_context *c,const unsigned char *k,unsigned int kb){(void)c;(void)k;(void)kb;return 0;} 
static int mbedtls_aes_crypt_ecb(mbedtls_aes_context *c,int m,const unsigned char in[16],unsigned char out[16]){(void)c;(void)m;memcpy(out,in,16);return 0;} 
#define MBEDTLS_AES_ENCRYPT 1
#endif

/* Conditional minimal crypto support for ChaCha20-Poly1305 */
#if defined(CONFIG_MBEDTLS_CHACHA20_C) && defined(CONFIG_MBEDTLS_POLY1305_C)
#include "mbedtls/chacha20.h"
#include "mbedtls/poly1305.h"
#define HAS_CHACHA20_POLY1305 1
#else
#define HAS_CHACHA20_POLY1305 0
#endif

#define LOG_TAG "LORA_CLIENT"
#define LORA_MAX_PACKET_SIZE 255
#define LORA_DISCOVERY_INTERVAL_MS 5000  // Send discovery beacon every 5 seconds
#define LORA_RX_TIMEOUT_MS 100          // Receive timeout

/* LoRa Protocol Constants */
#define LORA_BROADCAST_ADDR 0x00000000
#define LORA_GATEWAY_ADDR   0xFFFFFFFF
#define LORA_MSG_TYPE_DISCOVERY 0x01
#define LORA_MSG_TYPE_CHALLENGE 0x02
#define LORA_MSG_TYPE_CHALLENGE_ANSWER 0x03
#define LORA_MSG_TYPE_DATA 0x04
#define LORA_MSG_TYPE_ACK 0x05

/* LoRa message header structure */
typedef struct {
    uint32_t src_addr;      // Source address
    uint32_t dst_addr;      // Destination address  
    uint8_t msg_type;       // Message type
    uint8_t seq_num;        // Sequence number
    uint16_t payload_len;   // Payload length
} __attribute__((packed)) lora_msg_header_t;

static const char *TAG = "LORA_CLIENT";

/* Hardware configuration for Heltec ESP32S3 LoRa V3.2 */
static EspHal* s_hal = nullptr;
static SX1262* s_radio = nullptr;

/* Task handles */
static TaskHandle_t s_lora_rx_task_handle = nullptr;
static TaskHandle_t s_lora_tx_task_handle = nullptr;
static SemaphoreHandle_t s_tx_mutex = nullptr;

/* Internal state */
static bool s_initialized = false;
static bool s_handshake_done = false;
static uint8_t s_seq_counter = 0;
static float s_last_rssi = 0.0f;
static float s_last_snr = 0.0f;

/* External crypto keys */
extern uint8_t public_key[64];
extern size_t public_key_len;
extern uint8_t private_key[64];  
extern size_t private_key_len;
extern uint8_t vendor_public_key[32];

/* Challenge management */
#define MAX_PENDING_CHALLENGES 10
typedef struct {
    bool active;
    uint32_t serial;
    uint32_t model;
    uint32_t nonce;
    uint32_t device_addr;
    uint32_t challenge_time; // timestamp for timeout handling
} lora_pending_challenge_t;

static lora_pending_challenge_t s_pending_challenges[MAX_PENDING_CHALLENGES] = {{0}};

/* Forward declarations */
static void lora_rx_task(void *pvParameters);
static void lora_tx_task(void *pvParameters);
static esp_err_t lora_send_raw_packet(const uint8_t *data, size_t data_len, uint32_t dst_addr, uint8_t msg_type);
static bool lora_process_received_packet(const uint8_t *packet, size_t packet_len, float rssi, float snr);
static bool lora_decode_lwm2m_message(const uint8_t *data, size_t data_len, lwm2m_LwM2MMessage *message);
static void lora_process_lwm2m_message(const lwm2m_LwM2MMessage *message, uint32_t src_addr, float rssi);

/* Challenge management functions */
static lora_pending_challenge_t* lora_find_pending_challenge(uint32_t serial);
static lora_pending_challenge_t* lora_add_pending_challenge(uint32_t serial, uint32_t model, uint32_t device_addr);
static void lora_remove_pending_challenge(uint32_t serial);
static bool lora_encode_and_send_challenge(uint32_t serial, uint32_t model, uint32_t device_addr);
static bool lora_process_challenge_answer(const uint8_t *data, size_t data_len, uint32_t sender_addr, float rssi);

/* Crypto helper functions */
static bool lora_chacha20_poly1305_decrypt_with_nonce(const uint8_t *in, size_t in_len,
                                                      uint8_t *out, size_t out_cap,
                                                      uint32_t nonce32, const uint8_t *peer_pub,
                                                      size_t peer_pub_len);
static uint32_t lora_generate_challenge_nonce32(void);

/* ========================== Hardware Initialization ========================== */

extern "C" esp_err_t lora_client_init_and_start(void) {
    if (s_initialized) {
        return ESP_OK;
    }
    
    ESP_LOGI(TAG, "Starting LoRa client initialization...");
    
    // Create HAL instance for Heltec ESP32S3 LoRa V3.2
    // Verified SPI pins: SCK=9, MISO=11, MOSI=10
    s_hal = new EspHal(9, 11, 10);
    if (s_hal == nullptr) {
        ESP_LOGE(TAG, "Failed to create HAL instance");
        return ESP_ERR_NO_MEM;
    }
    
    // Initialize the HAL
    ESP_LOGI(TAG, "Initializing HAL...");
    s_hal->init();
    s_hal->delay(100); // Let system stabilize
    
    // Create radio instance for SX1262
    // Verified pins: NSS=8, DIO1=14, NRST=12, BUSY=13  
    s_radio = new SX1262(new Module(s_hal, 8, 14, 12, 13));
    if (s_radio == nullptr) {
        ESP_LOGE(TAG, "Failed to create radio instance");
        delete s_hal;
        s_hal = nullptr;
        return ESP_ERR_NO_MEM;
    }
    
    ESP_LOGI(TAG, "[SX1262] Initializing radio...");
    ESP_LOGI(TAG, "SPI pins - SCK: 9, MISO: 11, MOSI: 10");
    ESP_LOGI(TAG, "LoRa pins - NSS: 8, DIO1: 14, RST: 12, BUSY: 13");
    
    int state = s_radio->begin();
    if (state != RADIOLIB_ERR_NONE) {
        ESP_LOGE(TAG, "SX1262 initialization failed, code %d", state);
        delete s_radio;
        delete s_hal;
        s_radio = nullptr;
        s_hal = nullptr;
        return ESP_FAIL;
    }
    
    // Set default LoRa parameters (similar to BLE scanning configuration)
    state = s_radio->setFrequency(915.0f);      // 915 MHz ISM band
    if (state == RADIOLIB_ERR_NONE) {
        state = s_radio->setBandwidth(125.0f);   // 125 kHz bandwidth
    }
    if (state == RADIOLIB_ERR_NONE) {
        state = s_radio->setSpreadingFactor(7);  // SF7 for good range/speed balance
    }
    if (state == RADIOLIB_ERR_NONE) {
        state = s_radio->setCodingRate(5);       // CR 4/5
    }
    if (state == RADIOLIB_ERR_NONE) {
        state = s_radio->setOutputPower(17);     // 17 dBm output power
    }
    if (state == RADIOLIB_ERR_NONE) {
        state = s_radio->setPreambleLength(8);   // 8 symbol preamble
    }
    if (state == RADIOLIB_ERR_NONE) {
        state = s_radio->setSyncWord(0x12);      // Sync word
    }
    
    if (state != RADIOLIB_ERR_NONE) {
        ESP_LOGE(TAG, "LoRa parameter configuration failed, code %d", state);
        delete s_radio;
        delete s_hal;
        s_radio = nullptr;  
        s_hal = nullptr;
        return ESP_FAIL;
    }
    
    ESP_LOGI(TAG, "LoRa parameters configured successfully");
    
    // Create mutex for TX operations
    s_tx_mutex = xSemaphoreCreateMutex();
    if (s_tx_mutex == nullptr) {
        ESP_LOGE(TAG, "Failed to create TX mutex");
        delete s_radio;
        delete s_hal;
        s_radio = nullptr;
        s_hal = nullptr;
        return ESP_ERR_NO_MEM;
    }
    
    // Create RX task (similar to BLE GAP event handler)
    BaseType_t xReturned = xTaskCreate(
        lora_rx_task,
        "lora_rx_task", 
        8192,           // Larger stack for protobuf processing
        NULL,
        6,              // Higher priority than TX task
        &s_lora_rx_task_handle
    );
    
    if (xReturned != pdPASS) {
        ESP_LOGE(TAG, "Failed to create LoRa RX task");
        vSemaphoreDelete(s_tx_mutex);
        delete s_radio;
        delete s_hal;
        s_radio = nullptr;
        s_hal = nullptr;
        return ESP_FAIL;
    }
    
    // Create TX task for periodic discovery broadcasts
    xReturned = xTaskCreate(
        lora_tx_task,
        "lora_tx_task",
        4096,
        NULL, 
        5,              // Lower priority than RX
        &s_lora_tx_task_handle
    );
    
    if (xReturned != pdPASS) {
        ESP_LOGE(TAG, "Failed to create LoRa TX task");
        vTaskDelete(s_lora_rx_task_handle);
        vSemaphoreDelete(s_tx_mutex);
        delete s_radio;
        delete s_hal;
        s_radio = nullptr;
        s_hal = nullptr;
        return ESP_FAIL;
    }
    
    s_initialized = true;
    ESP_LOGI(TAG, "LoRa client initialized and started successfully");
    return ESP_OK;
}

/* ========================== Task Implementations ========================== */

static void lora_rx_task(void *pvParameters) {
    ESP_LOGI(TAG, "LoRa RX task started");
    
    uint8_t rx_buffer[LORA_MAX_PACKET_SIZE];
    
    while (s_initialized) {
        // Start receive with timeout
        int state = s_radio->startReceive();
        if (state != RADIOLIB_ERR_NONE) {
            ESP_LOGW(TAG, "Failed to start receive, code %d", state);
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }
        
        // Wait for packet or timeout
        vTaskDelay(pdMS_TO_TICKS(LORA_RX_TIMEOUT_MS));
        
        // Check if packet available (RadioLib provides this method)
        size_t packet_len = s_radio->getPacketLength(false);
        
        if (packet_len > 0 && packet_len <= LORA_MAX_PACKET_SIZE) {
            // Read the packet
            state = s_radio->readData(rx_buffer, packet_len);
            
            if (state == RADIOLIB_ERR_NONE) {
                // Get signal quality
                float rssi = s_radio->getRSSI();
                float snr = s_radio->getSNR();
                
                ESP_LOGD(TAG, "Received packet: %d bytes, RSSI: %.1f dBm, SNR: %.1f dB", 
                        (int)packet_len, rssi, snr);
                
                // Update signal quality
                s_last_rssi = rssi;
                s_last_snr = snr;
                
                // Process the received packet
                lora_process_received_packet(rx_buffer, packet_len, rssi, snr);
            } else {
                ESP_LOGW(TAG, "Failed to read packet data, code %d", state);
            }
        }
    }
    
    ESP_LOGI(TAG, "LoRa RX task ended");
    vTaskDelete(NULL);
}

static void lora_tx_task(void *pvParameters) {
    ESP_LOGI(TAG, "LoRa TX task started");
    
    while (s_initialized) {
        // Send periodic discovery beacon (similar to BLE extended advertising)
        // This allows LoRa devices to discover the gateway
        
        // Wait for discovery interval
        vTaskDelay(pdMS_TO_TICKS(LORA_DISCOVERY_INTERVAL_MS));
        
        // Send discovery beacon  
        const char discovery_msg[] = "LwM2M_Gateway_Discovery";
        esp_err_t err = lora_send_raw_packet((const uint8_t*)discovery_msg, 
                                           strlen(discovery_msg), 
                                           LORA_BROADCAST_ADDR, 
                                           LORA_MSG_TYPE_DISCOVERY);
        
        if (err == ESP_OK) {
            ESP_LOGD(TAG, "Discovery beacon sent");
        } else {
            ESP_LOGW(TAG, "Failed to send discovery beacon");
        }
    }
    
    ESP_LOGI(TAG, "LoRa TX task ended");
    vTaskDelete(NULL);
}

/* ========================== Packet Processing ========================== */

static esp_err_t lora_send_raw_packet(const uint8_t *data, size_t data_len, uint32_t dst_addr, uint8_t msg_type) {
    if (!s_initialized || s_radio == nullptr) {
        return ESP_ERR_INVALID_STATE;
    }
    
    if (data == nullptr || data_len == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    
    // Take TX mutex to ensure atomic transmission
    if (xSemaphoreTake(s_tx_mutex, pdMS_TO_TICKS(1000)) != pdTRUE) {
        ESP_LOGE(TAG, "Failed to acquire TX mutex");
        return ESP_ERR_TIMEOUT;
    }
    
    esp_err_t ret = ESP_OK;
    
    // Prepare packet with header
    size_t total_len = sizeof(lora_msg_header_t) + data_len;
    if (total_len > LORA_MAX_PACKET_SIZE) {
        ESP_LOGE(TAG, "Packet too large: %d bytes", (int)total_len);
        ret = ESP_ERR_INVALID_SIZE;
        xSemaphoreGive(s_tx_mutex);
        return ret;
    }
    
    uint8_t packet[LORA_MAX_PACKET_SIZE];
    lora_msg_header_t *header = (lora_msg_header_t*)packet;
    
    header->src_addr = LORA_GATEWAY_ADDR;
    header->dst_addr = dst_addr;
    header->msg_type = msg_type;
    header->seq_num = s_seq_counter++;
    header->payload_len = (uint16_t)data_len;
    
    // Copy payload after header
    memcpy(packet + sizeof(lora_msg_header_t), data, data_len);
    
    // Send the packet
    int state = s_radio->transmit(packet, total_len);
    if (state != RADIOLIB_ERR_NONE) {
        ESP_LOGE(TAG, "LoRa transmission failed, code %d", state);
        ret = ESP_FAIL;
    } else {
        ESP_LOGD(TAG, "LoRa packet sent: %d bytes to addr 0x%08lX", (int)total_len, dst_addr);
    }
    xSemaphoreGive(s_tx_mutex);
    return ret;
}

static bool lora_process_received_packet(const uint8_t *packet, size_t packet_len, float rssi, float snr) {
    if (packet_len < sizeof(lora_msg_header_t)) {
        ESP_LOGW(TAG, "Packet too small: %d bytes", (int)packet_len);
        return false;
    }
    
    const lora_msg_header_t *header = (const lora_msg_header_t*)packet;
    const uint8_t *payload = packet + sizeof(lora_msg_header_t);
    size_t payload_len = packet_len - sizeof(lora_msg_header_t);
    
    // Validate header
    if (header->payload_len != payload_len) {
        ESP_LOGW(TAG, "Payload length mismatch: header=%d, actual=%d", 
                 header->payload_len, (int)payload_len);
        return false;
    }
    
    // Check if packet is for us (broadcast or gateway address)
    if (header->dst_addr != LORA_BROADCAST_ADDR && header->dst_addr != LORA_GATEWAY_ADDR) {
        ESP_LOGD(TAG, "Packet not for us: dst=0x%08lX", header->dst_addr);
        return false;
    }
    
    ESP_LOGD(TAG, "Processing packet from 0x%08lX, type=%d, seq=%d, len=%d", 
             header->src_addr, header->msg_type, header->seq_num, (int)payload_len);
    
    switch (header->msg_type) {
        case LORA_MSG_TYPE_DISCOVERY: {
            // Device discovery message - try to decode as LwM2M message
            lwm2m_LwM2MMessage message = lwm2m_LwM2MMessage_init_zero;
            if (lora_decode_lwm2m_message(payload, payload_len, &message)) {
                lora_process_lwm2m_message(&message, header->src_addr, rssi);
                return true;
            }
            ESP_LOGD(TAG, "Received discovery message from 0x%08lX", header->src_addr);
            break;
        }
        
        case LORA_MSG_TYPE_CHALLENGE_ANSWER: {
            // Challenge answer from device
            if (lora_process_challenge_answer(payload, payload_len, header->src_addr, rssi)) {
                ESP_LOGI(TAG, "Challenge answer processed successfully from 0x%08lX", header->src_addr);
                return true;
            }
            ESP_LOGW(TAG, "Failed to process challenge answer from 0x%08lX", header->src_addr);
            break;
        }
        
        case LORA_MSG_TYPE_DATA: {
            // Regular data message - try to decode as LwM2M message
            lwm2m_LwM2MMessage message = lwm2m_LwM2MMessage_init_zero;
            if (lora_decode_lwm2m_message(payload, payload_len, &message)) {
                lora_process_lwm2m_message(&message, header->src_addr, rssi);
                return true;
            }
            ESP_LOGD(TAG, "Received data message from 0x%08lX", header->src_addr);
            break;
        }
        
        default:
            ESP_LOGD(TAG, "Unknown message type %d from 0x%08lX", header->msg_type, header->src_addr);
            break;
    }
    
    return false;
}

static bool lora_decode_lwm2m_message(const uint8_t *data, size_t data_len, lwm2m_LwM2MMessage *message) {
    if (!data || data_len == 0 || !message) {
        return false;
    }
    
    pb_istream_t stream = pb_istream_from_buffer(data, data_len);
    bool status = pb_decode(&stream, lwm2m_LwM2MMessage_fields, message);
    
    if (!status) {
        ESP_LOGD(TAG, "Failed to decode protobuf message: %s", PB_GET_ERROR(&stream));
        return false;
    }
    
    return true;
}

static void lora_process_lwm2m_message(const lwm2m_LwM2MMessage *message, uint32_t src_addr, float rssi) {
    ESP_LOGI(TAG, "LwM2M Message decoded - model: %ld, serial: %ld, RSSI: %.1f dBm from addr 0x%08lX", 
             message->model, message->serial, rssi, src_addr);
    
    // Check if device exists in the device list by serial number
    lwm2m_LwM2MDevice *existing_device = device_ring_buffer_find_by_serial(message->serial);
    
    if (existing_device != NULL) {
        ESP_LOGI(TAG, "Device with serial %ld already exists in device list", message->serial);
        
        // Update connectivity monitoring RSSI for existing device
        lwm2m_update_device_rssi(existing_device->instance_id, (int8_t)rssi);
        
        // Device exists, optionally update last seen time or other fields
    } else {
        ESP_LOGI(TAG, "Device with serial %ld not found in device list, initiating challenge", message->serial);
        
        // Check if we already have a pending challenge for this device
        lora_pending_challenge_t* pending = lora_find_pending_challenge(message->serial);
        if (pending) {
            ESP_LOGI(TAG, "Challenge already pending for device serial %ld", message->serial);
            return;
        }
        
        ESP_LOGI(TAG, "Device LoRa address: 0x%08lX", src_addr);
        
        // Send challenge to device
        if (lora_encode_and_send_challenge(message->serial, message->model, src_addr)) {
            ESP_LOGI(TAG, "Challenge sent to device with serial %ld", message->serial);
        } else {
            ESP_LOGE(TAG, "Failed to send challenge to device with serial %ld", message->serial);
        }
    }
}

/* ========================== Challenge Management ========================== */

static lora_pending_challenge_t* lora_find_pending_challenge(uint32_t serial) {
    for (int i = 0; i < MAX_PENDING_CHALLENGES; i++) {
        if (s_pending_challenges[i].active && s_pending_challenges[i].serial == serial) {
            return &s_pending_challenges[i];
        }
    }
    return NULL;
}

static uint32_t lora_generate_challenge_nonce32(void) {
    uint32_t nonce32 = 0;
    do {
        nonce32 = esp_random();
    } while (nonce32 == 0);
    return nonce32;
}

static lora_pending_challenge_t* lora_add_pending_challenge(uint32_t serial, uint32_t model, uint32_t device_addr) {
    // Check if already exists
    lora_pending_challenge_t* existing = lora_find_pending_challenge(serial);
    if (existing) {
        return existing;
    }
    
    // Find empty slot
    for (int i = 0; i < MAX_PENDING_CHALLENGES; i++) {
        if (!s_pending_challenges[i].active) {
            s_pending_challenges[i].active = true;
            s_pending_challenges[i].serial = serial;
            s_pending_challenges[i].model = model;
            s_pending_challenges[i].nonce = lora_generate_challenge_nonce32();
            s_pending_challenges[i].device_addr = device_addr;
            s_pending_challenges[i].challenge_time = xTaskGetTickCount();
            return &s_pending_challenges[i];
        }
    }
    
    // If no empty slot, replace oldest
    uint32_t oldest_time = UINT32_MAX;
    int oldest_idx = 0;
    for (int i = 0; i < MAX_PENDING_CHALLENGES; i++) {
        if (s_pending_challenges[i].challenge_time < oldest_time) {
            oldest_time = s_pending_challenges[i].challenge_time;
            oldest_idx = i;
        }
    }
    
    ESP_LOGW(TAG, "Challenge table full, replacing oldest entry for serial %ld", s_pending_challenges[oldest_idx].serial);
    s_pending_challenges[oldest_idx].active = true;
    s_pending_challenges[oldest_idx].serial = serial;
    s_pending_challenges[oldest_idx].model = model;
    s_pending_challenges[oldest_idx].nonce = lora_generate_challenge_nonce32();
    s_pending_challenges[oldest_idx].device_addr = device_addr;
    s_pending_challenges[oldest_idx].challenge_time = xTaskGetTickCount();
    return &s_pending_challenges[oldest_idx];
}

static void lora_remove_pending_challenge(uint32_t serial) {
    for (int i = 0; i < MAX_PENDING_CHALLENGES; i++) {
        if (s_pending_challenges[i].active && s_pending_challenges[i].serial == serial) {
            s_pending_challenges[i].active = false;
            ESP_LOGI(TAG, "Removed pending challenge for serial %ld", serial);
            break;
        }
    }
}

static bool lora_encode_and_send_challenge(uint32_t serial, uint32_t model, uint32_t device_addr) {
    // Add to pending challenges first to get the correct nonce
    lora_pending_challenge_t* challenge_entry = lora_add_pending_challenge(serial, model, device_addr);
    if (!challenge_entry) {
        ESP_LOGE(TAG, "Failed to add pending challenge for device serial %ld", serial);
        return false;
    }
    
    // Create challenge message
    lwm2m_LwM2MDeviceChallenge challenge = lwm2m_LwM2MDeviceChallenge_init_zero;
    challenge.nounce = challenge_entry->nonce;
    
    size_t pk_copy_len = public_key_len > sizeof(challenge.public_key.bytes) ? 
                        sizeof(challenge.public_key.bytes) : public_key_len;
    memcpy(challenge.public_key.bytes, public_key, pk_copy_len);
    challenge.public_key.size = pk_copy_len;
    
    // Encode the challenge message
    uint8_t buffer[256];
    pb_ostream_t stream = pb_ostream_from_buffer(buffer, sizeof(buffer));
    
    bool status = pb_encode(&stream, lwm2m_LwM2MDeviceChallenge_fields, &challenge);
    if (!status) {
        ESP_LOGE(TAG, "Failed to encode challenge message: %s", PB_GET_ERROR(&stream));
        return false;
    }
    
    size_t message_length = stream.bytes_written;
    ESP_LOGI(TAG, "Encoded challenge message, %d bytes for device serial %ld", 
             (int)message_length, serial);
    
    // Send challenge via LoRa
    ESP_LOGI(TAG, "Sending protobuf challenge via LoRa to device 0x%08lX (serial %ld)", 
             device_addr, serial);
    
    esp_err_t err = lora_send_raw_packet(buffer, message_length, device_addr, LORA_MSG_TYPE_CHALLENGE);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to send challenge via LoRa to device 0x%08lX (serial %ld): %s", 
                 device_addr, serial, esp_err_to_name(err));
        return false;
    }
    
    ESP_LOGI(TAG, "Successfully sent challenge message via LoRa");
    return true;
}

static bool lora_process_challenge_answer(const uint8_t *data, size_t data_len, uint32_t sender_addr, float rssi) {
    lwm2m_LwM2MDeviceChallengeAnswer answer = lwm2m_LwM2MDeviceChallengeAnswer_init_zero;
    
    pb_istream_t stream = pb_istream_from_buffer(data, data_len);
    bool status = pb_decode(&stream, lwm2m_LwM2MDeviceChallengeAnswer_fields, &answer);
    
    if (!status) {
        ESP_LOGE(TAG, "Failed to decode challenge answer: %s", PB_GET_ERROR(&stream));
        return false;
    }
    
    ESP_LOGI(TAG, "Decoded challenge answer message from LoRa addr 0x%08lX", sender_addr);
    
    // Find the matching challenge by device address
    lora_pending_challenge_t* pending = NULL;
    uint32_t sender_serial = 0;
    
    for (int i = 0; i < MAX_PENDING_CHALLENGES; i++) {
        if (s_pending_challenges[i].active && s_pending_challenges[i].device_addr == sender_addr) {
            pending = &s_pending_challenges[i];
            sender_serial = pending->serial;
            ESP_LOGI(TAG, "Found pending challenge for LoRa addr 0x%08lX (serial %ld)", 
                     sender_addr, sender_serial);
            break;
        }
    }
    
    if (!pending) {
        ESP_LOGW(TAG, "Received challenge answer but no pending challenge found for addr 0x%08lX", sender_addr);
        return false;
    }
    
    ESP_LOGI(TAG, "Processing challenge answer from device serial %ld", sender_serial);
    
    // Decrypt and verify the challenge answer signature using the correct nonce
    uint8_t decrypted_signature[64];
    bool verification_success = false;
    
    if (answer.signature.size > 0 && pending) {
        if (answer.public_key.size < 32) {
            ESP_LOGE(TAG, "Challenge answer missing peer public key (size=%u)", 
                     (unsigned)answer.public_key.size);
            return false;
        }
        if (answer.signature.size <= 16) {
            ESP_LOGE(TAG, "Challenge answer signature too short (%u)", 
                     (unsigned)answer.signature.size);
            return false;
        }
        if (answer.signature.size - 16 > sizeof(decrypted_signature)) {
            ESP_LOGE(TAG, "Decrypted signature would overflow buffer (%u)", 
                     (unsigned)(answer.signature.size - 16));
            return false;
        }
        
        ESP_LOGI(TAG, "Decrypting signature (%u bytes) using nonce %lu", 
                 (unsigned)answer.signature.size, pending->nonce);
        
        bool decrypt_success = lora_chacha20_poly1305_decrypt_with_nonce(answer.signature.bytes,
                                                                        answer.signature.size,
                                                                        decrypted_signature,
                                                                        sizeof(decrypted_signature),
                                                                        pending->nonce,
                                                                        answer.public_key.bytes,
                                                                        answer.public_key.size);
        
        if (decrypt_success) {
            size_t decrypted_len = answer.signature.size - 16; // Remove tag length
            ESP_LOGI(TAG, "Successfully decrypted signature (%u bytes)", (unsigned)decrypted_len);
            ESP_LOG_BUFFER_HEX_LEVEL(TAG, decrypted_signature, decrypted_len, ESP_LOG_INFO);

            if (answer.public_key.size != 32) {
                ESP_LOGE(TAG, "Unexpected public key length %u in challenge answer",
                         (unsigned)answer.public_key.size);
                memset(decrypted_signature, 0, decrypted_len);
                return false;
            }

            if (decrypted_len != 64) {
                ESP_LOGE(TAG, "Unexpected factory signature length: %u", (unsigned)decrypted_len);
                memset(decrypted_signature, 0, decrypted_len);
                return false;
            }

            /* Construct message as: serial_string + device_public_key */
            char serial_str[32];
            snprintf(serial_str, sizeof(serial_str), "%ld", sender_serial);
            size_t serial_len = strlen(serial_str);
            
            /* Allocate buffer for full message */
            size_t full_msg_len = serial_len + answer.public_key.size;
            uint8_t *full_message = (uint8_t*)malloc(full_msg_len);
            int verify_ret = -1;
            
            if (full_message) {
                memcpy(full_message, serial_str, serial_len);
                memcpy(full_message + serial_len, answer.public_key.bytes, answer.public_key.size);
                
                ESP_LOGI(TAG, "Verifying signature with message: '%s' + device_key (%u bytes total)", 
                         serial_str, (unsigned)full_msg_len);
                
                verify_ret = lwm2m_ed25519_verify_signature(vendor_public_key,
                                                            sizeof(vendor_public_key),
                                                            full_message,
                                                            full_msg_len,
                                                            decrypted_signature,
                                                            decrypted_len);
                free(full_message);
                
                if (verify_ret != 0) {
                    ESP_LOGW(TAG, "Serial+key verification failed, trying device key only...");
                    
                    verify_ret = lwm2m_ed25519_verify_signature(vendor_public_key,
                                                                sizeof(vendor_public_key),
                                                                answer.public_key.bytes,
                                                                answer.public_key.size,
                                                                decrypted_signature,
                                                                decrypted_len);
                }
            } else {
                ESP_LOGE(TAG, "Failed to allocate memory for full message, trying device key only...");
                
                verify_ret = lwm2m_ed25519_verify_signature(vendor_public_key,
                                                            sizeof(vendor_public_key),
                                                            answer.public_key.bytes,
                                                            answer.public_key.size,
                                                            decrypted_signature,
                                                            decrypted_len);
            }
            
            memset(decrypted_signature, 0, decrypted_len);

            if (verify_ret != 0) {
                ESP_LOGE(TAG, "Factory signature verification failed for serial %ld (err=%d)",
                         sender_serial, verify_ret);
                return false;
            }

            ESP_LOGI(TAG, "Factory signature verified for serial %ld", sender_serial);
            verification_success = true;
        } else {
            ESP_LOGE(TAG, "Failed to decrypt signature for device serial %ld", sender_serial);
            return false;
        }
    } else {
        ESP_LOGW(TAG, "No signature to verify or no pending challenge found");
        return false;
    }
    
    if (verification_success) {
        ESP_LOGI(TAG, "Challenge answer verified successfully for serial %ld", sender_serial);
    } else {
        ESP_LOGE(TAG, "Challenge answer verification failed for serial %ld", sender_serial);
        return false;
    }
    
    // Create a new device structure and add it to the device list
    lwm2m_LwM2MDevice new_device;
    memset(&new_device, 0, sizeof(new_device));
    new_device.model = pending->model;
    new_device.serial = pending->serial;
    new_device.instance_id = 0;  // Will be assigned during bootstrap
    new_device.banned = false;
    
    ESP_LOGI(TAG, "Device LoRa address: 0x%08lX", sender_addr);
    
    // Copy the public key from the challenge answer
    if (answer.public_key.size > 0 && answer.public_key.size <= sizeof(new_device.public_key.bytes)) {
        memcpy(new_device.public_key.bytes, answer.public_key.bytes, answer.public_key.size);
        new_device.public_key.size = answer.public_key.size;
    }
    
    // Add the device to the ring buffer
    esp_err_t err = device_ring_buffer_add(&new_device);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "Successfully added challenged device with serial %ld to device list", sender_serial);
        lora_remove_pending_challenge(sender_serial);
        
        // If LwM2M client is initialized, add the gateway instance and notify server
        if (objArray[5] != NULL) {
            uint32_t device_count = device_ring_buffer_get_count();
            gateway_add_instance(objArray[5], device_count - 1, new_device.serial, CONNECTION_LORA);
            
            // Add connectivity monitoring instance for the new device
            if (objArray[6] != NULL) {
                connectivity_moni_add_instance(objArray[6], device_count - 1, new_device.serial);
                ESP_LOGI(TAG, "Added connectivity monitoring instance for new device serial %ld", new_device.serial);
            }
            
            // Trigger registration update to notify LwM2M server about the new device
            lwm2m_trigger_registration_update();
            ESP_LOGI(TAG, "Added device instance to LwM2M gateway object and triggered registration update");
        } else {
            ESP_LOGI(TAG, "Device added to ring buffer. LwM2M gateway object will pick it up during initialization");
        }
        return true;
    } else {
        ESP_LOGE(TAG, "Failed to add challenged device with serial %ld to device list: %s", 
                 sender_serial, esp_err_to_name(err));
        return false;
    }
}

/* ========================== Crypto Helper Functions ========================== */

static bool lora_chacha20_poly1305_decrypt_with_nonce(const uint8_t *in, size_t in_len,
                                                      uint8_t *out, size_t out_cap,
                                                      uint32_t nonce32, const uint8_t *peer_pub,
                                                      size_t peer_pub_len) {
    if (!in || in_len < 16 || !out || out_cap == 0) {
        ESP_LOGE(TAG, "Invalid decrypt parameters");
        return false;
    }

#if HAS_CHACHA20_POLY1305
    if (!peer_pub || peer_pub_len < 32) {
        ESP_LOGE(TAG, "Peer public key missing or too short (%u bytes)", (unsigned)peer_pub_len);
        return false;
    }
    if (private_key_len < 32) {
        ESP_LOGE(TAG, "Factory private key not loaded (len=%u)", (unsigned)private_key_len);
        return false;
    }

    size_t ciphertext_len = in_len - 16; /* Separate 16-byte tag */
    if (out_cap < ciphertext_len) {
        ESP_LOGE(TAG, "Output buffer too small: need %u, have %u",
                 (unsigned)ciphertext_len, (unsigned)out_cap);
        return false;
    }

    uint8_t shared_key[32] = {0};
    int crypto_ret = lwm2m_crypto_curve25519_shared_key(peer_pub, private_key, shared_key);
    if (crypto_ret != 0) {
        ESP_LOGE(TAG, "Shared key derivation failed: %d", crypto_ret);
        memset(shared_key, 0, sizeof(shared_key));
        return false;
    }

    uint8_t nonce12[12] = {0};
    char nonce_str[13];
    snprintf(nonce_str, sizeof(nonce_str), "%012" PRIu32, nonce32);
    memcpy(nonce12, nonce_str, sizeof(nonce12));

    const uint8_t *ciphertext = in;
    const uint8_t *tag = in + ciphertext_len;
    crypto_ret = lwm2m_chacha20_poly1305_decrypt(shared_key, nonce12,
                                                 ciphertext, ciphertext_len,
                                                 NULL, 0, tag, out);

    memset(shared_key, 0, sizeof(shared_key));
    memset(nonce12, 0, sizeof(nonce12));

    if (crypto_ret != 0) {
        ESP_LOGE(TAG, "ChaCha20-Poly1305 decrypt failed: %d", crypto_ret);
        return false;
    }

    ESP_LOGI(TAG, "ChaCha20-Poly1305 decryption successful: %u->%u bytes",
             (unsigned)in_len, (unsigned)ciphertext_len);
    return true;

#else
    ESP_LOGW(TAG, "ChaCha20-Poly1305 not available, decryption not supported");
    return false;
#endif
}

/* ========================== Public API Implementation ========================== */

extern "C" esp_err_t lora_client_stop_scan(void) {
    s_initialized = false;
    
    // Stop tasks
    if (s_lora_rx_task_handle != nullptr) {
        vTaskDelete(s_lora_rx_task_handle);
        s_lora_rx_task_handle = nullptr;
    }
    
    if (s_lora_tx_task_handle != nullptr) {
        vTaskDelete(s_lora_tx_task_handle);
        s_lora_tx_task_handle = nullptr;
    }
    
    return ESP_OK;
}

extern "C" bool lora_client_handshake_done(void) {
    return s_handshake_done;
}

extern "C" uint32_t lora_client_get_pending_challenges_count(void) {
    uint32_t count = 0;
    for (int i = 0; i < MAX_PENDING_CHALLENGES; i++) {
        if (s_pending_challenges[i].active) {
            count++;
        }
    }
    return count;
}

extern "C" void lora_client_cleanup_stale_challenges(void) {
    uint32_t current_time = xTaskGetTickCount();
    const uint32_t CHALLENGE_TIMEOUT_MS = 30000; // 30 seconds timeout
    const uint32_t timeout_ticks = pdMS_TO_TICKS(CHALLENGE_TIMEOUT_MS);
    
    for (int i = 0; i < MAX_PENDING_CHALLENGES; i++) {
        if (s_pending_challenges[i].active) {
            uint32_t age = current_time - s_pending_challenges[i].challenge_time;
            if (age > timeout_ticks) {
                ESP_LOGW(TAG, "Removing stale challenge for serial %ld (age: %ld ms)", 
                         s_pending_challenges[i].serial, pdTICKS_TO_MS(age));
                s_pending_challenges[i].active = false;
            }
        }
    }
}

extern "C" bool lora_client_find_challenge_by_address(uint32_t addr, uint32_t *serial_out, uint32_t *model_out) {
    for (int i = 0; i < MAX_PENDING_CHALLENGES; i++) {
        if (s_pending_challenges[i].active && s_pending_challenges[i].device_addr == addr) {
            if (serial_out) *serial_out = s_pending_challenges[i].serial;
            if (model_out) *model_out = s_pending_challenges[i].model;
            return true;
        }
    }
    return false;
}

extern "C" esp_err_t lora_send_message(const char* message) {
    if (message == nullptr) {
        return ESP_ERR_INVALID_ARG;
    }
    
    return lora_send_raw_packet((const uint8_t*)message, strlen(message), 
                               LORA_BROADCAST_ADDR, LORA_MSG_TYPE_DATA);
}

extern "C" esp_err_t lora_send_protobuf_data(const uint8_t *data, size_t data_len, uint32_t target_addr) {
    if (!data || data_len == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    
    return lora_send_raw_packet(data, data_len, target_addr, LORA_MSG_TYPE_DATA);
}

extern "C" esp_err_t lora_set_parameters(float frequency, float bandwidth, uint8_t spreading_factor, uint8_t coding_rate) {
    if (!s_initialized || s_radio == nullptr) {
        return ESP_ERR_INVALID_STATE;
    }
    
    int state = s_radio->setFrequency(frequency);
    if (state == RADIOLIB_ERR_NONE) {
        state = s_radio->setBandwidth(bandwidth);
    }
    if (state == RADIOLIB_ERR_NONE) {
        state = s_radio->setSpreadingFactor(spreading_factor);
    }
    if (state == RADIOLIB_ERR_NONE) {
        state = s_radio->setCodingRate(coding_rate);
    }
    
    if (state != RADIOLIB_ERR_NONE) {
        ESP_LOGE(TAG, "Failed to set LoRa parameters, code %d", state);
        return ESP_FAIL;
    }
    
    ESP_LOGI(TAG, "LoRa parameters updated: freq=%.1f MHz, bw=%.1f kHz, sf=%d, cr=4/%d", 
             frequency, bandwidth, spreading_factor, coding_rate);
    return ESP_OK;
}

extern "C" esp_err_t lora_get_signal_quality(float *rssi, float *snr) {
    if (!rssi || !snr) {
        return ESP_ERR_INVALID_ARG;
    }
    
    *rssi = s_last_rssi;
    *snr = s_last_snr;
    return ESP_OK;
}

/* Legacy function stubs for backward compatibility */
extern "C" esp_err_t lora_init(void) {
    return lora_client_init_and_start();
}

extern "C" esp_err_t lora_start_task(void) {
    // Task is already started in lora_client_init_and_start()
    return s_initialized ? ESP_OK : ESP_ERR_INVALID_STATE;
}

extern "C" void lora_stop_task(void) {
    lora_client_stop_scan();
    
    // Cleanup resources
    if (s_radio != nullptr) {
        delete s_radio;
        s_radio = nullptr;
    }
    
    if (s_hal != nullptr) {
        s_hal->term();
        delete s_hal;
        s_hal = nullptr;
    }
    
    if (s_tx_mutex != nullptr) {
        vSemaphoreDelete(s_tx_mutex);
        s_tx_mutex = nullptr;
    }
    
    ESP_LOGI(TAG, "LoRa module cleaned up");
}