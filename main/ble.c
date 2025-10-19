/*
 * Extracted BLE logic from original main2.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "esp_err.h"
#include "nvs_flash.h"
#include "esp_bt.h"

#include "esp_gap_ble_api.h"
#include "esp_gatts_api.h"
#include "esp_bt_defs.h"
#include "esp_bt_main.h"
#include "esp_gatt_common_api.h"
#include "esp_gattc_api.h"

#include "pb_decode.h"
#include "pb_encode.h"
#include "lwm2m.pb.h"
#include "lwm2m_helpers.h"

#include "esp_random.h"

#include "ble.h"
#include "device.h"


/* Conditional minimal crypto support: provide stubs if mbedTLS components not enabled. */
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
#ifdef CONFIG_MBEDTLS_SHA512_C
#include "mbedtls/sha512.h"
#endif
#ifdef CONFIG_MBEDTLS_ECDH_C
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#endif
/* Conditional minimal crypto support for ChaCha20-Poly1305 */
#if defined(CONFIG_MBEDTLS_CHACHA20_C) && defined(CONFIG_MBEDTLS_POLY1305_C)
#include "mbedtls/chacha20.h"
#include "mbedtls/poly1305.h"
#define HAS_CHACHA20_POLY1305 1
#else
#define HAS_CHACHA20_POLY1305 0
#endif

#define LOG_TAG "BLE_CLIENT"
#define EXT_SCAN_DURATION 0
#define EXT_SCAN_PERIOD   0
#define STOP_SCAN_AFTER_HANDSHAKE 0

#define FUNC_SEND_WAIT_SEM(func, sem) do {\
        esp_err_t __err_rc = (func);\
        if (__err_rc != ESP_OK) { \
            ESP_LOGE(LOG_TAG, "%s, message send fail, error = %d", __func__, __err_rc); \
        } \
        xSemaphoreTake(sem, portMAX_DELAY); \
} while(0)

/* ---------------- Internal State ---------------- */
static char s_remote_device_name[ESP_BLE_ADV_NAME_LEN_MAX] = "ESP_EXTENDED_ADV";
static SemaphoreHandle_t s_scan_sem = NULL;
static bool s_initialized = false;
static bool s_handshake_done = false;
static bool s_have_target = false;
static bool s_handshake_started = false;

extern uint8_t public_key[64];
extern size_t public_key_len;

extern uint8_t private_key[64];
extern size_t private_key_len;

extern uint8_t vendor_public_key[32];

/* ChaCha20-Poly1305 decryption (forward declarations) */
static bool chacha20_poly1305_decrypt_with_nonce(const uint8_t *in, size_t in_len,
                                                 uint8_t *out, size_t out_cap,
                                                 uint32_t nonce32, const uint8_t *peer_pub,
                                                 size_t peer_pub_len);
/* Challenge state tracking */
#define MAX_PENDING_CHALLENGES 10
typedef struct {
    bool active;
    uint32_t serial;
    uint32_t model;
    uint32_t nonce;
    esp_bd_addr_t addr;
    uint8_t addr_type;
    uint32_t challenge_time; // timestamp for timeout handling
} pending_challenge_t;

static pending_challenge_t s_pending_challenges[MAX_PENDING_CHALLENGES] = {0};
static uint16_t s_current_sync_handle = 0xFFFF; // Track current sync handle for reports
/* Periodic advertising sync tracking */
#include "sdkconfig.h"
#ifdef CONFIG_BT_LE_MAX_PERIODIC_SYNCS
#define MAX_PERIODIC_SYNCS CONFIG_BT_LE_MAX_PERIODIC_SYNCS
#else
#define MAX_PERIODIC_SYNCS 4
#endif
typedef struct {
    bool used;
    uint8_t sid;
    esp_bd_addr_t addr;
    uint8_t addr_type;
    uint16_t sync_handle; /* filled on ESTAB */
} periodic_sync_entry_t;
static periodic_sync_entry_t s_periodic_syncs[MAX_PERIODIC_SYNCS] = {0};

static periodic_sync_entry_t *find_sync_entry(uint8_t sid, const esp_bd_addr_t addr) {
    for (size_t i = 0; i < MAX_PERIODIC_SYNCS; ++i) {
        if (s_periodic_syncs[i].used && s_periodic_syncs[i].sid == sid && memcmp(s_periodic_syncs[i].addr, addr, sizeof(esp_bd_addr_t)) == 0) {
            return &s_periodic_syncs[i];
        }
    }
    return NULL;
}

static periodic_sync_entry_t *alloc_sync_entry(uint8_t sid, const esp_bd_addr_t addr, uint8_t addr_type) {
    periodic_sync_entry_t *e = find_sync_entry(sid, addr);
    if (e) return e; /* already present */
    for (size_t i = 0; i < MAX_PERIODIC_SYNCS; ++i) {
        if (!s_periodic_syncs[i].used) {
            s_periodic_syncs[i].used = true;
            s_periodic_syncs[i].sid = sid;
            memcpy(s_periodic_syncs[i].addr, addr, sizeof(esp_bd_addr_t));
            s_periodic_syncs[i].addr_type = addr_type;
            s_periodic_syncs[i].sync_handle = 0xFFFF;
            return &s_periodic_syncs[i];
        }
    }
    return NULL; /* full */
}

static void free_sync_entry_by_handle(uint16_t sync_handle) {
    for (size_t i = 0; i < MAX_PERIODIC_SYNCS; ++i) {
        if (s_periodic_syncs[i].used && s_periodic_syncs[i].sync_handle == sync_handle) {
            memset(&s_periodic_syncs[i], 0, sizeof(s_periodic_syncs[i]));
            return;
        }
    }
}

/* Handshake / GATT client state */
#define GATTC_APP_ID 0x66
static esp_gatt_if_t s_gattc_if = ESP_GATT_IF_NONE;
static uint16_t s_conn_id = 0xFFFF;
static esp_bd_addr_t s_target_addr = {0};
static uint8_t s_target_addr_type = BLE_ADDR_TYPE_PUBLIC;
static uint16_t s_svc_start = 0, s_svc_end = 0;
static uint16_t s_char_handle = 0;
static char s_challenge[16] = {0};
/* Pending write buffer for deferred GATT sends */
static uint8_t s_pending_write_buf[256];
static size_t s_pending_write_len = 0;
static bool s_pending_write_ready = false;
/* Simple read retry after write */
#define READ_RETRY_MAX 1
static int s_read_retries_left = 0;

/* Service/Char UUIDs expected on peer */
static const uint16_t RW_SERVICE_UUID16 = 0x00FF;
static const uint16_t RW_CHAR_UUID16    = 0xFF01;

static esp_ble_ext_scan_params_t s_ext_scan_params = {
    .own_addr_type = BLE_ADDR_TYPE_PUBLIC,
    .filter_policy = BLE_SCAN_FILTER_ALLOW_ALL,
    .scan_duplicate = BLE_SCAN_DUPLICATE_ENABLE,
    .cfg_mask = ESP_BLE_GAP_EXT_SCAN_CFG_UNCODE_MASK | ESP_BLE_GAP_EXT_SCAN_CFG_CODE_MASK,
    .uncoded_cfg = {BLE_SCAN_TYPE_ACTIVE, 40, 40},
    .coded_cfg   = {BLE_SCAN_TYPE_ACTIVE, 40, 40},
};

static esp_ble_gap_periodic_adv_sync_params_t s_periodic_adv_sync_params = {
    .filter_policy = 0,
    .sid = 0,
    .addr_type = BLE_ADDR_TYPE_RANDOM,
    .skip = 10,
    .sync_timeout = 1000,
};

/* ------------- Challenge Management ------------- */
/* 
 * Challenge/Response mechanism for new device registration with BLE address tracking:
 * 1. When a new device appears in LwM2M message, initiate challenge instead of direct add
 * 2. Extract BLE MAC address from periodic advertising sync context
 * 3. Send LwM2MDeviceChallenge protobuf message to the device (includes real BLE address)
 * 4. Wait for LwM2MDeviceChallengeAnswer response from the device  
 * 5. Correlate challenge answer by BLE address (more reliable than serial matching)
 * 6. Verify the challenge answer and add device to the list if valid
 * 7. Remove pending challenge entry after successful verification
 * 
 * BLE Address Handling:
 * - Addresses are extracted from periodic advertising sync entries by sync_handle
 * - Pending challenges store the originating BLE address for correlation
 * - Challenge answers are matched first by BLE address, then by serial as fallback
 */
/* Forward declaration needed before first use */
static esp_err_t send_protobuf_data_via_gatt(const uint8_t *data, size_t data_len);
static void maybe_start_handshake_from_appearance(void);

static pending_challenge_t* find_pending_challenge(uint32_t serial)
{
    for (int i = 0; i < MAX_PENDING_CHALLENGES; i++) {
        if (s_pending_challenges[i].active && s_pending_challenges[i].serial == serial) {
            return &s_pending_challenges[i];
        }
    }
    return NULL;
}

static uint32_t generate_challenge_nonce32(void)
{
    uint32_t nonce32 = 0;

    do {
        nonce32 = esp_random();
    } while (nonce32 == 0);


    return nonce32;
}

static pending_challenge_t* add_pending_challenge(uint32_t serial, uint32_t model, const esp_bd_addr_t addr, uint8_t addr_type)
{
    // First check if already exists
    pending_challenge_t* existing = find_pending_challenge(serial);
    if (existing) {
        return existing; // Return existing one
    }
    
    // Find empty slot
    for (int i = 0; i < MAX_PENDING_CHALLENGES; i++) {
        if (!s_pending_challenges[i].active) {
            s_pending_challenges[i].active = true;
            s_pending_challenges[i].serial = serial;
            s_pending_challenges[i].model = model;
            // Generate a random 32-bit nonce (avoid zero to reduce trivial collisions)
            s_pending_challenges[i].nonce = generate_challenge_nonce32();
            memcpy(s_pending_challenges[i].addr, addr, sizeof(esp_bd_addr_t));
            s_pending_challenges[i].addr_type = addr_type;
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
    
    ESP_LOGW(LOG_TAG, "Challenge table full, replacing oldest entry for serial %ld", s_pending_challenges[oldest_idx].serial);
    s_pending_challenges[oldest_idx].active = true;
    s_pending_challenges[oldest_idx].serial = serial;
    s_pending_challenges[oldest_idx].model = model;
    // Generate a random 32-bit nonce (avoid zero to reduce trivial collisions)
    s_pending_challenges[oldest_idx].nonce = generate_challenge_nonce32();
    memcpy(s_pending_challenges[oldest_idx].addr, addr, sizeof(esp_bd_addr_t));
    s_pending_challenges[oldest_idx].addr_type = addr_type;
    s_pending_challenges[oldest_idx].challenge_time = xTaskGetTickCount();
    return &s_pending_challenges[oldest_idx];
}

static void remove_pending_challenge(uint32_t serial)
{
    for (int i = 0; i < MAX_PENDING_CHALLENGES; i++) {
        if (s_pending_challenges[i].active && s_pending_challenges[i].serial == serial) {
            s_pending_challenges[i].active = false;
            ESP_LOGI(LOG_TAG, "Removed pending challenge for serial %ld", serial);
            break;
        }
    }
}

static bool encode_and_send_challenge(uint32_t serial, uint32_t model, const esp_bd_addr_t addr, uint8_t addr_type)
{
    // Add to pending challenges first to get the correct nonce
    pending_challenge_t* challenge_entry = add_pending_challenge(serial, model, addr, addr_type);
    if (!challenge_entry) {
        ESP_LOGE(LOG_TAG, "Failed to add pending challenge for device serial %ld", serial);
        return false;
    }
    
    // Use the nonce from the pending challenge entry to ensure consistency
    lwm2m_LwM2MDeviceChallenge challenge = lwm2m_LwM2MDeviceChallenge_init_zero;
    challenge.nounce = challenge_entry->nonce;
    memcpy(challenge.public_key.bytes, public_key, public_key_len > sizeof(challenge.public_key.bytes) ? sizeof(challenge.public_key.bytes) : public_key_len);
    challenge.public_key.size = public_key_len > sizeof(challenge.public_key.bytes) ? sizeof(challenge.public_key.bytes) : public_key_len;

    
    // Encode the challenge message
    uint8_t buffer[256];
    pb_ostream_t stream = pb_ostream_from_buffer(buffer, sizeof(buffer));
    
    bool status = pb_encode(&stream, lwm2m_LwM2MDeviceChallenge_fields, &challenge);
    if (!status) {
        ESP_LOGE(LOG_TAG, "Failed to encode challenge message: %s", PB_GET_ERROR(&stream));
        return false;
    }
    
    size_t message_length = stream.bytes_written;
    ESP_LOGI(LOG_TAG, "Encoded challenge message, %d bytes for device serial %ld", message_length, serial);
    
    // Send the encoded challenge to the device via GATT characteristic
    ESP_LOGI(LOG_TAG, "Sending protobuf challenge via GATT to device %02X:%02X:%02X:%02X:%02X:%02X (serial %ld)", 
             addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], serial);
    
    // If we are already connected and have a characteristic, try to send immediately.
    if (s_conn_id != 0xFFFF && s_char_handle != 0) {
        esp_err_t err = send_protobuf_data_via_gatt(buffer, message_length);
        if (err != ESP_OK) {
            ESP_LOGE(LOG_TAG, "Failed to send challenge via GATT to device %02X:%02X:%02X:%02X:%02X:%02X (serial %ld): %s", 
                     addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], serial, esp_err_to_name(err));
            return false;
        }
        ESP_LOGI(LOG_TAG, "Successfully wrote challenge message via existing GATT connection");
        return true;
    }

    // Otherwise, queue the data and initiate/open a GATT connection to this device.
    if (message_length > sizeof(s_pending_write_buf)) {
        ESP_LOGE(LOG_TAG, "Challenge message too large for pending buffer (%u > %u)", (unsigned)message_length, (unsigned)sizeof(s_pending_write_buf));
        return false;
    }
    memcpy(s_pending_write_buf, buffer, message_length);
    s_pending_write_len = message_length;
    s_pending_write_ready = true;

    // Point connection target to this device and try to open connection.
    memcpy(s_target_addr, addr, sizeof(esp_bd_addr_t));
    s_target_addr_type = addr_type;
    s_have_target = true;
    s_handshake_done = false; // ensure handshake flow can proceed
    maybe_start_handshake_from_appearance();

    ESP_LOGI(LOG_TAG, "Queued challenge for deferred send; opening GATT connection to %02X:%02X:%02X:%02X:%02X:%02X", 
             addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
    return true; // queued
}

static bool process_challenge_answer(const uint8_t *data, size_t data_len, uint32_t sender_serial, const esp_bd_addr_t sender_addr, uint8_t sender_addr_type)
{
    lwm2m_LwM2MDeviceChallengeAnswer answer = lwm2m_LwM2MDeviceChallengeAnswer_init_zero;
    
    pb_istream_t stream = pb_istream_from_buffer(data, data_len);
    bool status = pb_decode(&stream, lwm2m_LwM2MDeviceChallengeAnswer_fields, &answer);
    
    if (!status) {
        ESP_LOGE(LOG_TAG, "Failed to decode challenge answer: %s", PB_GET_ERROR(&stream));
        return false;
    }
    
    ESP_LOGI(LOG_TAG, "Decoded challenge answer message from %02X:%02X:%02X:%02X:%02X:%02X", 
             sender_addr[0], sender_addr[1], sender_addr[2], sender_addr[3], sender_addr[4], sender_addr[5]);
    
    // Try to find the matching challenge by BLE address first, then by serial if provided
    pending_challenge_t* pending = NULL;
    
    // First try to match by BLE address (more reliable)
    for (int i = 0; i < MAX_PENDING_CHALLENGES; i++) {
        if (s_pending_challenges[i].active && 
            memcmp(s_pending_challenges[i].addr, sender_addr, sizeof(esp_bd_addr_t)) == 0 &&
            s_pending_challenges[i].addr_type == sender_addr_type) {
            pending = &s_pending_challenges[i];
            sender_serial = pending->serial;
            ESP_LOGI(LOG_TAG, "Found pending challenge for BLE address %02X:%02X:%02X:%02X:%02X:%02X (serial %ld)", 
                     sender_addr[0], sender_addr[1], sender_addr[2], sender_addr[3], sender_addr[4], sender_addr[5], sender_serial);
            break;
        }
    }
    
    // If not found by address and sender_serial is provided, try by serial
    if (!pending && sender_serial != 0) {
        pending = find_pending_challenge(sender_serial);
        if (pending) {
            ESP_LOGI(LOG_TAG, "Found pending challenge by serial %ld", sender_serial);
        }
    }
    
    // If still not found, try any active challenge as fallback
    if (!pending) {
        for (int i = 0; i < MAX_PENDING_CHALLENGES; i++) {
            if (s_pending_challenges[i].active) {
                pending = &s_pending_challenges[i];
                sender_serial = pending->serial;
                ESP_LOGW(LOG_TAG, "Using fallback pending challenge for serial %ld", sender_serial);
                break;
            }
        }
    }
    
    if (!pending) {
        ESP_LOGW(LOG_TAG, "Received challenge answer but no pending challenges found");
        return false;
    }
    
    ESP_LOGI(LOG_TAG, "Processing challenge answer from device serial %ld", sender_serial);
    
    // Decrypt and verify the challenge answer signature using the correct nonce
    uint8_t decrypted_signature[64]; // Buffer to hold decrypted factory signature
    bool verification_success = false;
    
    if (answer.signature.size > 0 && pending) {
        if (answer.public_key.size < 32) {
            ESP_LOGE(LOG_TAG, "Challenge answer missing peer public key (size=%u)",
                     (unsigned)answer.public_key.size);
            return false;
        }
        if (answer.signature.size <= 16) {
            ESP_LOGE(LOG_TAG, "Challenge answer signature too short (%u)",
                     (unsigned)answer.signature.size);
            return false;
        }
        if (answer.signature.size - 16 > sizeof(decrypted_signature)) {
            ESP_LOGE(LOG_TAG, "Decrypted signature would overflow buffer (%u)",
                     (unsigned)(answer.signature.size - 16));
            return false;
        }
        ESP_LOGI(LOG_TAG, "Decrypting signature (%u bytes) using nonce %u", 
                 (unsigned)answer.signature.size, (unsigned)pending->nonce);
        
        bool decrypt_success = chacha20_poly1305_decrypt_with_nonce(answer.signature.bytes, 
                                                                    answer.signature.size, 
                                                                    decrypted_signature, 
                                                                    sizeof(decrypted_signature),
                                                                    pending->nonce,
                                                                    answer.public_key.bytes,
                                                                    answer.public_key.size);
        
        if (decrypt_success) {
            size_t decrypted_len = answer.signature.size - 16; // Remove tag length
            ESP_LOGI(LOG_TAG, "Successfully decrypted signature (%u bytes)", (unsigned)decrypted_len);
            ESP_LOG_BUFFER_HEX_LEVEL(LOG_TAG, decrypted_signature, decrypted_len, ESP_LOG_INFO);

            if (answer.public_key.size != 32) {
                ESP_LOGE(LOG_TAG, "Unexpected public key length %u in challenge answer",
                         (unsigned)answer.public_key.size);
                memset(decrypted_signature, 0, decrypted_len);
                return false;
            }

            if (decrypted_len != 64) {
                ESP_LOGE(LOG_TAG, "Unexpected factory signature length: %u", (unsigned)decrypted_len);
                memset(decrypted_signature, 0, decrypted_len);
                return false;
            }

            /* Construct message as: serial_string + device_public_key (like Java) */
            char serial_str[32];
            snprintf(serial_str, sizeof(serial_str), "%ld", sender_serial);
            size_t serial_len = strlen(serial_str);
            
            /* Allocate buffer for full message */
            size_t full_msg_len = serial_len + answer.public_key.size;
            uint8_t *full_message = malloc(full_msg_len);
            int verify_ret = -1;
            
            if (full_message) {
                memcpy(full_message, serial_str, serial_len);
                memcpy(full_message + serial_len, answer.public_key.bytes, answer.public_key.size);
                
                ESP_LOGI(LOG_TAG, "Verifying signature with message: '%s' + device_key (%u bytes total)", 
                         serial_str, (unsigned)full_msg_len);
                
                verify_ret = lwm2m_ed25519_verify_signature(vendor_public_key,
                                                            sizeof(vendor_public_key),
                                                            full_message,
                                                            full_msg_len,
                                                            decrypted_signature,
                                                            decrypted_len);
                free(full_message);
                
                if (verify_ret != 0) {
                    ESP_LOGW(LOG_TAG, "Serial+key verification failed, trying device key only...");
                    
                    verify_ret = lwm2m_ed25519_verify_signature(vendor_public_key,
                                                                sizeof(vendor_public_key),
                                                                answer.public_key.bytes,
                                                                answer.public_key.size,
                                                                decrypted_signature,
                                                                decrypted_len);
                }
            } else {
                ESP_LOGE(LOG_TAG, "Failed to allocate memory for full message, trying device key only...");
                
                verify_ret = lwm2m_ed25519_verify_signature(vendor_public_key,
                                                            sizeof(vendor_public_key),
                                                            answer.public_key.bytes,
                                                            answer.public_key.size,
                                                            decrypted_signature,
                                                            decrypted_len);
            }
            
            memset(decrypted_signature, 0, decrypted_len);

            if (verify_ret != 0) {
                ESP_LOGE(LOG_TAG, "Factory signature verification failed for serial %ld (err=%d)",
                         sender_serial, verify_ret);
                return false;
            }

            ESP_LOGI(LOG_TAG, "Factory signature verified for serial %ld", sender_serial);
            verification_success = true;
        } else {
            ESP_LOGE(LOG_TAG, "Failed to decrypt signature for device serial %ld", sender_serial);
            return false;
        }
    } else {
        ESP_LOGW(LOG_TAG, "No signature to verify or no pending challenge found");
        return false;
    }
    
    if (verification_success) {
        ESP_LOGI(LOG_TAG, "Challenge answer verified successfully for serial %ld", sender_serial);
    } else {
        ESP_LOGE(LOG_TAG, "Challenge answer verification failed for serial %ld", sender_serial);
        return false;
    }
    
    // Create a new device structure and add it to the device list
    lwm2m_LwM2MDevice new_device = {0};
    new_device.model = pending->model;
    new_device.serial = pending->serial;
    new_device.instance_id = -1;  // Will be assigned during bootstrap
    new_device.banned = false;
    
    // TODO: Properly implement MAC address storage (requires pb_callback implementation)
    // For now, we store the MAC address information in the pending challenge structure
    ESP_LOGI(LOG_TAG, "Device BLE MAC address: %02X:%02X:%02X:%02X:%02X:%02X", 
             sender_addr[0], sender_addr[1], sender_addr[2], sender_addr[3], sender_addr[4], sender_addr[5]);
    
    // Copy the public key from the challenge answer
    if (answer.public_key.size > 0 && answer.public_key.size <= sizeof(new_device.public_key.bytes)) {
        memcpy(new_device.public_key.bytes, answer.public_key.bytes, answer.public_key.size);
        new_device.public_key.size = answer.public_key.size;
    }
    
    // Add the device to the ring buffer
    esp_err_t err = device_ring_buffer_add(&new_device);
    if (err == ESP_OK) {
        ESP_LOGI(LOG_TAG, "Successfully added challenged device with serial %ld to device list", sender_serial);
        remove_pending_challenge(sender_serial);
        return true;
    } else {
        ESP_LOGE(LOG_TAG, "Failed to add challenged device with serial %ld to device list: %s", 
                 sender_serial, esp_err_to_name(err));
        return false;
    }
}

/* ------------- Helpers ------------- */
static void generate_challenge(char *out, size_t out_len)
{
    uint32_t r = (uint32_t)xTaskGetTickCount();
    const char alphabet[] = "0123456789abcdefghijklmnopqrstuvwxyz";
    size_t i = 0;
    for (; i < out_len - 1 && r; ++i) {
        out[i] = alphabet[r % 36];
        r /= 36;
    }
    if (i == 0) { out[i++] = 'x'; }
    out[i] = '\0';
}

static void start_gattc_discovery(void);
static void start_gattc_challenge_write(void);
static void start_gattc_readback(void);
static void start_gattc_write_ok(void);
static void maybe_start_handshake_from_appearance(void);
static esp_err_t send_protobuf_data_via_gatt(const uint8_t *data, size_t data_len);

/* Challenge management functions */
static pending_challenge_t* find_pending_challenge(uint32_t serial);
static pending_challenge_t* add_pending_challenge(uint32_t serial, uint32_t model, const esp_bd_addr_t addr, uint8_t addr_type);
static void remove_pending_challenge(uint32_t serial);
static bool encode_and_send_challenge(uint32_t serial, uint32_t model, const esp_bd_addr_t addr, uint8_t addr_type);
static bool process_challenge_answer(const uint8_t *data, size_t data_len, uint32_t sender_serial, const esp_bd_addr_t sender_addr, uint8_t sender_addr_type);


/* ChaCha20-Poly1305 decryption (forward declarations) */
static bool chacha20_poly1305_decrypt_with_nonce(const uint8_t *in, size_t in_len,
                                                 uint8_t *out, size_t out_cap,
                                                 uint32_t nonce32, const uint8_t *peer_pub,
                                                 size_t peer_pub_len)
{
    if (!in || in_len < 16 || !out || out_cap == 0) {
        ESP_LOGE(LOG_TAG, "Invalid decrypt parameters");
        return false;
    }

#if HAS_CHACHA20_POLY1305
    if (!peer_pub || peer_pub_len < 32) {
        ESP_LOGE(LOG_TAG, "Peer public key missing or too short (%u bytes)", (unsigned)peer_pub_len);
        return false;
    }
    if (private_key_len < 32) {
        ESP_LOGE(LOG_TAG, "Factory private key not loaded (len=%u)", (unsigned)private_key_len);
        return false;
    }

    size_t ciphertext_len = in_len - 16; /* Separate 16-byte tag */
    if (out_cap < ciphertext_len) {
        ESP_LOGE(LOG_TAG, "Output buffer too small: need %u, have %u",
                 (unsigned)ciphertext_len, (unsigned)out_cap);
        return false;
    }

    uint8_t shared_key[32] = {0};
    int crypto_ret = lwm2m_crypto_curve25519_shared_key(peer_pub, private_key, shared_key);
    if (crypto_ret != 0) {
        ESP_LOGE(LOG_TAG, "Shared key derivation failed: %d", crypto_ret);
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
        ESP_LOGE(LOG_TAG, "ChaCha20-Poly1305 decrypt failed: %d", crypto_ret);
        return false;
    }

    ESP_LOGI(LOG_TAG, "ChaCha20-Poly1305 decryption successful: %u->%u bytes",
             (unsigned)in_len, (unsigned)ciphertext_len);
    return true;

#else
    ESP_LOGW(LOG_TAG, "ChaCha20-Poly1305 not available, decryption not supported");
    return false;
#endif
}

/* Wrapper function for compatibility */
/* Removed old chacha20_poly1305_decrypt wrapper that relied on a global counter-based nonce. */

static bool adv_next_element(const uint8_t *data, size_t len, size_t *offset,
                             uint8_t *type, const uint8_t **value, size_t *value_len)
{
    if (!data || !offset || *offset >= len) return false;
    size_t i = *offset;
    uint8_t l = data[i];
    if (l == 0) { *offset = len; return false; }
    if (i + 1 + l > len) { *offset = len; return false; }
    uint8_t t = data[i + 1];
    *type = t;
    *value = &data[i + 2];
    *value_len = (l >= 1) ? (size_t)(l - 1) : 0;
    *offset = i + 1 + l;
    return true;
}

static bool extract_msd_payload(const uint8_t *adv_data, size_t adv_len,
                                const uint8_t **payload, size_t *payload_len,
                                uint16_t *company_id_out)
{
    size_t off = 0; uint8_t type; const uint8_t *val; size_t val_len;
    while (adv_next_element(adv_data, adv_len, &off, &type, &val, &val_len)) {
        if (type == 0xFF && val_len >= 2) {
            uint16_t cid = (uint16_t)val[0] | ((uint16_t)val[1] << 8);
            if (company_id_out) *company_id_out = cid;
            if (payload && payload_len) {
                *payload = (val_len > 2) ? (val + 2) : NULL;
                *payload_len = (val_len > 2) ? (val_len - 2) : 0;
            }
            return true;
        }
    }
    return false;
}

static bool extract_service_data_payload(const uint8_t *adv_data, size_t adv_len,
                                         const uint8_t **payload, size_t *payload_len,
                                         uint16_t *uuid16_out)
{
    size_t off = 0; uint8_t type; const uint8_t *val; size_t val_len;
    while (adv_next_element(adv_data, adv_len, &off, &type, &val, &val_len)) {
        if (type == 0x16 && val_len >= 2) {
            uint16_t uuid16 = (uint16_t)val[0] | ((uint16_t)val[1] << 8);
            if (uuid16_out) *uuid16_out = uuid16;
            if (payload && payload_len) {
                *payload = (val_len > 2) ? (val + 2) : NULL;
                *payload_len = (val_len > 2) ? (val_len - 2) : 0;
            }
            return true;
        }
    }
    return false;
}

static bool decode_lwm2m_message(const uint8_t *data, size_t data_len, lwm2m_LwM2MMessage *message)
{
    pb_istream_t stream = pb_istream_from_buffer(data, data_len);
    bool status = pb_decode(&stream, lwm2m_LwM2MMessage_fields, message);
    if (!status) {
        ESP_LOGE(LOG_TAG, "Failed to decode protobuf message: %s", PB_GET_ERROR(&stream));
        return false;
    }
    return true;
}

static void process_lwm2m_message(const lwm2m_LwM2MMessage *message, const esp_bd_addr_t addr, uint8_t addr_type)
{
    ESP_LOGI(LOG_TAG, "LwM2M Message decoded - model: %ld, serial: %ld", message->model, message->serial);

    // Check if device exists in the device list by serial number
    lwm2m_LwM2MDevice *existing_device = device_ring_buffer_find_by_serial(message->serial);
    
    if (existing_device != NULL) {
        ESP_LOGI(LOG_TAG, "Device with serial %ld already exists in device list", message->serial);
        // Device exists, optionally update last seen time or other fields
        // For now, we just log that it exists
    } else {
        ESP_LOGI(LOG_TAG, "Device with serial %ld not found in device list, initiating challenge", message->serial);
        
        // Check if we already have a pending challenge for this device
        pending_challenge_t* pending = find_pending_challenge(message->serial);
        if (pending) {
            ESP_LOGI(LOG_TAG, "Challenge already pending for device serial %ld", message->serial);
            return;
        }
        
        // Use the real BLE address from the periodic advertising report
        ESP_LOGI(LOG_TAG, "Device BLE address: %02X:%02X:%02X:%02X:%02X:%02X (type %u)", 
                 addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr_type);
        
        // Send challenge to device (this will also add to pending challenges)
        if (encode_and_send_challenge(message->serial, message->model, addr, addr_type)) {
            ESP_LOGI(LOG_TAG, "Challenge sent to device with serial %ld", message->serial);
        } else {
            ESP_LOGE(LOG_TAG, "Failed to send challenge to device with serial %ld", message->serial);
        }
    }
}

/* ------------- GATT Client operations ------------- */
static void start_gattc_discovery(void)
{
    if (s_conn_id == 0xFFFF) return;
    esp_bt_uuid_t uuid = { .len = ESP_UUID_LEN_16, .uuid = { .uuid16 = RW_SERVICE_UUID16 } };
    esp_err_t err = esp_ble_gattc_search_service(s_gattc_if, s_conn_id, &uuid);
    if (err != ESP_OK) {
        ESP_LOGE(LOG_TAG, "search_service failed: %s", esp_err_to_name(err));
    }
}

static void start_gattc_challenge_write(void)
{
    if (s_conn_id == 0xFFFF || s_char_handle == 0) return;
    // If we have a pending protobuf write queued, send that instead of the ASCII challenge.
    if (s_pending_write_ready && s_pending_write_len > 0) {
        ESP_LOGI(LOG_TAG, "Writing queued protobuf challenge (%u bytes)", (unsigned)s_pending_write_len);
        esp_err_t err = esp_ble_gattc_write_char(s_gattc_if, s_conn_id, s_char_handle,
                                                 s_pending_write_len, (uint8_t*)s_pending_write_buf,
                                                 ESP_GATT_WRITE_TYPE_RSP, ESP_GATT_AUTH_REQ_NONE);
        if (err != ESP_OK) {
            ESP_LOGE(LOG_TAG, "write queued protobuf failed: %s", esp_err_to_name(err));
        }
        return;
    }

    // Fallback to legacy ASCII challenge flow if nothing queued.
    generate_challenge(s_challenge, sizeof(s_challenge));
    ESP_LOGI(LOG_TAG, "Writing challenge '%s'", s_challenge);
    esp_err_t err = esp_ble_gattc_write_char(s_gattc_if, s_conn_id, s_char_handle,
                                             strlen(s_challenge), (uint8_t*)s_challenge,
                                             ESP_GATT_WRITE_TYPE_RSP, ESP_GATT_AUTH_REQ_NONE);
    if (err != ESP_OK) {
        ESP_LOGE(LOG_TAG, "write_char failed: %s", esp_err_to_name(err));
    }
}

static void start_gattc_readback(void)
{
    if (s_conn_id == 0xFFFF || s_char_handle == 0) return;
    esp_err_t err = esp_ble_gattc_read_char(s_gattc_if, s_conn_id, s_char_handle, ESP_GATT_AUTH_REQ_NONE);
    if (err != ESP_OK) {
        ESP_LOGE(LOG_TAG, "read_char failed: %s", esp_err_to_name(err));
    }
}

static void start_gattc_write_ok(void)
{
    static const char ok[] = "ok";
    if (s_conn_id == 0xFFFF || s_char_handle == 0) return;
    esp_err_t err = esp_ble_gattc_write_char(s_gattc_if, s_conn_id, s_char_handle,
                                             sizeof(ok) - 1, (uint8_t*)ok,
                                             ESP_GATT_WRITE_TYPE_RSP, ESP_GATT_AUTH_REQ_NONE);
    if (err != ESP_OK) {
        ESP_LOGE(LOG_TAG, "write 'ok' failed: %s", esp_err_to_name(err));
    } else {
        s_handshake_done = true;
        ESP_LOGI(LOG_TAG, "Handshake completed successfully");
        esp_ble_gattc_close(s_gattc_if, s_conn_id);
        #if STOP_SCAN_AFTER_HANDSHAKE
        ESP_LOGI(LOG_TAG, "Stopping extended scan (handshake complete)");
        esp_ble_gap_stop_ext_scan();
        #endif
    }
}

static esp_err_t send_protobuf_data_via_gatt(const uint8_t *data, size_t data_len)
{
    if (s_gattc_if == ESP_GATT_IF_NONE) {
        ESP_LOGE(LOG_TAG, "GATT client interface not initialized");
        return ESP_ERR_INVALID_STATE;
    }
    
    if (s_conn_id == 0xFFFF) {
        ESP_LOGE(LOG_TAG, "No active GATT connection");
        return ESP_ERR_INVALID_STATE;
    }
    
    if (s_char_handle == 0) {
        ESP_LOGE(LOG_TAG, "No valid characteristic handle");
        return ESP_ERR_INVALID_STATE;
    }
    
    esp_err_t err = esp_ble_gattc_write_char(s_gattc_if, s_conn_id, s_char_handle,
                                             data_len, (uint8_t*)data,
                                             ESP_GATT_WRITE_TYPE_RSP, ESP_GATT_AUTH_REQ_NONE);
    if (err != ESP_OK) {
        ESP_LOGE(LOG_TAG, "Failed to write protobuf data to GATT characteristic: %s", esp_err_to_name(err));
    }
    
    return err;
}

static void maybe_start_handshake_from_appearance(void)
{
    if (s_handshake_started || s_handshake_done || !s_have_target) return;
    ESP_LOGI(LOG_TAG, "Opening GATT connection to target addr %02X:%02X:%02X:%02X:%02X:%02X (type %u)",
             s_target_addr[0], s_target_addr[1], s_target_addr[2], s_target_addr[3], s_target_addr[4], s_target_addr[5], (unsigned)s_target_addr_type);
#if CONFIG_BT_BLE_50_FEATURES_SUPPORTED
    esp_err_t err = esp_ble_gattc_aux_open(s_gattc_if, s_target_addr, s_target_addr_type, true);
#else
    esp_err_t err = esp_ble_gattc_open(s_gattc_if, s_target_addr, s_target_addr_type, true);
#endif
    if (err != ESP_OK) {
        ESP_LOGE(LOG_TAG, "gattc_open failed: %s", esp_err_to_name(err));
        return;
    }
    s_handshake_started = true;
}

/* ------------- Event Handlers ------------- */
static void gattc_event_handler(esp_gattc_cb_event_t event, esp_gatt_if_t gattc_if, esp_ble_gattc_cb_param_t *param)
{
    switch (event) {
    case ESP_GATTC_REG_EVT:
        s_gattc_if = gattc_if; break;
    case ESP_GATTC_OPEN_EVT:
        if (param->open.status != ESP_GATT_OK) { s_handshake_started = false; break; }
        s_conn_id = param->open.conn_id; esp_ble_gattc_send_mtu_req(gattc_if, s_conn_id); break;
    case ESP_GATTC_DISCONNECT_EVT:
        s_conn_id = 0xFFFF; s_svc_start = s_svc_end = 0; s_char_handle = 0; s_handshake_started = false; break;
    case ESP_GATTC_CFG_MTU_EVT: start_gattc_discovery(); break;
    case ESP_GATTC_SEARCH_RES_EVT: {
        const esp_gatt_id_t *sid = &param->search_res.srvc_id;
        if (sid->uuid.len == ESP_UUID_LEN_16 && sid->uuid.uuid.uuid16 == RW_SERVICE_UUID16) {
            s_svc_start = param->search_res.start_handle; s_svc_end = param->search_res.end_handle;
        }
        break; }
    case ESP_GATTC_SEARCH_CMPL_EVT: {
        if (param->search_cmpl.status == ESP_GATT_OK && s_svc_start && s_svc_end) {
            uint16_t count = 0; esp_bt_uuid_t uuid = { .len = ESP_UUID_LEN_16, .uuid = { .uuid16 = RW_CHAR_UUID16 } };
            if (esp_ble_gattc_get_attr_count(gattc_if, s_conn_id, ESP_GATT_DB_CHARACTERISTIC, s_svc_start, s_svc_end, 0, &count) == ESP_GATT_OK && count) {
                esp_gattc_char_elem_t *chars = calloc(count, sizeof(*chars));
                if (chars) {
                    uint16_t out_count = count;
                    if (esp_ble_gattc_get_char_by_uuid(gattc_if, s_conn_id, s_svc_start, s_svc_end, uuid, chars, &out_count) == ESP_GATT_OK && out_count) {
                        s_char_handle = chars[0].char_handle; start_gattc_challenge_write();
                    }
                    free(chars);
                }
            }
        }
        break; }
    case ESP_GATTC_WRITE_CHAR_EVT:
        if (param->write.status == ESP_GATT_OK) {
            // Clear pending buffer after successful write
            if (s_pending_write_ready) {
                s_pending_write_ready = false;
                s_pending_write_len = 0;
            }
            // Prepare to read back once; enable one retry if empty/error
            s_read_retries_left = READ_RETRY_MAX;
            start_gattc_readback();
        }
        break;
    case ESP_GATTC_READ_CHAR_EVT: {
        uint16_t handle = param->read.handle;
        uint16_t len = param->read.value_len;
        ESP_LOGI(LOG_TAG, "READ_CHAR_EVT handle=0x%04X status=%d len=%u", handle, param->read.status, (unsigned)len);
        if (param->read.status == ESP_GATT_OK && param->read.value && param->read.value_len) {
            ESP_LOG_BUFFER_HEX(LOG_TAG, param->read.value, param->read.value_len);
            
            // Try to decode as protobuf challenge answer first
            lwm2m_LwM2MDeviceChallengeAnswer answer = lwm2m_LwM2MDeviceChallengeAnswer_init_zero;
            pb_istream_t stream = pb_istream_from_buffer(param->read.value, param->read.value_len);
            bool decode_status = pb_decode(&stream, lwm2m_LwM2MDeviceChallengeAnswer_fields, &answer);
            
            if (decode_status) {
                ESP_LOGI(LOG_TAG, "Successfully decoded LwM2MDeviceChallengeAnswer");
                
                // Print public key in hex if present
                if (answer.public_key.size > 0) {
                    ESP_LOGI(LOG_TAG, "Public key (%u bytes):", (unsigned)answer.public_key.size);
                    ESP_LOG_BUFFER_HEX(LOG_TAG, answer.public_key.bytes, answer.public_key.size);
                } else {
                    ESP_LOGW(LOG_TAG, "No public key in challenge answer");
                }
                
                // Print signature in hex if present
                if (answer.signature.size > 0) {
                    ESP_LOGI(LOG_TAG, "Signature (%u bytes):", (unsigned)answer.signature.size);
                    ESP_LOG_BUFFER_HEX(LOG_TAG, answer.signature.bytes, answer.signature.size);
                } else {
                    ESP_LOGW(LOG_TAG, "No signature in challenge answer");
                }

                // Get sender address from current GATT connection target
                esp_bd_addr_t sender_addr;
                memcpy(sender_addr, s_target_addr, sizeof(esp_bd_addr_t));
                uint8_t sender_addr_type = s_target_addr_type;
                
                // Process the challenge answer (includes decryption and verification)
                if (process_challenge_answer(param->read.value, param->read.value_len, 0, sender_addr, sender_addr_type)) {
                    ESP_LOGI(LOG_TAG, "Challenge answer processed successfully");
                } else {
                    ESP_LOGW(LOG_TAG, "Failed to process challenge answer");
                }
            } else {
                // Fallback to legacy ASCII challenge processing
                ESP_LOGI(LOG_TAG, "Not a protobuf message, trying legacy ASCII challenge format");
                // mark the challenge as failed, and put the device into banned state for 30min
            }
        } else {
            // If read failed or zero-length, retry once if available
            if (s_read_retries_left > 0) {
                s_read_retries_left--;
                ESP_LOGW(LOG_TAG, "Read returned status=%d len=%u; retrying (%d left)", param->read.status, (unsigned)len, s_read_retries_left);
                start_gattc_readback();
            }
        }
        break; }
    default: break;
    }
}

static void gap_event_handler(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param)
{
    switch (event) {
    case ESP_GAP_BLE_SET_EXT_SCAN_PARAMS_COMPLETE_EVT:
    case ESP_GAP_BLE_EXT_SCAN_START_COMPLETE_EVT:
    case ESP_GAP_BLE_EXT_SCAN_STOP_COMPLETE_EVT:
        if (s_scan_sem) {
            xSemaphoreGive(s_scan_sem);
        }
        break;
    case ESP_GAP_BLE_EXT_ADV_REPORT_EVT: {
        uint8_t *adv_name = NULL; uint8_t adv_name_len = 0;
        adv_name = esp_ble_resolve_adv_data_by_type(param->ext_adv_report.params.adv_data,
                                                    param->ext_adv_report.params.adv_data_len,
                                                    ESP_BLE_AD_TYPE_NAME_CMPL, &adv_name_len);
        if (adv_name && adv_name_len == strlen(s_remote_device_name) &&
            memcmp(adv_name, s_remote_device_name, adv_name_len) == 0) {
            /* Attempt to create periodic sync if not already tracked */
            periodic_sync_entry_t *entry = alloc_sync_entry(param->ext_adv_report.params.sid,
                                                            param->ext_adv_report.params.addr,
                                                            param->ext_adv_report.params.addr_type);
            if (entry) {
                s_periodic_adv_sync_params.sid = param->ext_adv_report.params.sid;
                s_periodic_adv_sync_params.addr_type = param->ext_adv_report.params.addr_type;
                memcpy(s_periodic_adv_sync_params.addr, param->ext_adv_report.params.addr, sizeof(esp_bd_addr_t));
                esp_err_t err = esp_ble_gap_periodic_adv_create_sync(&s_periodic_adv_sync_params);
                if (err != ESP_OK) {
                    ESP_LOGW(LOG_TAG, "Failed to create periodic sync (sid %u) err=%s", param->ext_adv_report.params.sid, esp_err_to_name(err));
                } else {
                    ESP_LOGI(LOG_TAG, "Creating periodic sync for SID %u", param->ext_adv_report.params.sid);
                }
            } else {
                /* Either already present or table full */
            }
        }
        if (adv_name && adv_name_len) {
            static const char connect_name[] = "ESP_CONNECT"; size_t cn_len = strlen(connect_name);
            if (!s_have_target && adv_name_len == cn_len && memcmp(adv_name, connect_name, cn_len) == 0) {
                memcpy(s_target_addr, param->ext_adv_report.params.addr, sizeof(esp_bd_addr_t));
                s_target_addr_type = param->ext_adv_report.params.addr_type; s_have_target = true;
            }
        }
        break; }
    case ESP_GAP_BLE_PERIODIC_ADV_CREATE_SYNC_COMPLETE_EVT:
        ESP_LOGI(LOG_TAG, "Periodic create sync complete status=%d", param->period_adv_create_sync.status);
        break;
    case ESP_GAP_BLE_PERIODIC_ADV_SYNC_ESTAB_EVT: {
        if (param->periodic_adv_sync_estab.status == ESP_BT_STATUS_SUCCESS) {
            periodic_sync_entry_t *e = find_sync_entry(param->periodic_adv_sync_estab.sid,
                                                       param->periodic_adv_sync_estab.adv_addr);
            if (e) {
                e->sync_handle = param->periodic_adv_sync_estab.sync_handle;
                s_current_sync_handle = param->periodic_adv_sync_estab.sync_handle; // Track current handle
            }
            ESP_LOGI(LOG_TAG, "Periodic sync established sid=%u handle=%u interval=%u phy=%u", 
                     param->periodic_adv_sync_estab.sid,
                     param->periodic_adv_sync_estab.sync_handle,
                     param->periodic_adv_sync_estab.period_adv_interval,
                     param->periodic_adv_sync_estab.adv_phy);
        } else {
            ESP_LOGW(LOG_TAG, "Periodic sync establish failed status=%d", param->periodic_adv_sync_estab.status);
        }
        break; }
    case ESP_GAP_BLE_PERIODIC_ADV_SYNC_LOST_EVT:
        ESP_LOGW(LOG_TAG, "Periodic sync lost handle=%u", param->periodic_adv_sync_lost.sync_handle);
        if (s_current_sync_handle == param->periodic_adv_sync_lost.sync_handle) {
            s_current_sync_handle = 0xFFFF; // Clear current handle if it was lost
        }
        free_sync_entry_by_handle(param->periodic_adv_sync_lost.sync_handle);
        break;
    case ESP_GAP_BLE_PERIODIC_ADV_SYNC_TERMINATE_COMPLETE_EVT:
        /* Some ESP-IDF versions (v5.5.1) ble_period_adv_sync_terminate_cmpl_param do not expose sync_handle */
        ESP_LOGI(LOG_TAG, "Periodic sync terminated status=%d", param->period_adv_sync_term.status);
        /* Without the sync handle we cannot precisely free a single entry. Typically a LOST event
           will already have cleaned it up. If needed, consider tracking the handle at the time
           esp_ble_gap_periodic_adv_terminate_sync() is called and freeing here. */
        break;
    case ESP_GAP_BLE_PERIODIC_ADV_SYNC_CANCEL_COMPLETE_EVT:
        ESP_LOGI(LOG_TAG, "Periodic sync cancel complete status=%d", param->period_adv_sync_cancel.status);
        break;
    case ESP_GAP_BLE_PERIODIC_ADV_REPORT_EVT: {
        if (param->period_adv_report.params.data_length > 0) {
            // Find the sync entry using the currently tracked sync handle
            esp_bd_addr_t sender_addr = {0};
            uint8_t sender_addr_type = BLE_ADDR_TYPE_PUBLIC;
            bool found_sender = false;
            
            // Try to find the sync entry by the current sync handle
            if (s_current_sync_handle != 0xFFFF) {
                for (size_t i = 0; i < MAX_PERIODIC_SYNCS; i++) {
                    if (s_periodic_syncs[i].used && s_periodic_syncs[i].sync_handle == s_current_sync_handle) {
                        memcpy(sender_addr, s_periodic_syncs[i].addr, sizeof(esp_bd_addr_t));
                        sender_addr_type = s_periodic_syncs[i].addr_type;
                        found_sender = true;
                        ESP_LOGV(LOG_TAG, "Found sender addr %02X:%02X:%02X:%02X:%02X:%02X for sync handle %u", 
                                 sender_addr[0], sender_addr[1], sender_addr[2], sender_addr[3], 
                                 sender_addr[4], sender_addr[5], s_current_sync_handle);
                        break;
                    }
                }
            }
            
            // Fallback: try to find any active sync entry
            if (!found_sender) {
                for (size_t i = 0; i < MAX_PERIODIC_SYNCS; i++) {
                    if (s_periodic_syncs[i].used) {
                        memcpy(sender_addr, s_periodic_syncs[i].addr, sizeof(esp_bd_addr_t));
                        sender_addr_type = s_periodic_syncs[i].addr_type;
                        found_sender = true;
                        ESP_LOGD(LOG_TAG, "Using fallback sync entry %d for periodic advertising report", i);
                        break;
                    }
                }
            }
            
            if (!found_sender) {
                ESP_LOGW(LOG_TAG, "Could not find any active sync entry for periodic advertising report");
                // Use dummy address as fallback
                memset(sender_addr, 0, sizeof(esp_bd_addr_t));
                sender_addr_type = BLE_ADDR_TYPE_PUBLIC;
            }
            
            const uint8_t *adv_data = param->period_adv_report.params.data; size_t adv_len = param->period_adv_report.params.data_length;
            const uint8_t *protobuf_data = NULL; size_t protobuf_len = 0; uint16_t company_id = 0;
            if (extract_msd_payload(adv_data, adv_len, &protobuf_data, &protobuf_len, &company_id) && protobuf_data && protobuf_len) {
                // First try to decode as LwM2MMessage (normal discovery messages)
                lwm2m_LwM2MMessage message = lwm2m_LwM2MMessage_init_zero;
                if (decode_lwm2m_message(protobuf_data, protobuf_len, &message)) {
                    process_lwm2m_message(&message, sender_addr, sender_addr_type);
                    break;
                }
                
                // If that fails, try to decode as LwM2MDeviceChallengeAnswer
                if (process_challenge_answer(protobuf_data, protobuf_len, 0, sender_addr, sender_addr_type)) {
                    // Challenge answer was processed successfully
                    break;
                }
            }
            const uint8_t *svc_payload = NULL; size_t svc_len = 0; uint16_t uuid16 = 0;
            if (extract_service_data_payload(adv_data, adv_len, &svc_payload, &svc_len, &uuid16) && svc_payload && svc_len) {
                // First try to decode as LwM2MMessage (normal discovery messages)
                lwm2m_LwM2MMessage message = lwm2m_LwM2MMessage_init_zero;
                if (decode_lwm2m_message(svc_payload, svc_len, &message)) {
                    process_lwm2m_message(&message, sender_addr, sender_addr_type);
                    break;
                }
                
                // If that fails, try to decode as LwM2MDeviceChallengeAnswer
                if (process_challenge_answer(svc_payload, svc_len, 0, sender_addr, sender_addr_type)) {
                    // Challenge answer was processed successfully
                    break;
                }
            }
        }
        break; }
    default: break;
    }
}

/* ------------- Public API ------------- */
esp_err_t ble_client_init_and_start(void)
{
    if (s_initialized) return ESP_OK;
    /* removed unused variable 'ret' */


    ESP_ERROR_CHECK(esp_bt_controller_mem_release(ESP_BT_MODE_CLASSIC_BT));
    esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_bt_controller_init(&bt_cfg));
    ESP_ERROR_CHECK(esp_bt_controller_enable(ESP_BT_MODE_BLE));
    ESP_ERROR_CHECK(esp_bluedroid_init());
    ESP_ERROR_CHECK(esp_bluedroid_enable());

    ESP_ERROR_CHECK(esp_ble_gattc_register_callback(gattc_event_handler));
    ESP_ERROR_CHECK(esp_ble_gattc_app_register(GATTC_APP_ID));
    ESP_ERROR_CHECK(esp_ble_gap_register_callback(gap_event_handler));

    vTaskDelay(pdMS_TO_TICKS(200));
    s_scan_sem = xSemaphoreCreateBinary();
    if (!s_scan_sem) return ESP_ERR_NO_MEM;
    FUNC_SEND_WAIT_SEM(esp_ble_gap_set_ext_scan_params(&s_ext_scan_params), s_scan_sem);
    FUNC_SEND_WAIT_SEM(esp_ble_gap_start_ext_scan(EXT_SCAN_DURATION, EXT_SCAN_PERIOD), s_scan_sem);
    s_initialized = true;
    return ESP_OK;
}

esp_err_t ble_client_stop_scan(void)
{
    return esp_ble_gap_stop_ext_scan();
}

bool ble_client_handshake_done(void)
{
    return s_handshake_done;
}

uint32_t ble_client_get_pending_challenges_count(void)
{
    uint32_t count = 0;
    for (int i = 0; i < MAX_PENDING_CHALLENGES; i++) {
        if (s_pending_challenges[i].active) {
            count++;
        }
    }
    return count;
}

void ble_client_cleanup_stale_challenges(void)
{
    uint32_t current_time = xTaskGetTickCount();
    const uint32_t CHALLENGE_TIMEOUT_MS = 30000; // 30 seconds timeout
    const uint32_t timeout_ticks = pdMS_TO_TICKS(CHALLENGE_TIMEOUT_MS);
    
    for (int i = 0; i < MAX_PENDING_CHALLENGES; i++) {
        if (s_pending_challenges[i].active) {
            uint32_t age = current_time - s_pending_challenges[i].challenge_time;
            if (age > timeout_ticks) {
                ESP_LOGW(LOG_TAG, "Removing stale challenge for serial %ld (age: %ld ms)", 
                         s_pending_challenges[i].serial, pdTICKS_TO_MS(age));
                s_pending_challenges[i].active = false;
            }
        }
    }
}

bool ble_client_find_challenge_by_address(const uint8_t *addr, uint32_t *serial_out, uint32_t *model_out)
{
    if (!addr) return false;
    
    for (int i = 0; i < MAX_PENDING_CHALLENGES; i++) {
        if (s_pending_challenges[i].active && 
            memcmp(s_pending_challenges[i].addr, addr, sizeof(esp_bd_addr_t)) == 0) {
            if (serial_out) *serial_out = s_pending_challenges[i].serial;
            if (model_out) *model_out = s_pending_challenges[i].model;
            return true;
        }
    }
    return false;
}
