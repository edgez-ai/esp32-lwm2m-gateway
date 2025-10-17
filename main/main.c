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

 #include "lwip/err.h"
 #include "lwip/sockets.h"
 #include "lwip/sys.h"
 #include <lwip/netdb.h>
 #include "flash.h"
#include "lwm2m_client.h"
#include "device.h"
#include "lwm2m_helpers.h"
//#define LWM2M_SERVER_URI "coaps://192.168.10.148:5685"
static const char *TAG = "main";
static float tsens_out; /* local temperature reading passed to lwm2m module */
/* BLE GAP/GATT logic removed; now handled inside ble.c */

/* Helper function to generate ECDH key pair for testing */
#ifdef ESP_PLATFORM
#include "mbedtls/ecdh.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecp.h"

static int generate_ecdh_keypair(uint8_t *private_key, uint8_t *public_key)
{
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point Q;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    int ret = 0;
    size_t olen;
    
    // Initialize contexts
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&Q);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    
    // Seed the random number generator
    const char *pers = "ecdh_key_gen";
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers, strlen(pers));
    if (ret != 0) {
        ESP_LOGE(TAG, "mbedtls_ctr_drbg_seed failed: -0x%04x", -ret);
        goto cleanup;
    }
    
    // Load the P-256 curve
    ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) {
        ESP_LOGE(TAG, "mbedtls_ecp_group_load failed: -0x%04x", -ret);
        goto cleanup;
    }
    
    // Generate key pair
    ret = mbedtls_ecp_gen_keypair(&grp, &d, &Q, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        ESP_LOGE(TAG, "mbedtls_ecp_gen_keypair failed: -0x%04x", -ret);
        goto cleanup;
    }
    
    // Export private key (32 bytes)
    ret = mbedtls_mpi_write_binary(&d, private_key, 32);
    if (ret != 0) {
        ESP_LOGE(TAG, "Private key export failed: -0x%04x", -ret);
        goto cleanup;
    }
    
    // Export public key (65 bytes uncompressed format)
    ret = mbedtls_ecp_point_write_binary(&grp, &Q,
                                        MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, public_key, 65);
    if (ret != 0 || olen != 65) {
        ESP_LOGE(TAG, "Public key export failed: -0x%04x, olen=%d", -ret, olen);
        ret = -1;
        goto cleanup;
    }
    
cleanup:
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&Q);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    return ret;
}
#endif

/* Test function for ECDH key exchange and encrypt/decrypt process */
static void test_ecdh_crypto_full_process(void)
{
    ESP_LOGI(TAG, "=== Starting ECDH Crypto Full Process Test ===");
    
    // For testing, we'll simulate two parties with hardcoded keys
    // In a real scenario, these would be generated using ECDH key generation
    
    // Simulate Alice's private key (32 bytes for P-256)
    uint8_t alice_private_key[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
    };
    
    // Simulate Bob's public key (65 bytes: 0x04 + X coordinate + Y coordinate)
    uint8_t bob_public_key[65] = {
        0x04, // Uncompressed point indicator
        // X coordinate (32 bytes)
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
        // Y coordinate (32 bytes)
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
        0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
        0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
        0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60
    };
    
    // Step 1: ECDH Key Derivation
    uint8_t derived_key[32];
    ESP_LOGI(TAG, "Step 1: Performing ECDH key derivation...");
    
    int result = lwm2m_ecdh_derive_aes_key_simple(bob_public_key, alice_private_key, derived_key);
    if (result != 0) {
        ESP_LOGE(TAG, "ECDH key derivation failed with code: %d", result);
        return;
    }
    
    ESP_LOGI(TAG, "ECDH key derivation successful!");
    ESP_LOG_BUFFER_HEX(TAG, derived_key, 32);
    
    // Step 2: Prepare test data for encryption
    const char *test_message = "Hello, this is a secret message for LwM2M device!";
    const char *aad_data = "LwM2M-Device-ID:12345";
    size_t message_len = strlen(test_message);
    size_t aad_len = strlen(aad_data);
    
    uint8_t nonce[12];
    uint8_t ciphertext[256];
    uint8_t tag[16];
    uint8_t decrypted_text[256];
    
    ESP_LOGI(TAG, "Step 2: Preparing test data...");
    ESP_LOGI(TAG, "Original message: %s", test_message);
    ESP_LOGI(TAG, "AAD data: %s", aad_data);
    
    // Step 3: Generate secure nonce
    ESP_LOGI(TAG, "Step 3: Generating secure nonce...");
    result = lwm2m_chacha20_generate_nonce(nonce);
    if (result != 0) {
        ESP_LOGE(TAG, "Nonce generation failed with code: %d", result);
        return;
    }
    
    ESP_LOGI(TAG, "Nonce generated successfully!");
    ESP_LOG_BUFFER_HEX(TAG, nonce, 12);
    
    // Step 4: Encrypt the message
    ESP_LOGI(TAG, "Step 4: Encrypting message with ChaCha20-Poly1305...");
    result = lwm2m_chacha20_poly1305_encrypt(
        derived_key, nonce,
        (const uint8_t *)test_message, message_len,
        (const uint8_t *)aad_data, aad_len,
        ciphertext, tag
    );
    
    if (result != 0) {
        ESP_LOGE(TAG, "Encryption failed with code: %d", result);
        return;
    }
    
    ESP_LOGI(TAG, "Encryption successful!");
    ESP_LOGI(TAG, "Ciphertext (%d bytes):", message_len);
    ESP_LOG_BUFFER_HEX(TAG, ciphertext, message_len);
    ESP_LOGI(TAG, "Authentication tag (16 bytes):");
    ESP_LOG_BUFFER_HEX(TAG, tag, 16);
    
    // Step 5: Decrypt the message
    ESP_LOGI(TAG, "Step 5: Decrypting message...");
    memset(decrypted_text, 0, sizeof(decrypted_text)); // Clear buffer
    
    result = lwm2m_chacha20_poly1305_decrypt(
        derived_key, nonce,
        ciphertext, message_len,
        (const uint8_t *)aad_data, aad_len,
        tag, decrypted_text
    );
    
    if (result != 0) {
        ESP_LOGE(TAG, "Decryption failed with code: %d", result);
        if (result == -3) {
            ESP_LOGE(TAG, "Authentication tag verification failed!");
        }
        return;
    }
    
    // Null-terminate the decrypted text
    decrypted_text[message_len] = '\0';
    
    ESP_LOGI(TAG, "Decryption successful!");
    ESP_LOGI(TAG, "Decrypted message: %s", (char *)decrypted_text);
    
    // Step 6: Verify the decrypted message matches the original
    if (memcmp(test_message, decrypted_text, message_len) == 0) {
        ESP_LOGI(TAG, "✓ Message integrity verified - decrypted text matches original!");
    } else {
        ESP_LOGE(TAG, "✗ Message integrity check failed - decrypted text doesn't match!");
    }
    
    // Step 7: Test authentication failure (tamper detection)
    ESP_LOGI(TAG, "Step 7: Testing tamper detection...");
    uint8_t tampered_tag[16];
    memcpy(tampered_tag, tag, 16);
    tampered_tag[0] ^= 0x01; // Flip one bit to simulate tampering
    
    memset(decrypted_text, 0, sizeof(decrypted_text));
    result = lwm2m_chacha20_poly1305_decrypt(
        derived_key, nonce,
        ciphertext, message_len,
        (const uint8_t *)aad_data, aad_len,
        tampered_tag, decrypted_text
    );
    
    if (result == -3) {
        ESP_LOGI(TAG, "✓ Tamper detection working - correctly rejected tampered tag");
    } else {
        ESP_LOGE(TAG, "✗ Tamper detection failed - should have rejected tampered tag");
    }
    
    ESP_LOGI(TAG, "=== ECDH Crypto Full Process Test Complete ===");
}

/* Test function using real ECDH key generation */
static void test_ecdh_crypto_with_keygen(void)
{
    ESP_LOGI(TAG, "=== Starting ECDH Crypto Test with Real Key Generation ===");
    
#ifdef ESP_PLATFORM
    // Generate Alice's key pair
    uint8_t alice_private_key[32];
    uint8_t alice_public_key[65];
    
    // Generate Bob's key pair  
    uint8_t bob_private_key[32];
    uint8_t bob_public_key[65];
    
    ESP_LOGI(TAG, "Step 1: Generating Alice's ECDH key pair...");
    int result = generate_ecdh_keypair(alice_private_key, alice_public_key);
    if (result != 0) {
        ESP_LOGE(TAG, "Alice's key generation failed");
        return;
    }
    ESP_LOGI(TAG, "Alice's key pair generated successfully!");
    ESP_LOGI(TAG, "Alice's public key:");
    ESP_LOG_BUFFER_HEX(TAG, alice_public_key, 65);
    
    ESP_LOGI(TAG, "Step 2: Generating Bob's ECDH key pair...");
    result = generate_ecdh_keypair(bob_private_key, bob_public_key);
    if (result != 0) {
        ESP_LOGE(TAG, "Bob's key generation failed");
        return;
    }
    ESP_LOGI(TAG, "Bob's key pair generated successfully!");
    ESP_LOGI(TAG, "Bob's public key:");
    ESP_LOG_BUFFER_HEX(TAG, bob_public_key, 65);
    
    // Step 3: Alice derives shared key using Bob's public key
    uint8_t alice_shared_key[32];
    ESP_LOGI(TAG, "Step 3: Alice deriving shared key...");
    result = lwm2m_ecdh_derive_aes_key_simple(bob_public_key, alice_private_key, alice_shared_key);
    if (result != 0) {
        ESP_LOGE(TAG, "Alice's key derivation failed with code: %d", result);
        return;
    }
    ESP_LOGI(TAG, "Alice's shared key:");
    ESP_LOG_BUFFER_HEX(TAG, alice_shared_key, 32);
    
    // Step 4: Bob derives shared key using Alice's public key
    uint8_t bob_shared_key[32];
    ESP_LOGI(TAG, "Step 4: Bob deriving shared key...");
    result = lwm2m_ecdh_derive_aes_key_simple(alice_public_key, bob_private_key, bob_shared_key);
    if (result != 0) {
        ESP_LOGE(TAG, "Bob's key derivation failed with code: %d", result);
        return;
    }
    ESP_LOGI(TAG, "Bob's shared key:");
    ESP_LOG_BUFFER_HEX(TAG, bob_shared_key, 32);
    
    // Step 5: Verify both parties derived the same key
    if (memcmp(alice_shared_key, bob_shared_key, 32) == 0) {
        ESP_LOGI(TAG, "✓ ECDH Key Exchange Successful - Both parties have same shared key!");
    } else {
        ESP_LOGE(TAG, "✗ ECDH Key Exchange Failed - Shared keys don't match!");
        return;
    }
    
    // Step 6: Test secure communication using the shared key
    ESP_LOGI(TAG, "Step 6: Testing secure communication...");
    const char *alice_message = "Hello Bob, this is Alice sending a secure message!";
    const char *device_info = "DeviceType:LwM2M-Gateway,SerialNo:GW001";
    
    uint8_t nonce[12];
    uint8_t ciphertext[256];
    uint8_t tag[16];
    uint8_t plaintext[256];
    size_t message_len = strlen(alice_message);
    
    // Alice encrypts message to Bob
    result = lwm2m_chacha20_generate_nonce(nonce);
    if (result != 0) {
        ESP_LOGE(TAG, "Nonce generation failed");
        return;
    }
    
    result = lwm2m_chacha20_poly1305_encrypt(
        alice_shared_key, nonce,
        (const uint8_t *)alice_message, message_len,
        (const uint8_t *)device_info, strlen(device_info),
        ciphertext, tag
    );
    
    if (result != 0) {
        ESP_LOGE(TAG, "Alice's encryption failed with code: %d", result);
        return;
    }
    
    ESP_LOGI(TAG, "Alice encrypted message successfully!");
    ESP_LOGI(TAG, "Original: %s", alice_message);
    ESP_LOGI(TAG, "Encrypted (%d bytes):", message_len);
    ESP_LOG_BUFFER_HEX(TAG, ciphertext, message_len);
    
    // Bob decrypts message from Alice
    memset(plaintext, 0, sizeof(plaintext));
    result = lwm2m_chacha20_poly1305_decrypt(
        bob_shared_key, nonce,
        ciphertext, message_len,
        (const uint8_t *)device_info, strlen(device_info),
        tag, plaintext
    );
    
    if (result != 0) {
        ESP_LOGE(TAG, "Bob's decryption failed with code: %d", result);
        return;
    }
    
    plaintext[message_len] = '\0';
    ESP_LOGI(TAG, "Bob decrypted message: %s", (char *)plaintext);
    
    if (memcmp(alice_message, plaintext, message_len) == 0) {
        ESP_LOGI(TAG, "✓ Secure Communication Test Successful!");
    } else {
        ESP_LOGE(TAG, "✗ Message corruption detected!");
    }
    
    ESP_LOGI(TAG, "=== ECDH Crypto Test with Real Key Generation Complete ===");
    
#else
    ESP_LOGW(TAG, "Real key generation test skipped - requires ESP-IDF platform");
#endif
}

void app_main(void)
{
        // Default config
    temp_sensor_config_t temp_sensor = TSENS_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(temp_sensor_set_config(temp_sensor));
    ESP_ERROR_CHECK(temp_sensor_start());

    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    ESP_ERROR_CHECK(example_connect());
    /* DTLS log level now set inside lwm2m_client_start() */
    ESP_ERROR_CHECK(temp_sensor_read_celsius(&tsens_out));
    ESP_LOGI(TAG, "Temperature: %.2f °C", tsens_out);

    /* Test ECDH and encryption/decryption functionality */
    test_ecdh_crypto_full_process();
    
    /* Test ECDH with real key generation */
    test_ecdh_crypto_with_keygen();

    /* Initialize device ring buffer with persistence */
    ESP_ERROR_CHECK(device_ring_buffer_init_with_persistence());

    /* Example: Add some test devices to demonstrate ring buffer functionality */
    ESP_LOGI(TAG, "Demonstrating device ring buffer functionality...");
        
    device_ring_buffer_print_status();
    
    // Test finding a device
    lwm2m_LwM2MDevice *found = device_ring_buffer_find_by_serial(2002);
    if (found) {
        ESP_LOGI(TAG, "Found device with serial 2002: Model=%ld, Instance=%ld", 
                 found->model, found->instance_id);
    }

    /* Start LwM2M client task (moved to lwm2m_client.c) */
    lwm2m_client_start();

    /* Start BLE client (scanning + handshake) */
    esp_err_t ble_ret = ble_client_init_and_start();
    if (ble_ret != ESP_OK) {
        ESP_LOGE(TAG, "BLE init failed: %s", esp_err_to_name(ble_ret));
    }
}
