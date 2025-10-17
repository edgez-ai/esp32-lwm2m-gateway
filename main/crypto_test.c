/*
 * ECDH Cryptography Test Module
 * 
 * This module provides test functions for ECDH key exchange and
 * secure communication using ChaCha20-Poly1305 encryption.
 */

#include "crypto_test.h"
#include "esp_log.h"
#include <string.h>
#include "lwm2m_helpers.h"

#ifdef ESP_PLATFORM
#include "mbedtls/ecdh.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecp.h"
#endif

static const char *TAG = "crypto_test";

#ifdef ESP_PLATFORM
/**
 * @brief Generate ECDH key pair using P-256 curve
 * 
 * @param private_key Output buffer for private key (32 bytes)
 * @param public_key Output buffer for public key (65 bytes uncompressed)
 * @return 0 on success, negative error code on failure
 */
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

void test_ecdh_crypto_with_keygen(void)
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