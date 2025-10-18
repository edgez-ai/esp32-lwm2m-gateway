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

extern uint8_t public_key[64];
extern uint8_t private_key[64];
extern size_t public_key_len;
extern size_t private_key_len;

static const char *TAG = "crypto_test";

void test_ecdh_crypto_with_keygen(void)
{
    ESP_LOGI(TAG, "=== Starting Curve25519 Crypto Test with Predefined Keys ===");
    
#ifdef ESP_PLATFORM
    static const uint8_t bob_public_key_predefined[32] = {
        0xE6, 0xBA, 0x75, 0xEA, 0x41, 0x9E, 0xC6, 0xF7,
        0x8A, 0x28, 0x65, 0x3E, 0xD6, 0xB8, 0xC5, 0x45,
        0x78, 0x6F, 0x59, 0xB3, 0x37, 0x6E, 0x86, 0x63,
        0x2A, 0x5D, 0xD1, 0xB9, 0x1D, 0x8E, 0x96, 0x64
    };
    static const uint8_t bob_private_key_predefined[32] = {
        0x68, 0x0A, 0x90, 0x0F, 0xAA, 0x03, 0x3B, 0x1E,
        0x16, 0x2D, 0x1C, 0x19, 0xB7, 0x67, 0xA2, 0x6F,
        0xDC, 0x5A, 0x51, 0x37, 0x5C, 0x07, 0xCC, 0x41,
        0x85, 0x0E, 0xBA, 0xCC, 0x80, 0xFD, 0xDE, 0x7E
    };

    uint8_t alice_private_key[32];
    uint8_t alice_public_key[32];
    uint8_t alice_public_key_derived[32];
    int result = 0;

    ESP_LOGI(TAG, "Step 1: Loading Alice's predefined Curve25519 key pair...");
    if (private_key_len < 32 || public_key_len < 32) {
        ESP_LOGE(TAG, "Alice's key material is unavailable (priv=%d bytes, pub=%d bytes)",
                 (int)private_key_len, (int)public_key_len);
        ESP_LOGE(TAG, "Ensure factory data is loaded before running crypto tests");
        return;
    }

    memcpy(alice_private_key, private_key, sizeof(alice_private_key));
    memcpy(alice_public_key, public_key, sizeof(alice_public_key));
    ESP_LOGI(TAG, "Alice's private key (from factory data):");
    ESP_LOG_BUFFER_HEX(TAG, alice_private_key, sizeof(alice_private_key));
    ESP_LOGI(TAG, "Alice's public key (from factory data):");
    ESP_LOG_BUFFER_HEX(TAG, alice_public_key, sizeof(alice_public_key));

    result = lwm2m_curve25519_public_from_private(alice_private_key, alice_public_key_derived);
    if (result == 0) {
        if (memcmp(alice_public_key, alice_public_key_derived, sizeof(alice_public_key)) != 0) {
            ESP_LOGW(TAG, "Alice's stored public key does not match private key - using recomputed value");
            ESP_LOGI(TAG, "Alice's recomputed public key:");
            ESP_LOG_BUFFER_HEX(TAG, alice_public_key_derived, sizeof(alice_public_key_derived));
        }
        memcpy(alice_public_key, alice_public_key_derived, sizeof(alice_public_key));
    } else {
        ESP_LOGE(TAG, "Failed to derive Alice's public key from private key (code: %d)", result);
    }

    ESP_LOGI(TAG, "Step 2: Using Bob's predefined Curve25519 key pair...");
    ESP_LOGI(TAG, "Bob's private key (provided test vector):");
    ESP_LOG_BUFFER_HEX(TAG, bob_private_key_predefined, 32);
    ESP_LOGI(TAG, "Bob's public key (provided test vector):");
    ESP_LOG_BUFFER_HEX(TAG, bob_public_key_predefined, 32);

    // Step 3: Alice derives shared key using Bob's public key
    uint8_t alice_shared_key[32];
    ESP_LOGI(TAG, "Step 3: Alice deriving shared key...");
    result = lwm2m_crypto_curve25519_shared_key(bob_public_key_predefined, alice_private_key, alice_shared_key);
    if (result != 0) {
        ESP_LOGE(TAG, "Alice's key derivation failed with code: %d", result);
        return;
    }
    ESP_LOGI(TAG, "Alice's shared key:");
    ESP_LOG_BUFFER_HEX(TAG, alice_shared_key, sizeof(alice_shared_key));
    
    // Step 4: Bob derives shared key using Alice's public key
    uint8_t bob_shared_key[32];
    ESP_LOGI(TAG, "Step 4: Bob deriving shared key...");
    result = lwm2m_crypto_curve25519_shared_key(alice_public_key, bob_private_key_predefined, bob_shared_key);
    if (result != 0) {
        ESP_LOGE(TAG, "Bob's key derivation failed with code: %d", result);
        return;
    }
    ESP_LOGI(TAG, "Bob's shared key:");
    ESP_LOG_BUFFER_HEX(TAG, bob_shared_key, sizeof(bob_shared_key));
    
    // Step 5: Verify both parties derived the same key
    if (memcmp(alice_shared_key, bob_shared_key, 32) == 0) {
        ESP_LOGI(TAG, "✓ Curve25519 Key Exchange Successful - Both parties have same shared key!");
    } else {
        ESP_LOGE(TAG, "✗ Curve25519 Key Exchange Failed - Shared keys don't match!");
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
    result = lwm2m_crypto_encrypt_with_shared_key(
        alice_shared_key,
        (const uint8_t *)alice_message, message_len,
        (const uint8_t *)device_info, strlen(device_info),
        nonce,
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
    result = lwm2m_crypto_decrypt_with_shared_key(
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
    
    ESP_LOGI(TAG, "=== Curve25519 Crypto Test with Predefined Keys Complete ===");
    
#else
    ESP_LOGW(TAG, "Predefined key crypto test skipped - requires ESP-IDF platform");
#endif
}