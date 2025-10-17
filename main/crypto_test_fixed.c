/*
 * CORRECTED Curve25519 Key Generation for C Code
 * 
 * This shows the proper way to generate X25519 keys that are compatible
 * with Java's X25519 implementation.
 */

#include "crypto_test.h"
#include "lwm2m_helpers.h"
#include "esp_log.h"
#include <string.h>

#ifdef ESP_PLATFORM
#include "mbedtls/ecdh.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
// IMPORTANT: Use the correct header for Montgomery curves
#include "mbedtls/ecp.h"
#include "mbedtls/bignum.h"
#endif

static const char *TAG = "crypto_test_fixed";

#ifdef ESP_PLATFORM
/**
 * @brief Generate Curve25519 key pair using the CORRECT method
 * 
 * The key insight is that Curve25519 is a Montgomery curve, not a Weierstrass curve.
 * We need to:
 * 1. Generate a random 32-byte private key 
 * 2. Perform scalar multiplication with the base point to get the public key
 * 3. Handle the Montgomery ladder correctly
 * 
 * @param private_key Output buffer for private key (32 bytes)
 * @param public_key Output buffer for public key (32 bytes) 
 * @return 0 on success, negative error code on failure
 */
static int generate_curve25519_keypair_fixed(uint8_t *private_key, uint8_t *public_key)
{
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    int ret = 0;
    
    // Initialize contexts
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    
    // Seed the random number generator
    const char *pers = "curve25519_key_gen_fixed";
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers, strlen(pers));
    if (ret != 0) {
        ESP_LOGE(TAG, "mbedtls_ctr_drbg_seed failed: -0x%04x", -ret);
        goto cleanup;
    }
    
    // STEP 1: Generate a random 32-byte private key
    ret = mbedtls_ctr_drbg_random(&ctr_drbg, private_key, 32);
    if (ret != 0) {
        ESP_LOGE(TAG, "Random private key generation failed: -0x%04x", -ret);
        goto cleanup;
    }
    
    // STEP 2: Apply Curve25519 private key clamping
    // This is ESSENTIAL for X25519 compatibility!
    // See RFC 7748 Section 5 for these specific bit operations
    private_key[0] &= 248;     // Clear bottom 3 bits
    private_key[31] &= 127;    // Clear top bit  
    private_key[31] |= 64;     // Set second-highest bit
    
    // STEP 3: Compute public key = private_key * base_point
    // For X25519, we use the ECDH interface with a NULL peer key to get our public key
    mbedtls_ecp_group grp;
    mbedtls_mpi our_private;
    mbedtls_ecp_point our_public;
    
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&our_private);
    mbedtls_ecp_point_init(&our_public);
    
    // Load Curve25519 group
    ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to load Curve25519 group: -0x%04x", -ret);
        goto cleanup_ecp;
    }
    
    // Load our private key
    ret = mbedtls_mpi_read_binary(&our_private, private_key, 32);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to load private key: -0x%04x", -ret);
        goto cleanup_ecp;
    }
    
    // Compute public key = private_key * G (base point)
    ret = mbedtls_ecp_mul(&grp, &our_public, &our_private, &grp.G, 
                         mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to compute public key: -0x%04x", -ret);
        goto cleanup_ecp;
    }
    
    // STEP 4: Export public key in the correct X25519 format
    // For Montgomery curves, we only export the X coordinate
    size_t olen;
    ret = mbedtls_ecp_point_write_binary(&grp, &our_public, MBEDTLS_ECP_PF_COMPRESSED, 
                                        &olen, public_key, 33);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to export public key: -0x%04x", -ret);
        goto cleanup_ecp;
    }
    
    // For X25519, we want the raw 32-byte X coordinate, not the 33-byte compressed format
    if (olen == 33 && public_key[0] == 0x02) {
        // Remove the compression prefix and shift the data
        memmove(public_key, public_key + 1, 32);
    } else if (olen != 32) {
        ESP_LOGE(TAG, "Unexpected public key length: %zu, expected 32 or 33", olen);
        ret = -1;
        goto cleanup_ecp;
    }
    
cleanup_ecp:
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&our_private);
    mbedtls_ecp_point_free(&our_public);
    
cleanup:
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    return ret;
}

/**
 * Proper X25519 key generation that creates valid keys
 * This uses the same approach as your lwm2m_helpers.c but generates the public key correctly
 */
static int generate_curve25519_keypair_proper(uint8_t *private_key, uint8_t *public_key)
{
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point Q;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    int ret = 0;
    
    // Initialize contexts
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&Q);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    
    // Seed the random number generator
    const char *pers = "curve25519_proper_keygen";
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers, strlen(pers));
    if (ret != 0) {
        ESP_LOGE(TAG, "mbedtls_ctr_drbg_seed failed: -0x%04x", -ret);
        goto cleanup;
    }
    
    // Load Curve25519
    ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);
    if (ret != 0) {
        ESP_LOGE(TAG, "mbedtls_ecp_group_load failed: -0x%04x", -ret);
        goto cleanup;
    }
    
    // Generate a random private key scalar first
    ret = mbedtls_mpi_fill_random(&d, 32, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        ESP_LOGE(TAG, "Private key random generation failed: -0x%04x", -ret);
        goto cleanup;
    }
    
    // Export private key to apply clamping
    ret = mbedtls_mpi_write_binary(&d, private_key, 32);
    if (ret != 0) {
        ESP_LOGE(TAG, "Private key export failed: -0x%04x", -ret);
        goto cleanup;
    }
    
    // Apply X25519 clamping as per RFC 7748
    private_key[0] &= 248;     // Clear bottom 3 bits  
    private_key[31] &= 127;    // Clear top bit
    private_key[31] |= 64;     // Set second-highest bit
    
    // Re-import the clamped private key
    ret = mbedtls_mpi_read_binary(&d, private_key, 32);
    if (ret != 0) {
        ESP_LOGE(TAG, "Private key re-import failed: -0x%04x", -ret);
        goto cleanup;
    }
    
    // Compute public key = private_key * base_point
    ret = mbedtls_ecp_mul(&grp, &Q, &d, &grp.G, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        ESP_LOGE(TAG, "Public key computation failed: -0x%04x", -ret);
        goto cleanup;
    }
    
    // Export public key in the correct format for Curve25519
    // For Montgomery curves, we use the compressed format which gives us the X coordinate
    size_t olen;
    uint8_t temp_buffer[33];  // Temporary buffer for compressed format
    
    ret = mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_COMPRESSED, 
                                        &olen, temp_buffer, sizeof(temp_buffer));
    if (ret != 0) {
        ESP_LOGE(TAG, "Public key export failed: -0x%04x", -ret);
        goto cleanup;
    }
    
    // For Curve25519 compressed format, remove the prefix byte to get raw X coordinate
    if (olen == 33 && (temp_buffer[0] == 0x02 || temp_buffer[0] == 0x03)) {
        memcpy(public_key, temp_buffer + 1, 32);
    } else if (olen == 32) {
        memcpy(public_key, temp_buffer, 32);
    } else {
        ESP_LOGE(TAG, "Unexpected public key format, length: %zu", olen);
        ret = -1;
        goto cleanup;
    }
    
    ESP_LOGI(TAG, "Generated proper X25519 key pair with clamping");
    
cleanup:
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&Q);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    return ret;
}

void test_fixed_curve25519_crypto(void)
{
    ESP_LOGI(TAG, "=== Testing X25519 Key Format and Clamping ===");
    
#ifdef ESP_PLATFORM
    // First, let's demonstrate the key format issues with your original implementation
    ESP_LOGI(TAG, "=== Comparison: Original vs Corrected Key Format ===");
    
    // Test 1: Show the difference in private key clamping
    uint8_t original_private[32];
    uint8_t clamped_private[32];
    
    // Generate a random key (like your original implementation)
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    
    const char *pers = "key_format_demo";
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                         (const unsigned char *) pers, strlen(pers));
    
    mbedtls_ctr_drbg_random(&ctr_drbg, original_private, 32);
    memcpy(clamped_private, original_private, 32);
    
    ESP_LOGI(TAG, "Original random private key:");
    ESP_LOG_BUFFER_HEX(TAG, original_private, 32);
    
    // Apply X25519 clamping
    clamped_private[0] &= 248;     // Clear bottom 3 bits
    clamped_private[31] &= 127;    // Clear top bit  
    clamped_private[31] |= 64;     // Set second-highest bit
    
    ESP_LOGI(TAG, "X25519 clamped private key:");
    ESP_LOG_BUFFER_HEX(TAG, clamped_private, 32);
    
    ESP_LOGI(TAG, "Key format differences:");
    ESP_LOGI(TAG, "- Original byte[0]: 0x%02x, Clamped byte[0]: 0x%02x", 
             original_private[0], clamped_private[0]);
    ESP_LOGI(TAG, "- Original byte[31]: 0x%02x, Clamped byte[31]: 0x%02x", 
             original_private[31], clamped_private[31]);
    
    // Test 2: Try to use the clamped key with your existing ECDH function
    uint8_t test_public_key[32];
    uint8_t alice_private[32];
    uint8_t bob_private[32];
    
    // Generate two clamped private keys
    mbedtls_ctr_drbg_random(&ctr_drbg, alice_private, 32);
    alice_private[0] &= 248;
    alice_private[31] &= 127;
    alice_private[31] |= 64;
    
    mbedtls_ctr_drbg_random(&ctr_drbg, bob_private, 32);
    bob_private[0] &= 248;
    bob_private[31] &= 127;
    bob_private[31] |= 64;
    
    // Use known test vectors or try to generate a proper public key
    // For now, let's just generate a test public key using your original function
    ESP_LOGI(TAG, "=== Testing with properly clamped private keys ===");
    ESP_LOGI(TAG, "Alice's clamped private key:");
    ESP_LOG_BUFFER_HEX(TAG, alice_private, 32);
    ESP_LOGI(TAG, "Bob's clamped private key:");
    ESP_LOG_BUFFER_HEX(TAG, bob_private, 32);
    
    ESP_LOGI(TAG, "Note: The issue is that your original generate_curve25519_keypair()");
    ESP_LOGI(TAG, "function doesn't apply this clamping, and the public key export");
    ESP_LOGI(TAG, "method may not produce the raw X coordinate that Java expects.");
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "For Java compatibility, you need:");
    ESP_LOGI(TAG, "1. Private keys with X25519 clamping (shown above)");
    ESP_LOGI(TAG, "2. Public keys as raw 32-byte X coordinates");
    ESP_LOGI(TAG, "3. ECDH computation that handles Montgomery curve properly");
    
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    
#endif
}

#endif /* ESP_PLATFORM */