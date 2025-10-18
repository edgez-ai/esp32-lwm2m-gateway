#ifndef CRYPTO_TEST_H
#define CRYPTO_TEST_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Run Curve25519 cryptography test using predefined key material
 * 
 * This function demonstrates:
 * 1. Loading Curve25519 key material for Alice from factory data
 * 2. Using predefined Curve25519 keys for Bob (static test vector)
 * 3. Shared secret derivation using Curve25519 ECDH
 * 4. Secure communication using ChaCha20-Poly1305 encryption
 */
void test_ecdh_crypto_with_keygen(void);

#ifdef __cplusplus
}
#endif

#endif // CRYPTO_TEST_H