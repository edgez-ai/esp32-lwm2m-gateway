#ifndef CRYPTO_TEST_H
#define CRYPTO_TEST_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Run Curve25519 cryptography test with real key generation
 * 
 * This function demonstrates:
 * 1. Curve25519 key pair generation for two parties (Alice and Bob)
 * 2. Shared secret derivation using Curve25519 ECDH
 * 3. Secure communication using ChaCha20-Poly1305 encryption
 */
void test_ecdh_crypto_with_keygen(void);

#ifdef __cplusplus
}
#endif

#endif // CRYPTO_TEST_H