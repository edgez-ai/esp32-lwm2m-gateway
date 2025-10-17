/**
 * @file crypto_test_fixed.h
 * @brief Corrected Curve25519 cryptography test functions
 * 
 * This module provides the CORRECT implementation for Curve25519 key generation
 * that is compatible with Java's X25519 implementation and follows RFC 7748.
 */

#ifndef CRYPTO_TEST_FIXED_H
#define CRYPTO_TEST_FIXED_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Test the corrected Curve25519 implementation
 * 
 * This function demonstrates proper X25519 key generation that:
 * 1. Uses proper private key clamping as per RFC 7748
 * 2. Exports raw 32-byte public keys (X coordinate only)
 * 3. Should be compatible with Java's X25519 KeyAgreement
 */
void test_fixed_curve25519_crypto(void);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_TEST_FIXED_H */