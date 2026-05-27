/*
 * Copyright (c) 2026 Vincent Ping (vincentping@gmail.com)
 * SPDX-License-Identifier: Apache-2.0
 */
/*
 * crypto_utils.h — Shared cryptographic helpers for ASys
 *
 * Provides hmac_blake2b(), used by noise_ik.c, tofu.c, and auth_verify.c.
 * Eliminates duplicate static implementations in each file.
 */
#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <stddef.h>
#include <stdint.h>

#define CRYPTO_UTILS_BLAKE2B_BLOCK 128
#define CRYPTO_UTILS_BLAKE2B_OUT   64

/*
 * HMAC-BLAKE2b: standard HMAC with BLAKE2b(64) as hash function.
 * Matches Python: cryptography.hazmat.primitives.hmac.HMAC(key, hashes.BLAKE2b(64))
 * Output: 64 bytes written to out[].
 */
void hmac_blake2b(uint8_t        out[CRYPTO_UTILS_BLAKE2B_OUT],
                  const uint8_t *key,  size_t key_len,
                  const uint8_t *data, size_t data_len);

#endif /* CRYPTO_UTILS_H */
