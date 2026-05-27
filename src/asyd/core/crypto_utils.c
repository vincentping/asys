/*
 * Copyright (c) 2026 Vincent Ping (vincentping@gmail.com)
 * SPDX-License-Identifier: Apache-2.0
 */
/*
 * crypto_utils.c — Shared cryptographic helpers for ASys
 *
 * HMAC-BLAKE2b implementation shared by noise_ik.c, tofu.c, and auth_verify.c.
 * BLAKE2b block size is 128 bytes (vs SHA-2's 64).
 */

#include "crypto_utils.h"
#include "monocypher.h"

#include <string.h>

void hmac_blake2b(uint8_t        out[CRYPTO_UTILS_BLAKE2B_OUT],
                  const uint8_t *key,  size_t key_len,
                  const uint8_t *data, size_t data_len)
{
    /* If key is longer than block size, hash it first */
    uint8_t k_padded[CRYPTO_UTILS_BLAKE2B_BLOCK];
    memset(k_padded, 0, sizeof(k_padded));
    if (key_len > CRYPTO_UTILS_BLAKE2B_BLOCK) {
        crypto_blake2b(k_padded, CRYPTO_UTILS_BLAKE2B_OUT, key, key_len);
    } else {
        memcpy(k_padded, key, key_len);
    }

    uint8_t k_ipad[CRYPTO_UTILS_BLAKE2B_BLOCK];
    uint8_t k_opad[CRYPTO_UTILS_BLAKE2B_BLOCK];
    for (int i = 0; i < CRYPTO_UTILS_BLAKE2B_BLOCK; i++) {
        k_ipad[i] = k_padded[i] ^ 0x36;
        k_opad[i] = k_padded[i] ^ 0x5C;
    }

    /* inner = BLAKE2b(k_ipad || data) */
    uint8_t inner[CRYPTO_UTILS_BLAKE2B_OUT];
    crypto_blake2b_ctx ctx;
    crypto_blake2b_init(&ctx, CRYPTO_UTILS_BLAKE2B_OUT);
    crypto_blake2b_update(&ctx, k_ipad, CRYPTO_UTILS_BLAKE2B_BLOCK);
    if (data_len > 0)
        crypto_blake2b_update(&ctx, data, data_len);
    crypto_blake2b_final(&ctx, inner);

    /* out = BLAKE2b(k_opad || inner) */
    crypto_blake2b_init(&ctx, CRYPTO_UTILS_BLAKE2B_OUT);
    crypto_blake2b_update(&ctx, k_opad, CRYPTO_UTILS_BLAKE2B_BLOCK);
    crypto_blake2b_update(&ctx, inner, CRYPTO_UTILS_BLAKE2B_OUT);
    crypto_blake2b_final(&ctx, out);

    crypto_wipe(k_padded, sizeof(k_padded));
    crypto_wipe(k_ipad,   sizeof(k_ipad));
    crypto_wipe(k_opad,   sizeof(k_opad));
    crypto_wipe(inner,    sizeof(inner));
}
