/*
 * Copyright (c) 2026 Vincent Ping (vincentping@gmail.com)
 * SPDX-License-Identifier: Apache-2.0
 */
/*
 * noise_ik.c — Noise Protocol IK Handshake for ASys
 *
 * Implements Noise_IK_25519_ChaChaPoly_BLAKE2b
 * Spec: https://noiseprotocol.org/noise.html
 *
 * Built on Monocypher 4.x primitives:
 *   - crypto_x25519()             Curve25519 DH
 *   - crypto_aead_lock/unlock()   ChaCha20-Poly1305
 *   - crypto_blake2b()            BLAKE2b
 *   - crypto_wipe()               Secure zero
 */

#include "noise_ik.h"
#include "crypto_utils.h"
#include "monocypher.h"
#include <string.h>
#include <stdio.h>

/*
 * MixHash: h = BLAKE2b(h || data)
 * Updates the handshake hash in-place.
 */
static void mix_hash(uint8_t h[NOISE_HASH_SIZE],
                     const uint8_t *data, size_t data_len)
{
    crypto_blake2b_ctx ctx;
    crypto_blake2b_init(&ctx, NOISE_HASH_SIZE);
    crypto_blake2b_update(&ctx, h, NOISE_HASH_SIZE);
    crypto_blake2b_update(&ctx, data, data_len);
    crypto_blake2b_final(&ctx, h);
}

/*
 * MixKey: Noise HKDF using HMAC-BLAKE2b (matching noiseprotocol library).
 * Noise spec: (ck, k) = HKDF(ck, dh_output, num_outputs=2)
 *   temp   = HMAC(ck,   dh_output)
 *   new_ck = HMAC(temp, byte(0x01))
 *   k      = HMAC(temp, new_ck || byte(0x02))  [first 32 bytes]
 */
static void mix_key(uint8_t ck[NOISE_HASH_SIZE],
                    uint8_t k [NOISE_KEY_SIZE],
                    const uint8_t *dh_output, size_t dh_len)
{
    uint8_t temp[NOISE_HASH_SIZE];
    hmac_blake2b(temp, ck, NOISE_HASH_SIZE, dh_output, dh_len);

    uint8_t one = 0x01;
    hmac_blake2b(ck, temp, NOISE_HASH_SIZE, &one, 1);

    uint8_t data2[NOISE_HASH_SIZE + 1];
    memcpy(data2, ck, NOISE_HASH_SIZE);
    data2[NOISE_HASH_SIZE] = 0x02;
    uint8_t k_full[NOISE_HASH_SIZE];
    hmac_blake2b(k_full, temp, NOISE_HASH_SIZE, data2, NOISE_HASH_SIZE + 1);
    memcpy(k, k_full, NOISE_KEY_SIZE);

    crypto_wipe(temp,   sizeof(temp));
    crypto_wipe(data2,  sizeof(data2));
    crypto_wipe(k_full, sizeof(k_full));
}

/*
 * EncryptAndHash: encrypt plaintext with current k, mix ciphertext into h.
 * Uses IETF ChaCha20-Poly1305 (12-byte nonce) to match noiseprotocol library.
 * Nonce is always 0 during handshake (each key is used exactly once).
 */
static void encrypt_and_hash(uint8_t h[NOISE_HASH_SIZE],
                              const uint8_t k[NOISE_KEY_SIZE],
                              const uint8_t *plaintext,  size_t pt_len,
                              uint8_t       *ciphertext_out)
{
    /* Noise ChaChaPoly nonce: 4 zero bytes + 8-byte LE counter (counter=0) */
    uint8_t nonce12[12] = {0};
    uint8_t *mac = ciphertext_out + pt_len;

    crypto_aead_ctx ctx;
    crypto_aead_init_ietf(&ctx, k, nonce12);
    crypto_aead_write(&ctx, ciphertext_out, mac,
                      h, NOISE_HASH_SIZE,   /* AD = current h */
                      plaintext, pt_len);
    crypto_wipe(&ctx, sizeof(ctx));

    /* MixHash(ciphertext || mac) */
    mix_hash(h, ciphertext_out, pt_len + NOISE_MAC_SIZE);
}

/*
 * DecryptAndHash: decrypt ciphertext, verify MAC, mix ciphertext into h.
 * Uses IETF ChaCha20-Poly1305 (12-byte nonce) to match noiseprotocol library.
 * Returns 0 on success, NOISE_ERR_AUTH on MAC failure.
 */
static int decrypt_and_hash(uint8_t h[NOISE_HASH_SIZE],
                              const uint8_t k[NOISE_KEY_SIZE],
                              const uint8_t *ciphertext, size_t ct_len,
                              uint8_t       *plaintext_out)
{
    if (ct_len < NOISE_MAC_SIZE) return NOISE_ERR_AUTH;
    size_t pt_len = ct_len - NOISE_MAC_SIZE;

    /* Noise ChaChaPoly nonce: 4 zero bytes + 8-byte LE counter (counter=0) */
    uint8_t nonce12[12] = {0};
    const uint8_t *mac = ciphertext + pt_len;

    /* Save h before update (AD for verification) */
    uint8_t h_before[NOISE_HASH_SIZE];
    memcpy(h_before, h, NOISE_HASH_SIZE);

    /* MixHash(ciphertext || mac) — update h first */
    mix_hash(h, ciphertext, ct_len);

    crypto_aead_ctx ctx;
    crypto_aead_init_ietf(&ctx, k, nonce12);
    int rc = crypto_aead_read(&ctx, plaintext_out, mac,
                               h_before, NOISE_HASH_SIZE,
                               ciphertext, pt_len);
    crypto_wipe(&ctx, sizeof(ctx));
    crypto_wipe(h_before, sizeof(h_before));
    return (rc == 0) ? NOISE_OK : NOISE_ERR_AUTH;
}

/*
 * Split: derive final transport keys from ck.
 * Noise spec: (k1, k2) = HKDF(ck, empty, num_outputs=2)
 *   temp = HMAC(ck,   b'')
 *   k1   = HMAC(temp, byte(0x01))               [first 32 bytes]
 *   k2   = HMAC(temp, k1 || byte(0x02))         [first 32 bytes]
 */
static void split(const uint8_t ck[NOISE_HASH_SIZE],
                  uint8_t k1[NOISE_KEY_SIZE],
                  uint8_t k2[NOISE_KEY_SIZE])
{
    /* HMAC with empty data */
    uint8_t temp[NOISE_HASH_SIZE];
    hmac_blake2b(temp, ck, NOISE_HASH_SIZE, NULL, 0);

    uint8_t one = 0x01;
    uint8_t k1_full[NOISE_HASH_SIZE];
    hmac_blake2b(k1_full, temp, NOISE_HASH_SIZE, &one, 1);
    memcpy(k1, k1_full, NOISE_KEY_SIZE);

    uint8_t data2[NOISE_HASH_SIZE + 1];
    memcpy(data2, k1_full, NOISE_HASH_SIZE);
    data2[NOISE_HASH_SIZE] = 0x02;
    uint8_t k2_full[NOISE_HASH_SIZE];
    hmac_blake2b(k2_full, temp, NOISE_HASH_SIZE, data2, NOISE_HASH_SIZE + 1);
    memcpy(k2, k2_full, NOISE_KEY_SIZE);

    crypto_wipe(temp,    sizeof(temp));
    crypto_wipe(data2,   sizeof(data2));
    crypto_wipe(k1_full, sizeof(k1_full));
    crypto_wipe(k2_full, sizeof(k2_full));
}

/*
 * Initialize symmetric state.
 * protocol_name: "Noise_IK_25519_ChaChaPoly_BLAKE2b"
 */
static void init_symmetric(uint8_t h[NOISE_HASH_SIZE],
                             uint8_t ck[NOISE_HASH_SIZE])
{
    /* protocol name as bytes */
    static const char *proto = "Noise_IK_25519_ChaChaPoly_BLAKE2b";
    size_t proto_len = 33; /* strlen of above */

    /* h = BLAKE2b(protocol_name) if len > HASH_SIZE, else pad to HASH_SIZE */
    if (proto_len <= NOISE_HASH_SIZE) {
        memset(h, 0, NOISE_HASH_SIZE);
        memcpy(h, proto, proto_len);
    } else {
        crypto_blake2b((uint8_t*)h, NOISE_HASH_SIZE,
                       (const uint8_t*)proto, proto_len);
    }
    /* ck = h */
    memcpy(ck, h, NOISE_HASH_SIZE);
}

/* ── Key generation ────────────────────────────────────────── */

void noise_ik_generate_keypair(uint8_t priv_out[NOISE_KEY_SIZE],
                                uint8_t pub_out [NOISE_KEY_SIZE])
{
    /* In production: fill priv_out with 32 cryptographically random bytes */
    /* Here we use /dev/urandom — caller may also supply random bytes       */
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        (void)fread(priv_out, 1, NOISE_KEY_SIZE, f);
        fclose(f);
    }
    /* Curve25519 key clamping */
    priv_out[0]  &= 248;
    priv_out[31] &= 127;
    priv_out[31] |= 64;
    /* Derive public key */
    crypto_x25519_public_key(pub_out, priv_out);
}

/* ── Server (asyd) ─────────────────────────────────────────── */

int noise_ik_init_server(NoiseIKState *st,
                          const uint8_t s_priv[NOISE_KEY_SIZE],
                          const uint8_t s_pub [NOISE_KEY_SIZE])
{
    if (!st || !s_priv || !s_pub) return NOISE_ERR_PARAM;
    memset(st, 0, sizeof(*st));
    memcpy(st->s_priv, s_priv, NOISE_KEY_SIZE);
    memcpy(st->s_pub,  s_pub,  NOISE_KEY_SIZE);
    st->is_server = 1;

    init_symmetric(st->h, st->ck);
    /* MixHash(empty prologue) — matches noiseprotocol library behaviour:
     * mix_hash(b'') is always called, even for zero-length prologue. */
    mix_hash(st->h, (const uint8_t *)"", 0);
    /* MixHash(server static public key) — IK pre-message "<- s" */
    mix_hash(st->h, st->s_pub, NOISE_KEY_SIZE);
    return NOISE_OK;
}

int noise_ik_read_msg1(NoiseIKState *st,
                        const uint8_t msg1[NOISE_MSG1_SIZE],
                        uint8_t agent_static_pub_out[NOISE_KEY_SIZE])
{
    if (!st || !msg1) return NOISE_ERR_PARAM;
    if (!st->is_server) return NOISE_ERR_STATE;

    uint8_t k[NOISE_KEY_SIZE] = {0};
    uint8_t dh[NOISE_KEY_SIZE];

    /* ── Parse msg1: re(32) | enc_s(48) | enc_payload(16) ── */
    const uint8_t *re     = msg1;           /* remote ephemeral pub  */
    const uint8_t *enc_s  = msg1 + 32;      /* encrypted static pub  */
    const uint8_t *enc_p  = msg1 + 32 + 48; /* encrypted payload(empty+MAC) */

    /* 1. MixHash(re) */
    memcpy(st->re_pub, re, NOISE_KEY_SIZE);
    mix_hash(st->h, re, NOISE_KEY_SIZE);

    /* 2. DH(s_priv, re) → MixKey */
    crypto_x25519(dh, st->s_priv, st->re_pub);
    mix_key(st->ck, k, dh, NOISE_KEY_SIZE);
    crypto_wipe(dh, sizeof(dh));

    /* 3. DecryptAndHash(enc_s) → agent static pub */
    uint8_t agent_s[NOISE_KEY_SIZE];
    int rc = decrypt_and_hash(st->h, k, enc_s, 32 + NOISE_MAC_SIZE, agent_s);
    crypto_wipe(k, sizeof(k));
    if (rc != NOISE_OK) return NOISE_ERR_AUTH;
    memcpy(st->rs_pub, agent_s, NOISE_KEY_SIZE);
    if (agent_static_pub_out)
        memcpy(agent_static_pub_out, agent_s, NOISE_KEY_SIZE);

    /* 4. DH(s_priv, agent_s) → MixKey */
    crypto_x25519(dh, st->s_priv, st->rs_pub);
    mix_key(st->ck, k, dh, NOISE_KEY_SIZE);
    crypto_wipe(dh, sizeof(dh));

    /* 5. DecryptAndHash(enc_payload) — payload is empty, just verify MAC */
    uint8_t payload[1];
    rc = decrypt_and_hash(st->h, k, enc_p, NOISE_MAC_SIZE, payload);
    crypto_wipe(k, sizeof(k));
    return rc;
}

int noise_ik_write_msg2(NoiseIKState *st,
                         uint8_t msg2_out[NOISE_MSG2_SIZE])
{
    if (!st || !msg2_out) return NOISE_ERR_PARAM;
    if (!st->is_server) return NOISE_ERR_STATE;

    uint8_t k[NOISE_KEY_SIZE] = {0};
    uint8_t dh[NOISE_KEY_SIZE];

    /* Generate server ephemeral keypair */
    noise_ik_generate_keypair(st->e_priv, st->e_pub);

    /* 1. MixHash(e_pub), write e_pub */
    mix_hash(st->h, st->e_pub, NOISE_KEY_SIZE);
    memcpy(msg2_out, st->e_pub, NOISE_KEY_SIZE);

    /* 2. DH(e_priv, re) → MixKey */
    crypto_x25519(dh, st->e_priv, st->re_pub);
    mix_key(st->ck, k, dh, NOISE_KEY_SIZE);
    crypto_wipe(dh, sizeof(dh));

    /* 3. se: DH(e_priv, rs_pub) → MixKey
     * Noise IK table: responder processes "se" as DH(resp_e, init_s).
     * rs_pub here is the initiator's (client's) static public key, extracted
     * from msg1 and stored in st->rs_pub by noise_ik_read_msg1(). */
    crypto_x25519(dh, st->e_priv, st->rs_pub);
    mix_key(st->ck, k, dh, NOISE_KEY_SIZE);
    crypto_wipe(dh, sizeof(dh));

    /* 4. EncryptAndHash(empty payload) → write MAC only */
    encrypt_and_hash(st->h, k, NULL, 0, msg2_out + NOISE_KEY_SIZE);
    crypto_wipe(k, sizeof(k));

    /* 5. Split → transport keys
     * Noise spec: split() returns (c1, c2) where the INITIATOR encrypts with
     * c1 and decrypts with c2; the RESPONDER (us) encrypts with c2 and
     * decrypts with c1.  So for the server: recv=output1, send=output2. */
    split(st->ck, st->recv_key, st->send_key);
    st->send_nonce = 0;
    st->recv_nonce = 0;
    st->handshake_done = 1;

    return NOISE_OK;
}

/* ── Client (Agent) ────────────────────────────────────────── */

int noise_ik_init_client(NoiseIKState *st,
                          const uint8_t s_priv [NOISE_KEY_SIZE],
                          const uint8_t s_pub  [NOISE_KEY_SIZE],
                          const uint8_t rs_pub [NOISE_KEY_SIZE])
{
    if (!st || !s_priv || !s_pub || !rs_pub) return NOISE_ERR_PARAM;
    memset(st, 0, sizeof(*st));
    memcpy(st->s_priv,  s_priv,  NOISE_KEY_SIZE);
    memcpy(st->s_pub,   s_pub,   NOISE_KEY_SIZE);
    memcpy(st->rs_pub,  rs_pub,  NOISE_KEY_SIZE);
    st->is_server = 0;

    init_symmetric(st->h, st->ck);
    /* MixHash(empty prologue) — matches noiseprotocol library behaviour */
    mix_hash(st->h, (const uint8_t *)"", 0);
    /* MixHash(server static public key) — IK pre-message "<- s" */
    mix_hash(st->h, rs_pub, NOISE_KEY_SIZE);
    return NOISE_OK;
}

int noise_ik_write_msg1(NoiseIKState *st,
                         uint8_t msg1_out[NOISE_MSG1_SIZE])
{
    if (!st || !msg1_out) return NOISE_ERR_PARAM;
    if (st->is_server) return NOISE_ERR_STATE;

    uint8_t k[NOISE_KEY_SIZE] = {0};
    uint8_t dh[NOISE_KEY_SIZE];

    /* Generate client ephemeral keypair */
    noise_ik_generate_keypair(st->e_priv, st->e_pub);

    /* 1. MixHash(e_pub), write e_pub */
    mix_hash(st->h, st->e_pub, NOISE_KEY_SIZE);
    memcpy(msg1_out, st->e_pub, NOISE_KEY_SIZE);

    /* 2. DH(e_priv, rs_pub) → MixKey */
    crypto_x25519(dh, st->e_priv, st->rs_pub);
    mix_key(st->ck, k, dh, NOISE_KEY_SIZE);
    crypto_wipe(dh, sizeof(dh));

    /* 3. EncryptAndHash(s_pub) → enc_s */
    encrypt_and_hash(st->h, k,
                     st->s_pub, NOISE_KEY_SIZE,
                     msg1_out + NOISE_KEY_SIZE);
    crypto_wipe(k, sizeof(k));

    /* 4. DH(s_priv, rs_pub) → MixKey */
    crypto_x25519(dh, st->s_priv, st->rs_pub);
    mix_key(st->ck, k, dh, NOISE_KEY_SIZE);
    crypto_wipe(dh, sizeof(dh));

    /* 5. EncryptAndHash(empty payload) → MAC only */
    encrypt_and_hash(st->h, k, NULL, 0,
                     msg1_out + NOISE_KEY_SIZE + NOISE_KEY_SIZE + NOISE_MAC_SIZE);
    crypto_wipe(k, sizeof(k));

    return NOISE_OK;
}

int noise_ik_read_msg2(NoiseIKState *st,
                        const uint8_t msg2[NOISE_MSG2_SIZE])
{
    if (!st || !msg2) return NOISE_ERR_PARAM;
    if (st->is_server) return NOISE_ERR_STATE;

    uint8_t k[NOISE_KEY_SIZE] = {0};
    uint8_t dh[NOISE_KEY_SIZE];

    /* ── Parse msg2: re(32) | enc_payload(16) ── */
    const uint8_t *re    = msg2;
    const uint8_t *enc_p = msg2 + NOISE_KEY_SIZE;

    /* 1. MixHash(re) */
    memcpy(st->re_pub, re, NOISE_KEY_SIZE);
    mix_hash(st->h, re, NOISE_KEY_SIZE);

    /* 2. DH(e_priv, re) → MixKey */
    crypto_x25519(dh, st->e_priv, st->re_pub);
    mix_key(st->ck, k, dh, NOISE_KEY_SIZE);
    crypto_wipe(dh, sizeof(dh));

    /* 3. se: DH(s_priv, re_pub) → MixKey
     * Noise IK table: initiator processes "se" as DH(init_s, resp_e).
     * re_pub here is the responder's (server's) ephemeral public key from msg2. */
    crypto_x25519(dh, st->s_priv, st->re_pub);
    mix_key(st->ck, k, dh, NOISE_KEY_SIZE);
    crypto_wipe(dh, sizeof(dh));

    /* 4. DecryptAndHash(enc_payload) — verify MAC */
    uint8_t payload[1];
    int rc = decrypt_and_hash(st->h, k, enc_p, NOISE_MAC_SIZE, payload);
    crypto_wipe(k, sizeof(k));
    if (rc != NOISE_OK) return NOISE_ERR_AUTH;

    /* 5. Split → transport keys
     * Noise spec: the INITIATOR (us) encrypts with c1=output1 and decrypts
     * with c2=output2.  So for the client: send=output1, recv=output2. */
    split(st->ck, st->send_key, st->recv_key);
    st->send_nonce = 0;
    st->recv_nonce = 0;
    st->handshake_done = 1;

    return NOISE_OK;
}

/* ── Transport ─────────────────────────────────────────────── */

int noise_ik_encrypt(NoiseIKState *st,
                      const uint8_t *plaintext,  size_t plaintext_len,
                      uint8_t       *ciphertext_out)
{
    if (!st || !ciphertext_out) return NOISE_ERR_PARAM;
    if (!st->handshake_done)    return NOISE_ERR_STATE;

    /* Noise ChaChaPoly nonce: 4 zero bytes + 8-byte LE counter */
    uint8_t nonce12[12] = {0};
    uint64_t n = st->send_nonce;
    for (int i = 0; i < 8; i++) nonce12[4 + i] = (uint8_t)(n >> (8 * i));

    uint8_t *mac = ciphertext_out + plaintext_len;
    crypto_aead_ctx ctx;
    crypto_aead_init_ietf(&ctx, st->send_key, nonce12);
    crypto_aead_write(&ctx, ciphertext_out, mac,
                      NULL, 0,   /* no additional data for transport */
                      plaintext, plaintext_len);
    crypto_wipe(&ctx, sizeof(ctx));
    st->send_nonce++;
    return NOISE_OK;
}

int noise_ik_decrypt(NoiseIKState *st,
                      const uint8_t *ciphertext,  size_t ciphertext_len,
                      uint8_t       *plaintext_out)
{
    if (!st || !ciphertext || !plaintext_out) return NOISE_ERR_PARAM;
    if (!st->handshake_done)                  return NOISE_ERR_STATE;
    if (ciphertext_len < NOISE_MAC_SIZE)       return NOISE_ERR_AUTH;

    size_t pt_len = ciphertext_len - NOISE_MAC_SIZE;
    const uint8_t *mac = ciphertext + pt_len;

    /* Noise ChaChaPoly nonce: 4 zero bytes + 8-byte LE counter */
    uint8_t nonce12[12] = {0};
    uint64_t n = st->recv_nonce;
    for (int i = 0; i < 8; i++) nonce12[4 + i] = (uint8_t)(n >> (8 * i));

    crypto_aead_ctx ctx;
    crypto_aead_init_ietf(&ctx, st->recv_key, nonce12);
    int rc = crypto_aead_read(&ctx, plaintext_out, mac,
                               NULL, 0,
                               ciphertext, pt_len);
    crypto_wipe(&ctx, sizeof(ctx));
    if (rc != 0) return NOISE_ERR_AUTH;
    st->recv_nonce++;
    return NOISE_OK;
}

/* ── Wipe ──────────────────────────────────────────────────── */

void noise_ik_wipe(NoiseIKState *st)
{
    if (st) crypto_wipe(st, sizeof(*st));
}