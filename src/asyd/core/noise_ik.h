/*
 * Copyright (c) 2026 Vincent Ping (vincentping@gmail.com)
 * SPDX-License-Identifier: Apache-2.0
 */
/*
 * noise_ik.h — Noise Protocol IK Handshake for ASys
 *
 * Implements Noise_IK_25519_ChaChaPoly_BLAKE2b
 * Built on top of Monocypher (monocypher.c / monocypher.h)
 *
 * Usage:
 *   Server (asyd): noise_ik_init_server() → noise_ik_read_msg1() → noise_ik_write_msg2()
 *   Client (Agent): noise_ik_init_client() → noise_ik_write_msg1() → noise_ik_read_msg2()
 *
 * After handshake: use noise_ik_encrypt() / noise_ik_decrypt() for APDU frames.
 */

#ifndef NOISE_IK_H
#define NOISE_IK_H

#include <stdint.h>
#include <stddef.h>

/* ── Key / nonce sizes ─────────────────────────────────────── */
#define NOISE_KEY_SIZE      32   /* Curve25519 key size (bytes)      */
#define NOISE_MAC_SIZE      16   /* ChaCha20-Poly1305 MAC (bytes)    */
#define NOISE_HASH_SIZE     64   /* BLAKE2b output (bytes)           */

/* ── Handshake message sizes ───────────────────────────────── */
/*
 * MSG1 (Agent → asyd):
 *   ephemeral_pub(32) + encrypted_static_pub(32+16) + encrypted_payload(0+16)
 *   = 32 + 48 + 16 = 96 bytes
 */
#define NOISE_MSG1_SIZE     96

/*
 * MSG2 (asyd → Agent):
 *   ephemeral_pub(32) + encrypted_payload(0+16)
 *   = 32 + 16 = 48 bytes
 */
#define NOISE_MSG2_SIZE     48

/* ── Error codes ───────────────────────────────────────────── */
#define NOISE_OK            0
#define NOISE_ERR_AUTH     -1   /* MAC verification failed           */
#define NOISE_ERR_PARAM    -2   /* Bad parameter                     */
#define NOISE_ERR_STATE    -3   /* Wrong state for this operation    */

/* ── Handshake state ───────────────────────────────────────── */
typedef struct {
    /* Static keys */
    uint8_t s_priv[NOISE_KEY_SIZE];   /* Our static private key       */
    uint8_t s_pub [NOISE_KEY_SIZE];   /* Our static public key        */
    uint8_t rs_pub[NOISE_KEY_SIZE];   /* Remote static public key     */

    /* Ephemeral keys (generated per handshake) */
    uint8_t e_priv[NOISE_KEY_SIZE];   /* Our ephemeral private key    */
    uint8_t e_pub [NOISE_KEY_SIZE];   /* Our ephemeral public key     */
    uint8_t re_pub[NOISE_KEY_SIZE];   /* Remote ephemeral public key  */

    /* Handshake hash & chaining key (Noise symmetric state) */
    uint8_t h [NOISE_HASH_SIZE];      /* Handshake hash               */
    uint8_t ck[NOISE_HASH_SIZE];      /* Chaining key                 */

    /* Transport keys (available after handshake completes) */
    uint8_t send_key[NOISE_KEY_SIZE]; /* Key for sending APDU frames  */
    uint8_t recv_key[NOISE_KEY_SIZE]; /* Key for receiving APDU frames*/
    uint64_t send_nonce;              /* Monotonic nonce (send)       */
    uint64_t recv_nonce;              /* Monotonic nonce (recv)       */

    /* State flags */
    int      is_server;               /* 1 = asyd, 0 = Agent          */
    int      handshake_done;          /* 1 = transport keys ready     */
} NoiseIKState;

/* ── Key generation ────────────────────────────────────────── */

/*
 * Generate a Curve25519 static key pair.
 * priv_out: 32-byte private key (random)
 * pub_out:  32-byte public key
 */
void noise_ik_generate_keypair(uint8_t priv_out[NOISE_KEY_SIZE],
                                uint8_t pub_out [NOISE_KEY_SIZE]);

/* ── Server (asyd) API ─────────────────────────────────────── */

/*
 * Initialize server state.
 * s_priv: server static private key (32 bytes)
 * s_pub:  server static public key  (32 bytes)
 */
int noise_ik_init_server(NoiseIKState *st,
                          const uint8_t s_priv[NOISE_KEY_SIZE],
                          const uint8_t s_pub [NOISE_KEY_SIZE]);

/*
 * Process handshake message 1 from Agent.
 * msg1:     96-byte buffer received from Agent
 * agent_static_pub_out: recovered Agent static public key (for whitelist check)
 * Returns NOISE_OK or NOISE_ERR_AUTH if MAC fails.
 */
int noise_ik_read_msg1(NoiseIKState *st,
                        const uint8_t msg1[NOISE_MSG1_SIZE],
                        uint8_t agent_static_pub_out[NOISE_KEY_SIZE]);

/*
 * Write handshake message 2 to Agent.
 * msg2_out: 48-byte buffer to send to Agent
 * After this call, st->handshake_done == 1 and transport keys are ready.
 */
int noise_ik_write_msg2(NoiseIKState *st,
                         uint8_t msg2_out[NOISE_MSG2_SIZE]);

/* ── Client (Agent) API ────────────────────────────────────── */

/*
 * Initialize client state.
 * s_priv:  Agent static private key (32 bytes)
 * s_pub:   Agent static public key  (32 bytes)
 * rs_pub:  Server (asyd) static public key (32 bytes, obtained out-of-band)
 */
int noise_ik_init_client(NoiseIKState *st,
                          const uint8_t s_priv [NOISE_KEY_SIZE],
                          const uint8_t s_pub  [NOISE_KEY_SIZE],
                          const uint8_t rs_pub [NOISE_KEY_SIZE]);

/*
 * Write handshake message 1 to server.
 * msg1_out: 96-byte buffer to send to asyd
 */
int noise_ik_write_msg1(NoiseIKState *st,
                         uint8_t msg1_out[NOISE_MSG1_SIZE]);

/*
 * Process handshake message 2 from server.
 * msg2: 48-byte buffer received from asyd
 * After this call, st->handshake_done == 1 and transport keys are ready.
 */
int noise_ik_read_msg2(NoiseIKState *st,
                        const uint8_t msg2[NOISE_MSG2_SIZE]);

/* ── Transport (post-handshake) ────────────────────────────── */

/*
 * Encrypt an APDU frame for sending.
 * plaintext:    input buffer (Lc bytes)
 * plaintext_len: length of plaintext
 * ciphertext_out: output buffer (plaintext_len + NOISE_MAC_SIZE bytes)
 * Returns NOISE_OK or NOISE_ERR_STATE if handshake not complete.
 */
int noise_ik_encrypt(NoiseIKState *st,
                      const uint8_t *plaintext,  size_t plaintext_len,
                      uint8_t       *ciphertext_out);

/*
 * Decrypt a received APDU frame.
 * ciphertext:     input buffer (plaintext_len + NOISE_MAC_SIZE bytes)
 * ciphertext_len: total length including MAC
 * plaintext_out:  output buffer (ciphertext_len - NOISE_MAC_SIZE bytes)
 * Returns NOISE_OK or NOISE_ERR_AUTH if MAC fails.
 */
int noise_ik_decrypt(NoiseIKState *st,
                      const uint8_t *ciphertext,  size_t ciphertext_len,
                      uint8_t       *plaintext_out);

/* ── Utility ───────────────────────────────────────────────── */

/*
 * Securely wipe a NoiseIKState (zero all key material).
 * Call before freeing or reusing a state.
 */
void noise_ik_wipe(NoiseIKState *st);

#endif /* NOISE_IK_H */