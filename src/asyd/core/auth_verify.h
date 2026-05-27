/*
 * Copyright (c) 2026 Vincent Ping (vincentping@gmail.com)
 * SPDX-License-Identifier: Apache-2.0
 */
/*
 * auth_verify.h — APDU Auth Tag (HMAC-BLAKE2b) verification
 *
 * Implements spec §2.2.3 verify flow.
 * Called from handle_client() before dispatch() for all Signed frames.
 */
#ifndef AUTH_VERIFY_H
#define AUTH_VERIFY_H

#include "apdu_parser.h"
#include "noise_ik.h"

/*
 * Verify the Auth Tag of a Signed APDU frame.
 *
 * Auth_Tag = HMAC-BLAKE2b(recv_key, CLA||INS||P1||P2||Lc||Epoch_ID||Seq||Payload)[:16]
 *
 * epoch_id: 4-byte session identifier derived post-handshake via
 *           HMAC-BLAKE2b(recv_key, "asys-epoch-v1")[:4] — never transmitted.
 *
 * Frame layout for Signed frames (Auth Tag NOT counted in Lc, per parser):
 *   frame->data[0..3]          = Seq (4B BE)
 *   frame->data[4..data_len-1] = Payload
 *   frame->auth_tag[0..15]     = Received Auth Tag (after Le)
 *
 * Returns 1 if valid, 0 if invalid (caller must send 0x6982 and disconnect).
 * Uses crypto_verify16() — constant-time, no timing side channel.
 */
int verify_auth_tag(const NoiseIKState *noise, const ApduFrame *frame,
                    const uint8_t epoch_id[4]);

#endif /* AUTH_VERIFY_H */
