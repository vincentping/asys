/*
 * Copyright (c) 2026 Vincent Ping (vincentping@gmail.com)
 * SPDX-License-Identifier: Apache-2.0
 */
/*
 * auth_verify.c — APDU Auth Tag verification (spec §2.2.3)
 */
#include "auth_verify.h"
#include "crypto_utils.h"
#include "monocypher.h"

#include <string.h>  /* memcpy */

int verify_auth_tag(const NoiseIKState *noise, const ApduFrame *frame,
                    const uint8_t epoch_id[4])
{
    /* Lc = frame->data_len = Seq(4B) + Payload(N)
     * Auth Tag NOT in Lc — extracted separately by parser into frame->auth_tag */
    if (frame->data_len < 4 || frame->auth_tag == NULL)
        return 0;

    /* Build HMAC input: Header(5B) || Epoch_ID(4B) || Seq(4B) || Payload */
    uint8_t header[5];
    header[0] = frame->cla;
    header[1] = frame->ins;
    header[2] = frame->p1;
    header[3] = frame->p2;
    /* data_len is the Lc byte as transmitted on the wire.
     * For standard frames Lc ≤ 255, so the cast is safe.
     * Extended frames use a 2-byte Lc (spec §3.2); if they ever carry
     * Signed payloads, this will need a different encoding — see TODO below. */
    header[4] = (uint8_t)frame->data_len;  /* Lc as transmitted */

    uint8_t msg[5 + 4 + 4 + 255]; /* header + epoch_id + seq + max standard payload */
    size_t  payload_len = frame->data_len - 4;

    /* For extended frames, payload could be larger; check fits in local buf.
     * For Phase 4, all Signed frames are standard (Lc <= 255). */
    /* TODO (Phase 6): support extended Signed frames (Lc > 255).
     * This is an implementation limit, NOT a protocol limit — the spec
     * allows extended frames with Sec≠00.  For Phase 4 all Signed
     * instructions (PROC_THROTTLE, SVC_RESTART) use standard frames.
     * When extended Signed frames are added, allocate msg on the heap or
     * pass in a caller-supplied scratch buffer sized to APDU_MAX_FRAME_SIZE. */
    if (payload_len > 255)
        return 0;

    memcpy(msg,      header,           5);           /* Header */
    memcpy(msg + 5,  epoch_id,         4);           /* Epoch_ID */
    memcpy(msg + 9,  frame->data,      4);           /* Seq */
    memcpy(msg + 13, frame->data + 4,  payload_len); /* Payload */
    size_t msg_len = 5 + 4 + 4 + payload_len;

    uint8_t digest[64];
    hmac_blake2b(digest, noise->recv_key, 32, msg, msg_len);

    /* Constant-time compare first 16 bytes */
    int ok = (crypto_verify16(digest, frame->auth_tag) == 0);

    crypto_wipe(digest, sizeof(digest));
    crypto_wipe(msg,    sizeof(msg));

    return ok;
}
