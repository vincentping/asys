/*
 * Copyright (c) 2026 Vincent Ping (vincentping@gmail.com)
 * SPDX-License-Identifier: Apache-2.0
 */
/*
 * apdu_parser.h — ASys APDU Frame Parser
 *
 * Zero-copy design: recv() writes directly into ApduParser.buf;
 * ApduFrame.data / .auth_tag are pointers into that same buffer.
 * No intermediate copies of payload bytes after the kernel recv.
 *
 * Static memory pool: APDU_POOL_SIZE parser slots pre-allocated at
 * compile time. No malloc anywhere in the parse path.
 *
 * Frame sync: apdu_parser_try_parse() is re-entrant — call it after
 * every recv(). Returns APDU_NEED_MORE until a complete frame arrives,
 * then APDU_FRAME_READY. Leftover bytes (pipelining) are preserved by
 * apdu_parser_consume() via a single memmove.
 *
 * Supported layouts (spec §3.1–3.2):
 *
 *   Standard (CLA.Ext=0):
 *     [CLA][INS][P1][P2][Lc(1B)][Data(Lc B)][Le(1B)]
 *     With Sec≠00: … [Le][Auth Tag(16B)]
 *
 *   Extended (CLA.Ext=1):
 *     [CLA][INS][P1][P2][0x00][Lc_h][Lc_l][Data][Le_h][Le_l]
 *     With Sec≠00: … [Le_h][Le_l][Auth Tag(16B)]
 *
 * Auth Tag is ALWAYS at the physical end of the frame, not counted in Lc
 * (spec §3.1.2).
 */

#ifndef APDU_PARSER_H
#define APDU_PARSER_H

#include <stdint.h>
#include <stddef.h>

/* ── Frame geometry ──────────────────────────────────────── */
#define APDU_STD_HDR_SIZE    5     /* CLA+INS+P1+P2+Lc              */
#define APDU_EXT_HDR_SIZE    7     /* CLA+INS+P1+P2+0x00+Lc_h+Lc_l */
#define APDU_STD_LE_SIZE     1
#define APDU_EXT_LE_SIZE     2
#define APDU_AUTH_TAG_SIZE   16    /* ChaCha20-Poly1305 MAC          */
#define APDU_MAX_DATA_LEN    65535 /* Extended frame maximum         */

/*
 * Maximum single frame: extended header + max data + extended Le + auth tag
 *   = 7 + 65535 + 2 + 16 = 65560 bytes
 */
#define APDU_MAX_FRAME_SIZE  \
    (APDU_EXT_HDR_SIZE + APDU_MAX_DATA_LEN + APDU_EXT_LE_SIZE + APDU_AUTH_TAG_SIZE)

/* ── CLA byte bit masks (spec §3.1.2) ───────────────────── */
#define APDU_CLA_VER_MASK    0xE0  /* bits 7-5: protocol version    */
#define APDU_CLA_M_BIT       0x10  /* bit  4  : More / chaining     */
#define APDU_CLA_SEC_MASK    0x0C  /* bits 3-2: security level      */
#define APDU_CLA_EXT_BIT     0x02  /* bit  1  : extended frame      */
#define APDU_CLA_RFU_BIT     0x01  /* bit  0  : reserved, must be 0 */

#define APDU_CLA_SEC_SHIFT   2     /* right-shift to get 0/1/2      */

/* Security levels */
#define APDU_SEC_PLAIN       0x00
#define APDU_SEC_SIGNED      0x01
#define APDU_SEC_ENC_SIGN    0x02

/* ── Return codes ────────────────────────────────────────── */
#define APDU_FRAME_READY     2     /* Complete frame available        */
#define APDU_NEED_MORE       1     /* Incomplete — keep reading       */
#define APDU_OK              0
#define APDU_ERR_VERSION    -1     /* CLA ver bits ≠ 000              */
#define APDU_ERR_RFU        -2     /* CLA bit 0 set                   */
#define APDU_ERR_EXT_LC     -3     /* Extended Lc placeholder ≠ 0x00  */
#define APDU_ERR_LENGTH     -4     /* Computed size would overflow buf */

/* ── Pool size ───────────────────────────────────────────── */
#define APDU_POOL_SIZE       8     /* Concurrent connection slots     */

/* ── Parsed frame (zero-copy view into ApduParser.buf) ───── */
/*
 * data and auth_tag are pointers INTO the owning ApduParser's buf.
 * They are valid only until apdu_parser_consume() is called.
 * If the handler needs to retain data across consume(), it must copy.
 */
typedef struct {
    /* Raw header bytes */
    uint8_t         cla;
    uint8_t         ins;
    uint8_t         p1;
    uint8_t         p2;

    /* CLA decoded sub-fields */
    uint8_t         ver;      /* always 0 (validated)              */
    int             m_bit;    /* 0 or 1                            */
    uint8_t         sec;      /* APDU_SEC_PLAIN / SIGNED / ENC_SIGN*/
    int             ext;      /* 0 = standard, 1 = extended        */

    /* Payload */
    uint16_t        data_len; /* 0–65535                           */
    const uint8_t  *data;     /* → parser buf + header_size        */

    /* Le */
    uint16_t        le;       /* unified: 0x0000 = fire-and-forget */

    /* Auth tag (NULL when sec == APDU_SEC_PLAIN) */
    const uint8_t  *auth_tag; /* → parser buf + header+data+le     */

    /* Total bytes this frame occupies in buf (for consume) */
    size_t          total_size;
} ApduFrame;

/* ── Parser state (one per connection, from static pool) ─── */
typedef struct {
    uint8_t  buf[APDU_MAX_FRAME_SIZE]; /* static receive buffer    */
    size_t   filled;                   /* valid bytes in buf       */
    int      in_use;                   /* pool: 1=acquired         */
} ApduParser;

/* ── Pool API ────────────────────────────────────────────── */

/*
 * Acquire a parser slot from the static pool.
 * Returns NULL if all APDU_POOL_SIZE slots are in use.
 * The slot is zeroed and ready for use.
 */
ApduParser *apdu_pool_acquire(void);

/*
 * Release a parser slot back to the pool.
 * Zeroes the buffer to prevent key material leakage.
 */
void apdu_pool_release(ApduParser *p);

/* ── Zero-copy recv helpers ──────────────────────────────── */

/*
 * Return a pointer into buf where the next recv() should write,
 * and the maximum number of bytes that may be written.
 *
 * Usage:
 *   size_t max;
 *   uint8_t *dst = apdu_parser_recv_ptr(p, &max);
 *   ssize_t n = recv(fd, dst, max, 0);
 *   if (n > 0) apdu_parser_recv_commit(p, (size_t)n);
 */
uint8_t *apdu_parser_recv_ptr(ApduParser *p, size_t *out_max);

/*
 * Advance the filled counter after a successful recv().
 */
void apdu_parser_recv_commit(ApduParser *p, size_t n_received);

/* ── Frame parsing ───────────────────────────────────────── */

/*
 * Attempt to parse a complete frame from p->buf[0..filled].
 *
 * Returns:
 *   APDU_FRAME_READY  — *out is populated; call apdu_parser_consume() when done
 *   APDU_NEED_MORE    — incomplete frame, call recv() + commit() and retry
 *   APDU_ERR_*        — malformed frame; caller should drop the connection
 *
 * Zero-copy guarantee: out->data and out->auth_tag point into p->buf.
 * Do NOT call apdu_parser_consume() before finishing with those pointers.
 */
int apdu_parser_try_parse(ApduParser *p, ApduFrame *out);

/*
 * Consume a parsed frame: shift any remaining bytes (next frame or
 * partial next frame) to the start of buf via memmove.
 *
 * Must be called with the same frame returned by apdu_parser_try_parse().
 * After this call, out->data and out->auth_tag are invalid.
 */
void apdu_parser_consume(ApduParser *p, const ApduFrame *frame);

/*
 * Reset parser state (e.g., after an error, before reuse).
 */
void apdu_parser_reset(ApduParser *p);

#endif /* APDU_PARSER_H */
