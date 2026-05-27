/*
 * Copyright (c) 2026 Vincent Ping (vincentping@gmail.com)
 * SPDX-License-Identifier: Apache-2.0
 */
/*
 * apdu_parser.c — ASys APDU Frame Parser Implementation
 */

#include "apdu_parser.h"

#include <string.h>   /* memset, memmove */

/* ── Static pool ─────────────────────────────────────────── */

static ApduParser g_pool[APDU_POOL_SIZE];

ApduParser *apdu_pool_acquire(void)
{
    for (int i = 0; i < APDU_POOL_SIZE; i++) {
        if (!g_pool[i].in_use) {
            memset(&g_pool[i], 0, sizeof(g_pool[i]));
            g_pool[i].in_use = 1;
            return &g_pool[i];
        }
    }
    return NULL; /* pool exhausted */
}

void apdu_pool_release(ApduParser *p)
{
    if (!p) return;
    memset(p, 0, sizeof(*p)); /* zero key material */
    /* in_use = 0 is set by memset above */
}

/* ── Zero-copy recv helpers ──────────────────────────────── */

uint8_t *apdu_parser_recv_ptr(ApduParser *p, size_t *out_max)
{
    *out_max = APDU_MAX_FRAME_SIZE - p->filled;
    return p->buf + p->filled;
}

void apdu_parser_recv_commit(ApduParser *p, size_t n_received)
{
    p->filled += n_received;
}

/* ── Frame parsing ───────────────────────────────────────── */

/*
 * Internal: minimum bytes needed to determine if the frame is
 * standard or extended (just the CLA byte).
 */
#define MIN_BYTES_FOR_CLA  1

int apdu_parser_try_parse(ApduParser *p, ApduFrame *out)
{
    if (!p || !out) return APDU_ERR_LENGTH;

    /* Need at least CLA to decide frame type */
    if (p->filled < MIN_BYTES_FOR_CLA)
        return APDU_NEED_MORE;

    uint8_t cla = p->buf[0];

    /* ── CLA validation ── */
    if ((cla & APDU_CLA_VER_MASK) != 0x00)
        return APDU_ERR_VERSION;

    if (cla & APDU_CLA_RFU_BIT)
        return APDU_ERR_RFU;

    int     ext       = (cla & APDU_CLA_EXT_BIT) ? 1 : 0;
    size_t  hdr_size  = ext ? APDU_EXT_HDR_SIZE : APDU_STD_HDR_SIZE;

    /* Need full header before we know data length */
    if (p->filled < hdr_size)
        return APDU_NEED_MORE;

    /* ── Parse header ── */
    uint8_t ins = p->buf[1];
    uint8_t p1  = p->buf[2];
    uint8_t p2  = p->buf[3];

    uint16_t data_len;
    if (!ext) {
        /* Standard: Lc is byte[4] */
        data_len = p->buf[4];
    } else {
        /* Extended: byte[4] must be 0x00 (placeholder), then Lc_h Lc_l */
        if (p->buf[4] != 0x00)
            return APDU_ERR_EXT_LC;
        data_len = ((uint16_t)p->buf[5] << 8) | p->buf[6];
    }

    /* ── Compute total expected frame size ── */
    uint8_t sec      = (uint8_t)((cla & APDU_CLA_SEC_MASK) >> APDU_CLA_SEC_SHIFT);
    size_t  le_size  = ext ? APDU_EXT_LE_SIZE : APDU_STD_LE_SIZE;
    size_t  tag_size = (sec != APDU_SEC_PLAIN) ? APDU_AUTH_TAG_SIZE : 0;

    /*
     * Overflow guard: data_len is uint16_t (max 65535).
     * hdr_size + data_len + le_size + tag_size fits in size_t on any
     * 32/64-bit platform; and APDU_MAX_FRAME_SIZE is exactly the maximum
     * valid combination, so any valid frame fits in the buffer.
     */
    size_t total = hdr_size + (size_t)data_len + le_size + tag_size;
    if (total > APDU_MAX_FRAME_SIZE)
        return APDU_ERR_LENGTH; /* should never happen with valid inputs */

    /* Still waiting for data + Le (+ auth tag) */
    if (p->filled < total)
        return APDU_NEED_MORE;

    /* ── Parse Le ── */
    size_t le_offset = hdr_size + data_len;
    uint16_t le;
    if (!ext) {
        le = p->buf[le_offset];
    } else {
        le = ((uint16_t)p->buf[le_offset] << 8) | p->buf[le_offset + 1];
    }

    /* ── Populate output (zero-copy pointers into buf) ── */
    out->cla       = cla;
    out->ins       = ins;
    out->p1        = p1;
    out->p2        = p2;
    out->ver       = 0;
    out->m_bit     = (cla & APDU_CLA_M_BIT) ? 1 : 0;
    out->sec       = sec;
    out->ext       = ext;
    out->data_len  = data_len;
    out->data      = (data_len > 0) ? (p->buf + hdr_size) : NULL;
    out->le        = le;
    out->auth_tag  = (tag_size > 0)
                     ? (p->buf + le_offset + le_size)
                     : NULL;
    out->total_size = total;

    return APDU_FRAME_READY;
}

/* ── Consume ─────────────────────────────────────────────── */

void apdu_parser_consume(ApduParser *p, const ApduFrame *frame)
{
    if (!p || !frame) return;
    if (frame->total_size >= p->filled) {
        /* Consumed entire buffer (common case: no pipelining) */
        p->filled = 0;
    } else {
        /* Shift leftover bytes to front (pipelining / sticky packet) */
        size_t remaining = p->filled - frame->total_size;
        memmove(p->buf, p->buf + frame->total_size, remaining);
        p->filled = remaining;
    }
}

/* ── Reset ───────────────────────────────────────────────── */

void apdu_parser_reset(ApduParser *p)
{
    if (!p) return;
    p->filled = 0;
    /* Wipe buf to avoid partial key material persisting */
    memset(p->buf, 0, sizeof(p->buf));
}
