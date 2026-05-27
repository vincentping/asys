/*
 * test_apdu_parser.c — APDU Parser Conformance Tests
 *
 * Tests:
 *   1.  Standard frame, Lc=0, plain               → FRAME_READY, data=NULL
 *   2.  Standard frame, Lc=3, plain               → data points into buf
 *   3.  Standard frame, Lc=2, Sec=01 (signed)     → auth_tag present
 *   4.  Standard frame, Lc=2, Sec=10 (enc+sign)   → auth_tag present
 *   5.  Extended frame, Lc=256, plain              → ext=1, data_len=256
 *   6.  Extended frame, Lc=0, plain               → ext=1, data=NULL
 *   7.  Half-packet: split after byte 2           → NEED_MORE then READY
 *   8.  Pipelining: two frames fed as one chunk   → consume, then second READY
 *   9.  CLA version error (bits 7-5 ≠ 000)        → ERR_VERSION
 *  10.  CLA RFU bit set                           → ERR_RFU
 *  11.  Extended frame with Lc placeholder ≠ 0x00 → ERR_EXT_LC
 *  12.  M bit decoding (chaining flag)            → m_bit=1
 *  13.  Zero-copy: data ptr is inside parser buf  → pointer arithmetic check
 *  14.  Pool: acquire / release / exhaustion      → NULL on exhaustion
 *  15.  Le=0xFF (standard max)                   → le decoded correctly
 *  16.  Extended Le=0x0100                       → le=256
 *
 * Build (from tests/conformance/):
 *   gcc -O2 -Wall \
 *       test_apdu_parser.c \
 *       ../../src/asyd/core/apdu_parser.c \
 *       -I../../src/asyd/core \
 *       -o test_apdu_parser
 * Run:
 *   ./test_apdu_parser
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include "apdu_parser.h"

/* ── Minimal test harness ──────────────────────────────── */
static int g_pass = 0, g_fail = 0;

#define EXPECT(label, expr) do {                         \
    if (expr) {                                          \
        printf("  PASS  %s\n", (label));                 \
        g_pass++;                                        \
    } else {                                             \
        printf("  FAIL  %s  (line %d)\n", (label), __LINE__); \
        g_fail++;                                        \
    }                                                    \
} while(0)

/* ── Helper: load bytes into a fresh parser ──────────── */
static void load(ApduParser *p, const uint8_t *bytes, size_t len)
{
    apdu_parser_reset(p);
    memcpy(p->buf, bytes, len);
    p->filled = len;
}

/* ── Build standard frame in caller's buffer ─────────── */
/*
 * Returns total frame size written.
 * auth_tag: 16 bytes if sec != 0, else ignored.
 */
static size_t build_std(uint8_t *out,
                         uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2,
                         const uint8_t *data, uint8_t lc,
                         uint8_t le,
                         const uint8_t *tag)   /* NULL if plain */
{
    size_t i = 0;
    out[i++] = cla;
    out[i++] = ins;
    out[i++] = p1;
    out[i++] = p2;
    out[i++] = lc;
    if (data) { memcpy(out + i, data, lc); i += lc; }
    out[i++] = le;
    if (tag) { memcpy(out + i, tag, APDU_AUTH_TAG_SIZE); i += APDU_AUTH_TAG_SIZE; }
    return i;
}

/* Build extended frame */
static size_t build_ext(uint8_t *out,
                         uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2,
                         const uint8_t *data, uint16_t data_len,
                         uint16_t le,
                         const uint8_t *tag)
{
    size_t i = 0;
    out[i++] = cla;
    out[i++] = ins;
    out[i++] = p1;
    out[i++] = p2;
    out[i++] = 0x00;                        /* Lc placeholder */
    out[i++] = (uint8_t)(data_len >> 8);
    out[i++] = (uint8_t)(data_len & 0xFF);
    if (data) { memcpy(out + i, data, data_len); i += data_len; }
    out[i++] = (uint8_t)(le >> 8);
    out[i++] = (uint8_t)(le & 0xFF);
    if (tag) { memcpy(out + i, tag, APDU_AUTH_TAG_SIZE); i += APDU_AUTH_TAG_SIZE; }
    return i;
}

/* ── Tests ─────────────────────────────────────────────── */

int main(void)
{
    printf("=== ASys APDU Parser Conformance Test ===\n\n");

    ApduParser p;
    memset(&p, 0, sizeof(p));
    ApduFrame  fr;
    uint8_t    scratch[APDU_MAX_FRAME_SIZE];
    size_t     flen;

    /* ── 1. Standard, Lc=0, plain ───────────────────────── */
    printf("[Standard Frame]\n");
    {
        flen = build_std(scratch, 0x00, 0x01, 0x00, 0x00, NULL, 0, 0x00, NULL);
        load(&p, scratch, flen);
        int rc = apdu_parser_try_parse(&p, &fr);
        EXPECT("std Lc=0: FRAME_READY",     rc == APDU_FRAME_READY);
        EXPECT("std Lc=0: ins=0x01",        fr.ins == 0x01);
        EXPECT("std Lc=0: data_len=0",      fr.data_len == 0);
        EXPECT("std Lc=0: data=NULL",       fr.data == NULL);
        EXPECT("std Lc=0: auth_tag=NULL",   fr.auth_tag == NULL);
        EXPECT("std Lc=0: ext=0",           fr.ext == 0);
        EXPECT("std Lc=0: sec=PLAIN",       fr.sec == APDU_SEC_PLAIN);
        EXPECT("std Lc=0: le=0x00",         fr.le == 0x00);
        EXPECT("std Lc=0: total=6",         fr.total_size == 6);
    }

    /* ── 2. Standard, Lc=3, plain ───────────────────────── */
    {
        uint8_t payload[] = {0xAA, 0xBB, 0xCC};
        flen = build_std(scratch, 0x00, 0x02, 0x01, 0x02,
                         payload, 3, 0xFF, NULL);
        load(&p, scratch, flen);
        int rc = apdu_parser_try_parse(&p, &fr);
        EXPECT("std Lc=3: FRAME_READY",     rc == APDU_FRAME_READY);
        EXPECT("std Lc=3: data_len=3",      fr.data_len == 3);
        EXPECT("std Lc=3: data[0]=0xAA",    fr.data && fr.data[0] == 0xAA);
        EXPECT("std Lc=3: data[2]=0xCC",    fr.data && fr.data[2] == 0xCC);
        EXPECT("std Lc=3: le=0xFF",         fr.le == 0xFF);
        EXPECT("std Lc=3: total=9",         fr.total_size == 9);
    }

    /* ── 3. Standard, Sec=01 (signed) with auth tag ──────── */
    printf("\n[Secure Frame]\n");
    {
        uint8_t payload[] = {0xDE, 0xAD};
        uint8_t tag[16];
        memset(tag, 0x5A, 16);
        /* CLA = 0x04 → Sec=01 */
        flen = build_std(scratch, 0x04, 0x01, 0x00, 0x00,
                         payload, 2, 0x00, tag);
        load(&p, scratch, flen);
        int rc = apdu_parser_try_parse(&p, &fr);
        EXPECT("sec=01: FRAME_READY",        rc == APDU_FRAME_READY);
        EXPECT("sec=01: sec field",          fr.sec == APDU_SEC_SIGNED);
        EXPECT("sec=01: auth_tag≠NULL",      fr.auth_tag != NULL);
        EXPECT("sec=01: auth_tag[0]=0x5A",   fr.auth_tag && fr.auth_tag[0] == 0x5A);
        EXPECT("sec=01: total=5+2+1+16=24",  fr.total_size == 24);
    }

    /* ── 4. Standard, Sec=10 (enc+sign) ─────────────────── */
    {
        uint8_t tag[16];
        memset(tag, 0x3C, 16);
        /* CLA = 0x08 → Sec=10 */
        flen = build_std(scratch, 0x08, 0x00, 0x00, 0x00, NULL, 0, 0x00, tag);
        load(&p, scratch, flen);
        int rc = apdu_parser_try_parse(&p, &fr);
        EXPECT("sec=10: FRAME_READY",        rc == APDU_FRAME_READY);
        EXPECT("sec=10: sec field",          fr.sec == APDU_SEC_ENC_SIGN);
        EXPECT("sec=10: auth_tag present",   fr.auth_tag != NULL);
        EXPECT("sec=10: total=5+0+1+16=22",  fr.total_size == 22);
    }

    /* ── 5. Extended frame, data_len=256 ─────────────────── */
    printf("\n[Extended Frame]\n");
    {
        uint8_t big[256];
        memset(big, 0xBE, 256);
        /* CLA = 0x02 → Ext=1, plain */
        flen = build_ext(scratch, 0x02, 0x03, 0x00, 0x00,
                         big, 256, 0x0000, NULL);
        load(&p, scratch, flen);
        int rc = apdu_parser_try_parse(&p, &fr);
        EXPECT("ext Lc=256: FRAME_READY",    rc == APDU_FRAME_READY);
        EXPECT("ext Lc=256: ext=1",          fr.ext == 1);
        EXPECT("ext Lc=256: data_len=256",   fr.data_len == 256);
        EXPECT("ext Lc=256: data[0]=0xBE",   fr.data && fr.data[0] == 0xBE);
        EXPECT("ext Lc=256: le=0",           fr.le == 0);
        /* total = 7+256+2 = 265 */
        EXPECT("ext Lc=256: total=265",      fr.total_size == 265);
    }

    /* ── 6. Extended frame, data_len=0 ───────────────────── */
    {
        flen = build_ext(scratch, 0x02, 0x00, 0x00, 0x00,
                         NULL, 0, 0x0100, NULL);
        load(&p, scratch, flen);
        int rc = apdu_parser_try_parse(&p, &fr);
        EXPECT("ext Lc=0: FRAME_READY",      rc == APDU_FRAME_READY);
        EXPECT("ext Lc=0: data=NULL",        fr.data == NULL);
        EXPECT("ext Lc=0: le=256",           fr.le == 0x0100);
        EXPECT("ext Lc=0: total=9",          fr.total_size == 9);
    }

    /* ── 7. Half-packet ───────────────────────────────────── */
    printf("\n[Frame Sync — Half-packet / Pipelining]\n");
    {
        uint8_t payload[] = {0x11, 0x22};
        flen = build_std(scratch, 0x00, 0x02, 0x00, 0x00,
                         payload, 2, 0x00, NULL);
        /* Feed only first 3 bytes */
        apdu_parser_reset(&p);
        memcpy(p.buf, scratch, 3);
        p.filled = 3;
        int rc = apdu_parser_try_parse(&p, &fr);
        EXPECT("half-pkt: 3 bytes → NEED_MORE",  rc == APDU_NEED_MORE);

        /* Feed the rest */
        memcpy(p.buf + p.filled, scratch + 3, flen - 3);
        p.filled = flen;
        rc = apdu_parser_try_parse(&p, &fr);
        EXPECT("half-pkt: full frame → READY",   rc == APDU_FRAME_READY);
        EXPECT("half-pkt: data[0]=0x11",         fr.data && fr.data[0] == 0x11);
    }

    /* ── 8. Pipelining: two frames concatenated ───────────── */
    {
        /* Frame A: SYS_HELLO (Lc=0) */
        uint8_t frameA[6];
        size_t  lenA = build_std(frameA, 0x00, 0x01, 0x00, 0x00,
                                 NULL, 0, 0x00, NULL);

        /* Frame B: with 1 byte payload */
        uint8_t pb = 0x42;
        uint8_t frameB[7];
        size_t  lenB = build_std(frameB, 0x00, 0x02, 0x00, 0x00,
                                 &pb, 1, 0xFF, NULL);

        /* Concatenate both into parser buf */
        apdu_parser_reset(&p);
        memcpy(p.buf,        frameA, lenA);
        memcpy(p.buf + lenA, frameB, lenB);
        p.filled = lenA + lenB;

        /* Parse frame A */
        int rc = apdu_parser_try_parse(&p, &fr);
        EXPECT("pipeline: first frame READY",    rc == APDU_FRAME_READY);
        EXPECT("pipeline: frame A ins=0x01",     fr.ins == 0x01);
        EXPECT("pipeline: frame A total_size",   fr.total_size == lenA);

        apdu_parser_consume(&p, &fr);

        /* Now frame B should be at buf[0] */
        rc = apdu_parser_try_parse(&p, &fr);
        EXPECT("pipeline: second frame READY",   rc == APDU_FRAME_READY);
        EXPECT("pipeline: frame B ins=0x02",     fr.ins == 0x02);
        EXPECT("pipeline: frame B data[0]=0x42", fr.data && fr.data[0] == 0x42);
        EXPECT("pipeline: buf empty after B",
               (apdu_parser_consume(&p, &fr), p.filled == 0));
    }

    /* ── 9. Error: bad version ───────────────────────────── */
    printf("\n[Error Cases]\n");
    {
        /* CLA = 0x20 → Ver = 001 → ERR_VERSION */
        uint8_t bad[] = {0x20, 0x01, 0x00, 0x00, 0x00, 0x00};
        load(&p, bad, sizeof(bad));
        EXPECT("bad ver: ERR_VERSION",
               apdu_parser_try_parse(&p, &fr) == APDU_ERR_VERSION);
    }

    /* ── 10. Error: RFU bit set ──────────────────────────── */
    {
        /* CLA = 0x01 → bit 0 set → ERR_RFU */
        uint8_t bad[] = {0x01, 0x01, 0x00, 0x00, 0x00, 0x00};
        load(&p, bad, sizeof(bad));
        EXPECT("RFU set: ERR_RFU",
               apdu_parser_try_parse(&p, &fr) == APDU_ERR_RFU);
    }

    /* ── 11. Error: extended Lc placeholder ≠ 0x00 ────────── */
    {
        /* CLA=0x02 (Ext=1), but byte[4]=0xFF instead of 0x00 */
        uint8_t bad[] = {0x02, 0x01, 0x00, 0x00, 0xFF, 0x00, 0x01, 0xAA, 0x00, 0x00};
        load(&p, bad, sizeof(bad));
        EXPECT("ext bad Lc: ERR_EXT_LC",
               apdu_parser_try_parse(&p, &fr) == APDU_ERR_EXT_LC);
    }

    /* ── 12. M bit (chaining) ────────────────────────────── */
    printf("\n[CLA Sub-fields]\n");
    {
        /* CLA = 0x10 → M=1, Sec=00, Ext=0 */
        flen = build_std(scratch, 0x10, 0x10, 0x00, 0x00, NULL, 0, 0x00, NULL);
        load(&p, scratch, flen);
        int rc = apdu_parser_try_parse(&p, &fr);
        EXPECT("M bit=1: FRAME_READY",   rc == APDU_FRAME_READY);
        EXPECT("M bit=1: m_bit=1",       fr.m_bit == 1);
        EXPECT("M bit=1: sec=PLAIN",     fr.sec == APDU_SEC_PLAIN);
        EXPECT("M bit=1: ext=0",         fr.ext == 0);
    }

    /* ── 13. Zero-copy: data ptr inside buf ──────────────── */
    printf("\n[Zero-copy]\n");
    {
        uint8_t payload[] = {0x01, 0x02, 0x03};
        flen = build_std(scratch, 0x00, 0x05, 0x00, 0x00,
                         payload, 3, 0x00, NULL);
        load(&p, scratch, flen);
        apdu_parser_try_parse(&p, &fr);
        /* data must point into p.buf, not into scratch */
        int inside = (fr.data >= p.buf) &&
                     (fr.data + fr.data_len <= p.buf + APDU_MAX_FRAME_SIZE);
        EXPECT("data ptr inside parser buf",   inside);
        EXPECT("data ptr = buf + hdr_size",
               fr.data == p.buf + APDU_STD_HDR_SIZE);
    }

    /* ── 14. Pool: acquire / release / exhaustion ────────── */
    printf("\n[Static Pool]\n");
    {
        ApduParser *slots[APDU_POOL_SIZE];
        int got_all = 1;
        for (int i = 0; i < APDU_POOL_SIZE; i++) {
            slots[i] = apdu_pool_acquire();
            if (!slots[i]) { got_all = 0; break; }
        }
        EXPECT("pool: acquire all slots", got_all);

        ApduParser *overflow = apdu_pool_acquire();
        EXPECT("pool: NULL on exhaustion", overflow == NULL);

        apdu_pool_release(slots[0]);
        ApduParser *reacquired = apdu_pool_acquire();
        EXPECT("pool: reacquire after release", reacquired != NULL);

        /* Clean up */
        if (reacquired) apdu_pool_release(reacquired);
        for (int i = 1; i < APDU_POOL_SIZE; i++)
            if (slots[i]) apdu_pool_release(slots[i]);
    }

    /* ── 15. Standard Le=0xFF ────────────────────────────── */
    printf("\n[Le Decoding]\n");
    {
        flen = build_std(scratch, 0x00, 0x01, 0x00, 0x00, NULL, 0, 0xFF, NULL);
        load(&p, scratch, flen);
        apdu_parser_try_parse(&p, &fr);
        EXPECT("std Le=0xFF", fr.le == 0xFF);
    }

    /* ── 16. Extended Le=0x0100 ──────────────────────────── */
    {
        flen = build_ext(scratch, 0x02, 0x01, 0x00, 0x00,
                         NULL, 0, 0x0100, NULL);
        load(&p, scratch, flen);
        apdu_parser_try_parse(&p, &fr);
        EXPECT("ext Le=0x0100", fr.le == 0x0100);
    }

    /* ── Summary ─────────────────────────────────────────── */
    printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    if (g_fail == 0)
        printf("ALL TESTS PASSED — APDU parser is functional\n");
    else
        printf("SOME TESTS FAILED — check output above\n");

    return g_fail ? 1 : 0;
}
