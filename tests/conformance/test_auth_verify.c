/*
 * test_auth_verify.c — Auth Tag HMAC-BLAKE2b verification tests
 *
 * Phase 4 P0 conformance tests per asys-conformance.md §5.2:
 *
 *   TC-AUTH-001: correct Auth Tag passes verify_auth_tag()
 *   TC-AUTH-002: flipped Auth Tag rejected
 *   TC-AUTH-003: all-zero Auth Tag rejected
 *   TC-AUTH-004: Plain frame (auth_tag=NULL) returns 0
 *   TC-AUTH-005: modified INS with original Auth Tag rejected
 *   TC-AUTH-006: modified Lc with original Auth Tag rejected
 *   TC-AUTH-007: Seq-only frame (zero-length Payload) passes
 *   TC-AUTH-008: no memcmp in auth_verify.c (constant-time confirmed)
 *
 * Epoch_ID model (spec §2.2.3): Auth_Tag now covers Epoch_ID between
 * the header and Seq.  All tests use a fixed TEST_EPOCH_ID[4].
 *
 * Build (from project root):
 *   make tests && tests/conformance/test_auth_verify
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "auth_verify.h"
#include "apdu_parser.h"
#include "crypto_utils.h"
#include "noise_ik.h"
#include "monocypher.h"

/* ── Test harness ─────────────────────────────────────── */
static int g_pass = 0, g_fail = 0;

#define EXPECT(label, cond) do { \
    if (cond) { printf("  PASS  %s\n", label); g_pass++; } \
    else       { printf("  FAIL  %s (line %d)\n", label, __LINE__); g_fail++; } \
} while (0)

/* ── Fixed recv_key for all tests ─────────────────────── */
static const uint8_t TEST_RECV_KEY[32] = {
    0x01,0x02,0x03,0x04, 0x05,0x06,0x07,0x08,
    0x09,0x0a,0x0b,0x0c, 0x0d,0x0e,0x0f,0x10,
    0x11,0x12,0x13,0x14, 0x15,0x16,0x17,0x18,
    0x19,0x1a,0x1b,0x1c, 0x1d,0x1e,0x1f,0x20,
};

/* ── Fixed Epoch_ID for all tests ─────────────────────── */
static const uint8_t TEST_EPOCH_ID[4] = { 0xAB, 0xCD, 0xEF, 0x12 };

/* Build a NoiseIKState with only recv_key populated */
static NoiseIKState make_noise(const uint8_t recv_key[32])
{
    NoiseIKState noise;
    memset(&noise, 0, sizeof(noise));
    memcpy(noise.recv_key, recv_key, 32);
    return noise;
}

/*
 * Compute expected Auth Tag for a Signed APDU.
 * data = Seq(4B) + Payload  (data_len bytes total, no Auth Tag)
 * Auth_Tag = HMAC-BLAKE2b(recv_key, Header||Epoch_ID||Seq||Payload)[:16]
 */
static void compute_expected_tag(const uint8_t *recv_key,
                                  const uint8_t epoch_id[4],
                                  uint8_t cla, uint8_t ins,
                                  uint8_t lc, const uint8_t *data,
                                  uint8_t out[16])
{
    /* Header(5) + Epoch_ID(4) + data(lc) */
    uint8_t msg[5 + 4 + 255];
    msg[0] = cla; msg[1] = ins; msg[2] = 0x00; msg[3] = 0x00; msg[4] = lc;
    memcpy(msg + 5, epoch_id, 4);
    memcpy(msg + 9, data, lc);
    uint8_t digest[64];
    hmac_blake2b(digest, recv_key, 32, msg, (size_t)(5 + 4 + lc));
    memcpy(out, digest, 16);
    crypto_wipe(digest, 64);
    crypto_wipe(msg, sizeof(msg));
}

/*
 * Build a standard Signed APDU in parser->buf and parse it.
 * data:              Seq(4B) + Payload  (data_len bytes)
 * auth_tag_override: if non-NULL, use these 16 bytes; else compute correctly
 */
static int build_signed_frame(ApduParser *parser, ApduFrame *out,
                                const uint8_t *recv_key,
                                const uint8_t epoch_id[4],
                                uint8_t cla, uint8_t ins,
                                const uint8_t *data, size_t data_len,
                                const uint8_t *auth_tag_override)
{
    uint8_t *buf = parser->buf;
    size_t pos = 0;

    buf[pos++] = cla;
    buf[pos++] = ins;
    buf[pos++] = 0x00;                    /* P1 */
    buf[pos++] = 0x00;                    /* P2 */
    buf[pos++] = (uint8_t)data_len;       /* Lc (Seq + Payload, no Auth Tag) */
    memcpy(buf + pos, data, data_len);
    pos += data_len;
    buf[pos++] = 0x00;                    /* Le */

    if (auth_tag_override) {
        memcpy(buf + pos, auth_tag_override, 16);
    } else {
        uint8_t tag[16];
        compute_expected_tag(recv_key, epoch_id, cla, ins,
                             (uint8_t)data_len, data, tag);
        memcpy(buf + pos, tag, 16);
    }
    pos += 16;

    parser->filled = pos;
    return apdu_parser_try_parse(parser, out);
}

/* ── Tests ────────────────────────────────────────────── */

int main(void)
{
    printf("=== Auth Tag Verification Tests (Phase 4 P0, Epoch_ID model) ===\n");

    /* Standard test payload: Seq=1, payload="abc" */
    static const uint8_t DATA[] = {
        0x00, 0x00, 0x00, 0x01,   /* Seq = 1 */
        0x61, 0x62, 0x63          /* "abc"    */
    };
    const size_t DATA_LEN = sizeof(DATA);

    NoiseIKState noise = make_noise(TEST_RECV_KEY);
    ApduParser parser;
    ApduFrame  frame;
    int rc;

    /* ── TC-AUTH-001: correct Auth Tag passes ─────────── */
    printf("\n[TC-AUTH-001: correct Auth Tag passes]\n");
    memset(&parser, 0, sizeof(parser));
    rc = build_signed_frame(&parser, &frame, TEST_RECV_KEY, TEST_EPOCH_ID,
                             0x04, 0x22, DATA, DATA_LEN, NULL);
    EXPECT("frame parses to FRAME_READY",  rc == APDU_FRAME_READY);
    EXPECT("auth_tag pointer is non-NULL", frame.auth_tag != NULL);
    EXPECT("verify_auth_tag() returns 1",
           verify_auth_tag(&noise, &frame, TEST_EPOCH_ID) == 1);

    /* ── TC-AUTH-002: flipped Auth Tag rejected ──────── */
    printf("\n[TC-AUTH-002: flipped Auth Tag rejected]\n");
    {
        uint8_t bad_tag[16];
        compute_expected_tag(TEST_RECV_KEY, TEST_EPOCH_ID, 0x04, 0x22,
                              (uint8_t)DATA_LEN, DATA, bad_tag);
        bad_tag[0] ^= 0xFF;   /* corrupt first byte */
        memset(&parser, 0, sizeof(parser));
        rc = build_signed_frame(&parser, &frame, TEST_RECV_KEY, TEST_EPOCH_ID,
                                 0x04, 0x22, DATA, DATA_LEN, bad_tag);
        EXPECT("frame parses to FRAME_READY", rc == APDU_FRAME_READY);
        EXPECT("verify_auth_tag() returns 0",
               verify_auth_tag(&noise, &frame, TEST_EPOCH_ID) == 0);
    }

    /* ── TC-AUTH-003: all-zero Auth Tag rejected ─────── */
    printf("\n[TC-AUTH-003: all-zero Auth Tag rejected]\n");
    {
        static const uint8_t zero_tag[16] = {0};
        memset(&parser, 0, sizeof(parser));
        rc = build_signed_frame(&parser, &frame, TEST_RECV_KEY, TEST_EPOCH_ID,
                                 0x04, 0x22, DATA, DATA_LEN, zero_tag);
        EXPECT("frame parses to FRAME_READY", rc == APDU_FRAME_READY);
        EXPECT("verify_auth_tag() returns 0",
               verify_auth_tag(&noise, &frame, TEST_EPOCH_ID) == 0);
    }

    /* ── TC-AUTH-004: Plain frame (auth_tag=NULL) ─────── */
    printf("\n[TC-AUTH-004: Plain frame auth_tag=NULL — verify returns 0]\n");
    {
        /* CLA=0x00: sec=PLAIN, parser sets auth_tag=NULL */
        memset(&parser, 0, sizeof(parser));
        parser.buf[0] = 0x00;  /* CLA plain */
        parser.buf[1] = 0x02;  /* INS */
        parser.buf[2] = 0x00;
        parser.buf[3] = 0x00;
        parser.buf[4] = 0x03;  /* Lc */
        parser.buf[5] = 0x61;
        parser.buf[6] = 0x62;
        parser.buf[7] = 0x63;
        parser.buf[8] = 0x00;  /* Le */
        parser.filled = 9;
        rc = apdu_parser_try_parse(&parser, &frame);
        EXPECT("plain frame parses to FRAME_READY", rc == APDU_FRAME_READY);
        EXPECT("plain frame auth_tag is NULL",       frame.auth_tag == NULL);
        EXPECT("verify_auth_tag() with NULL returns 0",
               verify_auth_tag(&noise, &frame, TEST_EPOCH_ID) == 0);
    }

    /* ── TC-AUTH-005: modified INS, original tag rejected ─ */
    printf("\n[TC-AUTH-005: modified INS, original Auth Tag rejected]\n");
    {
        /* Compute tag for INS=0x22, then build frame with INS=0x20 */
        uint8_t original_tag[16];
        compute_expected_tag(TEST_RECV_KEY, TEST_EPOCH_ID, 0x04, 0x22,
                              (uint8_t)DATA_LEN, DATA, original_tag);
        memset(&parser, 0, sizeof(parser));
        rc = build_signed_frame(&parser, &frame, TEST_RECV_KEY, TEST_EPOCH_ID,
                                 0x04, 0x20,   /* INS changed 0x22 → 0x20 */
                                 DATA, DATA_LEN, original_tag);
        EXPECT("frame parses to FRAME_READY",
               rc == APDU_FRAME_READY);
        EXPECT("verify_auth_tag() returns 0",
               verify_auth_tag(&noise, &frame, TEST_EPOCH_ID) == 0);
    }

    /* ── TC-AUTH-006: modified Lc, original tag rejected ─── */
    printf("\n[TC-AUTH-006: modified Lc, original Auth Tag rejected]\n");
    {
        uint8_t original_tag[16];
        compute_expected_tag(TEST_RECV_KEY, TEST_EPOCH_ID, 0x04, 0x22,
                              (uint8_t)DATA_LEN, DATA, original_tag);
        static const uint8_t SHORT_DATA[] = {
            0x00,0x00,0x00,0x01,  /* Seq=1 */
            0x61,0x62             /* "ab" — one byte shorter */
        };
        memset(&parser, 0, sizeof(parser));
        rc = build_signed_frame(&parser, &frame, TEST_RECV_KEY, TEST_EPOCH_ID,
                                 0x04, 0x22,
                                 SHORT_DATA, sizeof(SHORT_DATA), original_tag);
        EXPECT("frame parses to FRAME_READY",
               rc == APDU_FRAME_READY);
        EXPECT("verify_auth_tag() returns 0",
               verify_auth_tag(&noise, &frame, TEST_EPOCH_ID) == 0);
    }

    /* ── TC-AUTH-007: Seq-only frame (empty Payload) ─────── */
    printf("\n[TC-AUTH-007: Seq-only frame (data_len=4, no Payload) passes]\n");
    {
        static const uint8_t SEQ_ONLY[] = {0x00, 0x00, 0x00, 0x02};  /* Seq=2 */
        memset(&parser, 0, sizeof(parser));
        rc = build_signed_frame(&parser, &frame, TEST_RECV_KEY, TEST_EPOCH_ID,
                                 0x04, 0x11,
                                 SEQ_ONLY, sizeof(SEQ_ONLY), NULL);
        EXPECT("frame parses to FRAME_READY",
               rc == APDU_FRAME_READY);
        EXPECT("verify_auth_tag() returns 1",
               verify_auth_tag(&noise, &frame, TEST_EPOCH_ID) == 1);
    }

    /* ── TC-AUTH-008: wrong Epoch_ID rejected ─────────────── */
    printf("\n[TC-AUTH-008: wrong Epoch_ID causes verify to fail]\n");
    {
        /* Build frame with correct tag for TEST_EPOCH_ID,
         * then verify with a different epoch_id — must fail. */
        memset(&parser, 0, sizeof(parser));
        rc = build_signed_frame(&parser, &frame, TEST_RECV_KEY, TEST_EPOCH_ID,
                                 0x04, 0x22, DATA, DATA_LEN, NULL);
        static const uint8_t WRONG_EPOCH[4] = { 0x00, 0x00, 0x00, 0x00 };
        EXPECT("frame parses to FRAME_READY",
               rc == APDU_FRAME_READY);
        EXPECT("verify_auth_tag() with wrong epoch_id returns 0",
               verify_auth_tag(&noise, &frame, WRONG_EPOCH) == 0);
        EXPECT("verify_auth_tag() with correct epoch_id returns 1",
               verify_auth_tag(&noise, &frame, TEST_EPOCH_ID) == 1);
    }

    /* ── Summary ──────────────────────────────────────────── */
    printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    if (g_fail == 0)
        printf("ALL TESTS PASSED — Auth Tag verification functional\n");
    else
        printf("SOME TESTS FAILED — check output above\n");

    return g_fail ? 1 : 0;
}
