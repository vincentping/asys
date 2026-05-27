/*
 * test_proc_throttle.c — PROC_THROTTLE (0x20) Handler Conformance Tests
 *
 * Tests:
 *   TC-PROC-001: CLA.Sec != Signed → 0x6982
 *   TC-PROC-002: Lc < 8 → 0x6700
 *   TC-PROC-003: P1 invalid (not 0x00 or 0x01) → 0x6A80
 *   TC-PROC-004: PID == 0 → 0x6A80
 *   TC-PROC-005: valid STOP request on child process → 0x9000
 *   TC-PROC-006: valid CONT request on stopped process → 0x9000
 *   TC-PROC-007: target process does not exist → 0x6A80
 *
 * Build (from tests/conformance/):
 *   gcc -O2 -Wall \
 *       test_proc_throttle.c \
 *       ../../src/asyd/core/apdu_parser.c \
 *       ../../src/asyd/core/dispatcher.c \
 *       ../../src/asyd/core/task_pool.c \
 *       ../../src/asyd/core/monocypher.c \
 *       ../../src/asyd/core/noise_ik.c \
 *       ../../src/asyd/core/whitelist.c \
 *       ../../src/asyd/core/auth_verify.c \
 *       ../../src/asyd/core/crypto_utils.c \
 *       ../../src/asyd/handlers/sys_caps.c \
 *       ../../src/asyd/handlers/sys_hello.c \
 *       ../../src/asyd/handlers/sys_status.c \
 *       ../../src/asyd/handlers/sys_procs.c \
 *       ../../src/asyd/handlers/proc_throttle.c \
 *       ../../src/asyd/handlers/svc_restart.c \
 *       ../../src/asyd/handlers/task_query.c \
 *       -I../../src/asyd/core \
 *       -o test_proc_throttle
 * Run:
 *   ./test_proc_throttle
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "apdu_parser.h"
#include "dispatcher.h"

static int g_pass = 0, g_fail = 0;

#define EXPECT(label, expr) do {                                            \
    if (expr) { printf("  PASS  %s\n", (label)); g_pass++; }               \
    else      { printf("  FAIL  %s (line %d)\n", (label), __LINE__); g_fail++; } \
} while(0)

static uint16_t get_u16(const uint8_t *b) { return ((uint16_t)b[0] << 8) | b[1]; }

/*
 * Build a PROC_THROTTLE ApduFrame directly.
 * data[] layout: [Seq(4B BE)][PID(4B BE)]
 */
static ApduFrame make_throttle_req(uint8_t sec, uint8_t p1,
                                   uint32_t pid,
                                   uint8_t data_buf[8])
{
    ApduFrame f;
    memset(&f, 0, sizeof(f));
    f.cla     = (sec == APDU_SEC_SIGNED) ? 0x04 : 0x00;
    f.ins     = 0x20;
    f.p1      = p1;
    f.sec     = sec;
    /* Seq = 0 (Phase 3: not validated) */
    data_buf[0] = 0; data_buf[1] = 0; data_buf[2] = 0; data_buf[3] = 0;
    data_buf[4] = (uint8_t)(pid >> 24);
    data_buf[5] = (uint8_t)(pid >> 16);
    data_buf[6] = (uint8_t)(pid >>  8);
    data_buf[7] = (uint8_t)(pid & 0xFF);
    f.data     = data_buf;
    f.data_len = 8;
    return f;
}

int handler_proc_throttle(const ApduFrame *req, uint8_t *resp, size_t sz, uint16_t session_id);

int main(void)
{
    printf("=== ASys PROC_THROTTLE Conformance Test ===\n\n");

    uint8_t  resp[DISP_RESP_MAX];
    uint8_t  data_buf[8];
    ApduFrame req;
    int      n;

    /* ── TC-PROC-001: CLA.Sec must be Signed ─────────────── */
    printf("[TC-PROC-001: CLA.Sec check]\n");
    req = make_throttle_req(APDU_SEC_PLAIN, 0x00, 1234, data_buf);
    n = handler_proc_throttle(&req, resp, sizeof(resp), 1);
    EXPECT("plain CLA → 0x6982 (Access Denied)",
           n == 2 && get_u16(resp) == 0x6982);

    /* ── TC-PROC-002: Lc length check ───────────────────── */
    printf("\n[TC-PROC-002: Lc length check]\n");
    req = make_throttle_req(APDU_SEC_SIGNED, 0x00, 1234, data_buf);
    req.data_len = 4;   /* too short: need 8 */
    n = handler_proc_throttle(&req, resp, sizeof(resp), 1);
    EXPECT("Lc=4 → 0x6700 (Wrong Length)",
           n == 2 && get_u16(resp) == 0x6700);

    /* ── TC-PROC-003: P1 invalid value ─────────────────── */
    printf("\n[TC-PROC-003: P1 invalid value]\n");
    req = make_throttle_req(APDU_SEC_SIGNED, 0x02, 1234, data_buf);
    n = handler_proc_throttle(&req, resp, sizeof(resp), 1);
    EXPECT("P1=0x02 → 0x6A80 (Wrong Data)",
           n == 2 && get_u16(resp) == 0x6A80);

    /* ── TC-PROC-004: PID=0 rejected ───────────────────── */
    printf("\n[TC-PROC-004: PID=0 rejected]\n");
    req = make_throttle_req(APDU_SEC_SIGNED, 0x00, 0, data_buf);
    n = handler_proc_throttle(&req, resp, sizeof(resp), 1);
    EXPECT("PID=0 → 0x6A80 (Wrong Data)",
           n == 2 && get_u16(resp) == 0x6A80);

    /* ── TC-PROC-005 + 006: STOP and CONT on child process ─ */
    printf("\n[TC-PROC-005: STOP child process]\n");
    pid_t child = fork();
    if (child == 0) {
        /* child: loop until killed */
        while (1) sleep(1);
    }

    /* parent: STOP the child */
    req = make_throttle_req(APDU_SEC_SIGNED, 0x00, (uint32_t)child, data_buf);
    n = handler_proc_throttle(&req, resp, sizeof(resp), 1);
    EXPECT("STOP child → 0x9000",
           n == 2 && get_u16(resp) == 0x9000);

    printf("\n[TC-PROC-006: CONT stopped process]\n");
    req = make_throttle_req(APDU_SEC_SIGNED, 0x01, (uint32_t)child, data_buf);
    n = handler_proc_throttle(&req, resp, sizeof(resp), 1);
    EXPECT("CONT child → 0x9000",
           n == 2 && get_u16(resp) == 0x9000);

    /* clean up child */
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);

    /* ── TC-PROC-007: non-existent process ──────────────── */
    printf("\n[TC-PROC-007: non-existent PID]\n");
    /* Use a PID that is astronomically unlikely to exist */
    req = make_throttle_req(APDU_SEC_SIGNED, 0x00, 999999, data_buf);
    n = handler_proc_throttle(&req, resp, sizeof(resp), 1);
    EXPECT("PID not found → 0x6A80 (Wrong Data)",
           n == 2 && get_u16(resp) == 0x6A80);

    /* ── Summary ─────────────────────────────────────────── */
    printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    if (g_fail == 0)
        printf("ALL TESTS PASSED — PROC_THROTTLE handler functional\n");
    else
        printf("SOME TESTS FAILED — check output above\n");

    return g_fail ? 1 : 0;
}
