/*
 * test_svc_restart.c — SVC_RESTART (0x22) Handler Conformance Tests
 *
 * Tests:
 *   TC-SVC-001: CLA.Sec != Signed → 0x6982
 *   TC-SVC-002: Lc < MIN_DATA_LEN (5) → 0x6700
 *   TC-SVC-003: Lc=5, name="A" (illegal char, min valid length) → 0x6A80
 *   TC-SVC-004: illegal char in name (uppercase) → 0x6A80
 *   TC-SVC-005: illegal char in name (path separator '/') → 0x6A80
 *   TC-SVC-006: name with '.service' suffix → 0x6A80 (rejected at protocol layer)
 *   TC-SVC-007: name exactly 64 bytes → 0x9000
 *   TC-SVC-008: name 65 bytes → 0x6A80
 *   TC-SVC-009: idempotency — second request returns existing Pending handle
 *   TC-SVC-010: pool full → 0x6400 (Blocked), no fork
 *
 * Note on TC-SVC-007/008: tests that pass validation will fork() systemctl.
 * The child process attempts to restart an unlikely-named service; it will fail
 * quickly.  The parent receives SW=0x9000 and a Task_Handle regardless of whether
 * systemctl succeeds, which is the correct async behaviour.
 *
 * Build (from tests/conformance/):
 *   gcc -O2 -Wall \
 *       test_svc_restart.c \
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
 *       -o test_svc_restart
 * Run:
 *   ./test_svc_restart
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "apdu_parser.h"
#include "dispatcher.h"
#include "task_pool.h"

/* Session IDs used throughout these tests */
#define TEST_SESSION_ID  1

static int g_pass = 0, g_fail = 0;

#define EXPECT(label, expr) do {                                            \
    if (expr) { printf("  PASS  %s\n", (label)); g_pass++; }               \
    else      { printf("  FAIL  %s (line %d)\n", (label), __LINE__); g_fail++; } \
} while(0)

static uint16_t get_u16(const uint8_t *b) { return ((uint16_t)b[0] << 8) | b[1]; }
static uint32_t get_u32(const uint8_t *b)
{
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] <<  8) |  (uint32_t)b[3];
}

int handler_svc_restart(const ApduFrame *req, uint8_t *resp, size_t sz, uint16_t session_id);

/*
 * Build an SVC_RESTART ApduFrame.
 * buf must be at least 4 + name_len bytes.
 * Data layout: [Seq(4B BE=0)][SvcName(name_len bytes)]
 */
static ApduFrame make_restart_req(uint8_t sec,
                                  const char *name, int name_len,
                                  uint8_t *buf, int buf_size)
{
    ApduFrame f;
    memset(&f, 0, sizeof(f));
    f.cla     = (sec == APDU_SEC_SIGNED) ? 0x04 : 0x00;
    f.ins     = 0x22;
    f.sec     = sec;
    /* Seq = 0 (Phase 3: not validated) */
    buf[0] = 0; buf[1] = 0; buf[2] = 0; buf[3] = 0;
    if (name_len > 0 && name_len <= buf_size - 4)
        memcpy(buf + 4, name, (size_t)name_len);
    f.data     = buf;
    f.data_len = (uint16_t)(4 + name_len);
    return f;
}

/*
 * Reap any zombie children left by fork()s during tests.
 * Called at end of test to avoid leaving zombies.
 */
static void reap_children(void)
{
    while (waitpid(-1, NULL, WNOHANG) > 0)
        ;
}

int main(void)
{
    printf("=== ASys SVC_RESTART Conformance Test ===\n\n");

    task_pool_init();

    uint8_t   resp[DISP_RESP_MAX];
    uint8_t   data_buf[4 + TASK_SVC_NAME_MAX + 4];  /* generous buffer */
    ApduFrame req;
    int       n;

    /* ── TC-SVC-001: CLA.Sec check ───────────────────────── */
    printf("[TC-SVC-001: CLA.Sec check]\n");
    req = make_restart_req(APDU_SEC_PLAIN, "nginx", 5, data_buf, (int)sizeof(data_buf));
    n = handler_svc_restart(&req, resp, sizeof(resp), TEST_SESSION_ID);
    EXPECT("plain CLA → 0x6982 (Access Denied)",
           n == 2 && get_u16(resp) == 0x6982);

    /* ── TC-SVC-002: Lc < MIN_DATA_LEN ──────────────────── */
    printf("\n[TC-SVC-002: Lc < MIN_DATA_LEN]\n");
    req = make_restart_req(APDU_SEC_SIGNED, "nginx", 5, data_buf, (int)sizeof(data_buf));
    req.data_len = 4;   /* only Seq, no name bytes */
    n = handler_svc_restart(&req, resp, sizeof(resp), TEST_SESSION_ID);
    EXPECT("Lc=4 → 0x6700 (Wrong Length)",
           n == 2 && get_u16(resp) == 0x6700);

    /* ── TC-SVC-003: illegal char at minimum valid length ────── */
    printf("\n[TC-SVC-003: illegal char, Lc satisfies MIN_DATA_LEN]\n");
    /* data_len=5 (name_len=1): length check passes, charset check fails */
    req = make_restart_req(APDU_SEC_SIGNED, "A", 1, data_buf, (int)sizeof(data_buf));
    n = handler_svc_restart(&req, resp, sizeof(resp), TEST_SESSION_ID);
    EXPECT("uppercase char rejected (\"A\"), Lc=5 → 0x6A80 (Wrong Data)",
           n == 2 && get_u16(resp) == 0x6A80);

    /* ── TC-SVC-004: illegal char (uppercase) ────────────── */
    printf("\n[TC-SVC-004: illegal char — uppercase]\n");
    req = make_restart_req(APDU_SEC_SIGNED, "Nginx", 5, data_buf, (int)sizeof(data_buf));
    n = handler_svc_restart(&req, resp, sizeof(resp), TEST_SESSION_ID);
    EXPECT("\"Nginx\" → 0x6A80 (Wrong Data)",
           n == 2 && get_u16(resp) == 0x6A80);

    /* ── TC-SVC-005: illegal char (path separator) ───────── */
    printf("\n[TC-SVC-005: illegal char — '/']\n");
    req = make_restart_req(APDU_SEC_SIGNED, "../etc/passwd", 13,
                           data_buf, (int)sizeof(data_buf));
    n = handler_svc_restart(&req, resp, sizeof(resp), TEST_SESSION_ID);
    EXPECT("\"../etc/passwd\" → 0x6A80 (Wrong Data)",
           n == 2 && get_u16(resp) == 0x6A80);

    /* ── TC-SVC-006: name with '.service' suffix → rejected ── */
    printf("\n[TC-SVC-006: name with '.service' suffix — rejected at protocol layer]\n");
    req = make_restart_req(APDU_SEC_SIGNED, "nginx.service", 13,
                           data_buf, (int)sizeof(data_buf));
    n = handler_svc_restart(&req, resp, sizeof(resp), TEST_SESSION_ID);
    EXPECT("\"nginx.service\" → 0x6A80 (Wrong Data)",
           n == 2 && get_u16(resp) == 0x6A80);

    /* ── TC-SVC-007: name exactly 64 bytes ──────────────── */
    printf("\n[TC-SVC-007: max-length name (64 bytes)]\n");
    char name64[64];
    memset(name64, 'a', 64);   /* 64 × 'a' — all valid */
    req = make_restart_req(APDU_SEC_SIGNED, name64, 64,
                           data_buf, (int)sizeof(data_buf));
    n = handler_svc_restart(&req, resp, sizeof(resp), TEST_SESSION_ID);
    EXPECT("64-byte name → 0x9000 (handle valid)",
           n == 6 && get_u16(resp + 4) == 0x9000 && get_u32(resp) != 0);
    reap_children();
    task_pool_init();

    /* ── TC-SVC-008: name 65 bytes → rejected ────────────── */
    printf("\n[TC-SVC-008: name too long (65 bytes)]\n");
    char name65[65];
    memset(name65, 'a', 65);
    req = make_restart_req(APDU_SEC_SIGNED, name65, 65,
                           data_buf, (int)sizeof(data_buf));
    n = handler_svc_restart(&req, resp, sizeof(resp), TEST_SESSION_ID);
    EXPECT("65-byte name → 0x6A80 (Wrong Data)",
           n == 2 && get_u16(resp) == 0x6A80);

    /* ── TC-SVC-009: idempotency ─────────────────────────── */
    printf("\n[TC-SVC-009: idempotency — return existing Pending handle]\n");
    task_pool_init();
    /* Pre-populate a PENDING slot for session=1, svc="nginx" directly, so the
     * handler finds it without forking a new child. */
    uint32_t pre_handle = task_pool_alloc(1, "nginx", 0);
    EXPECT("pre-alloc handle non-zero", pre_handle != 0);

    req = make_restart_req(APDU_SEC_SIGNED, "nginx", 5,
                           data_buf, (int)sizeof(data_buf));
    n = handler_svc_restart(&req, resp, sizeof(resp), TEST_SESSION_ID);
    EXPECT("idempotent call → 0x9000",
           n == 6 && get_u16(resp + 4) == 0x9000);
    EXPECT("returned handle == pre-existing Pending handle",
           get_u32(resp) == pre_handle);
    task_pool_free(pre_handle);

    /* ── TC-SVC-010: pool full → 0x6400, no fork ─────────── */
    printf("\n[TC-SVC-010: pool full → SW_BLOCKED, no fork]\n");
    task_pool_init();
    /* Fill all 64 slots */
    uint32_t fill_handles[TASK_POOL_SIZE];
    for (int i = 0; i < TASK_POOL_SIZE; i++) {
        char svc[16];
        snprintf(svc, sizeof(svc), "svc%d", i);
        fill_handles[i] = task_pool_alloc((uint16_t)(i + 1), svc, (pid_t)(2000 + i));
    }
    EXPECT("pool filled (available() == 0)", task_pool_available() == 0);

    req = make_restart_req(APDU_SEC_SIGNED, "nginx", 5,
                           data_buf, (int)sizeof(data_buf));
    n = handler_svc_restart(&req, resp, sizeof(resp), TEST_SESSION_ID);
    EXPECT("pool full → 0x6400 (Blocked)",
           n == 2 && get_u16(resp) == 0x6400);
    /* clean up */
    for (int i = 0; i < TASK_POOL_SIZE; i++)
        task_pool_free(fill_handles[i]);

    /* ── Summary ─────────────────────────────────────────── */
    printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    if (g_fail == 0)
        printf("ALL TESTS PASSED — SVC_RESTART handler functional\n");
    else
        printf("SOME TESTS FAILED — check output above\n");

    return g_fail ? 1 : 0;
}
