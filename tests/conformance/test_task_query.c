/*
 * test_task_query.c — TASK_QUERY (0x11) Handler Conformance Tests
 *
 * Tests:
 *   TC-QUERY-001: Lc < 4 → 0x6700
 *   TC-QUERY-002: handle not found → Status=0xFF, SW=0x9000
 *   TC-QUERY-003: cross-session query → Status=0xFF (no info leak)
 *   TC-QUERY-004: Pending state → Status=0x00, handle not released
 *   TC-QUERY-005: Success state → Status=0x01, handle released
 *   TC-QUERY-006: Failed state → Status=0x02, handle released
 *   TC-QUERY-007: Timeout state → Status=0x03, handle released
 *   TC-QUERY-008: sweep_timeouts triggered inside handler → Status=0x03
 *
 * Build (from tests/conformance/):
 *   gcc -O2 -Wall \
 *       test_task_query.c \
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
 *       -o test_task_query
 * Run:
 *   ./test_task_query
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include "apdu_parser.h"
#include "dispatcher.h"
#include "task_pool.h"

static int g_pass = 0, g_fail = 0;

#define EXPECT(label, expr) do {                                            \
    if (expr) { printf("  PASS  %s\n", (label)); g_pass++; }               \
    else      { printf("  FAIL  %s (line %d)\n", (label), __LINE__); g_fail++; } \
} while(0)

static uint16_t get_u16(const uint8_t *b) { return ((uint16_t)b[0] << 8) | b[1]; }

int handler_task_query(const ApduFrame *req, uint8_t *resp, size_t sz, uint16_t session_id);

/*
 * Build a TASK_QUERY ApduFrame with the given 32-bit handle.
 */
static ApduFrame make_query_req(uint32_t handle, uint8_t data_buf[4])
{
    ApduFrame f;
    memset(&f, 0, sizeof(f));
    f.cla      = 0x00;   /* Plain — TASK_QUERY does not require Signed */
    f.ins      = 0x11;
    f.sec      = APDU_SEC_PLAIN;
    data_buf[0] = (uint8_t)(handle >> 24);
    data_buf[1] = (uint8_t)(handle >> 16);
    data_buf[2] = (uint8_t)(handle >>  8);
    data_buf[3] = (uint8_t)(handle & 0xFF);
    f.data     = data_buf;
    f.data_len = 4;
    return f;
}

int main(void)
{
    printf("=== ASys TASK_QUERY Conformance Test ===\n\n");

    task_pool_init();

    uint8_t   resp[DISP_RESP_MAX];
    uint8_t   data_buf[4];
    ApduFrame req;
    int       n;
    uint32_t  handle;
    TaskEntry *e;

    /* ── TC-QUERY-001: Lc < 4 ────────────────────────────── */
    printf("[TC-QUERY-001: Lc < 4]\n");
    req = make_query_req(0x00001234, data_buf);
    req.data_len = 2;   /* too short */
    n = handler_task_query(&req, resp, sizeof(resp), 1);
    EXPECT("Lc=2 → 0x6700 (Wrong Length)",
           n == 2 && get_u16(resp) == 0x6700);

    /* ── TC-QUERY-002: handle not found ──────────────────── */
    printf("\n[TC-QUERY-002: handle not found]\n");
    task_pool_init();
    req = make_query_req(0x00001234, data_buf);
    n = handler_task_query(&req, resp, sizeof(resp), 1);
    EXPECT("unknown handle → Status=0xFF, SW=0x9000",
           n == 3 && resp[0] == 0xFF && get_u16(resp + 1) == 0x9000);

    /* ── TC-QUERY-003: cross-session query ───────────────── */
    printf("\n[TC-QUERY-003: cross-session query]\n");
    task_pool_init();
    handle = task_pool_alloc(1, "nginx", 100);   /* session=1 */
    req = make_query_req(handle, data_buf);
    n = handler_task_query(&req, resp, sizeof(resp), 2);  /* query as session=2 */
    EXPECT("cross-session → Status=0xFF (no info leak)",
           n == 3 && resp[0] == 0xFF && get_u16(resp + 1) == 0x9000);
    task_pool_free(handle);

    /* ── TC-QUERY-004: Pending state ─────────────────────── */
    printf("\n[TC-QUERY-004: Pending state — handle not released]\n");
    task_pool_init();
    handle = task_pool_alloc(1, "nginx", 100);
    /* task stays TASK_PENDING (no update_by_pid called) */
    req = make_query_req(handle, data_buf);
    n = handler_task_query(&req, resp, sizeof(resp), 1);
    EXPECT("Pending → Status=0x00, SW=0x9000",
           n == 3 && resp[0] == 0x00 && get_u16(resp + 1) == 0x9000);
    EXPECT("Pending handle not released (still findable)",
           task_pool_find_handle(handle, 1) != NULL);
    task_pool_free(handle);

    /* ── TC-QUERY-005: Success state ─────────────────────── */
    printf("\n[TC-QUERY-005: Success state — handle released]\n");
    task_pool_init();
    handle = task_pool_alloc(1, "nginx", 100);
    e = task_pool_find_handle(handle, 1);
    if (e) e->status = TASK_SUCCESS;
    req = make_query_req(handle, data_buf);
    n = handler_task_query(&req, resp, sizeof(resp), 1);
    EXPECT("Success → Status=0x01, SW=0x9000",
           n == 3 && resp[0] == 0x01 && get_u16(resp + 1) == 0x9000);
    EXPECT("Success handle released (no longer findable)",
           task_pool_find_handle(handle, 1) == NULL);

    /* ── TC-QUERY-006: Failed state ──────────────────────── */
    printf("\n[TC-QUERY-006: Failed state — handle released]\n");
    task_pool_init();
    handle = task_pool_alloc(1, "redis", 200);
    e = task_pool_find_handle(handle, 1);
    if (e) e->status = TASK_FAILED;
    req = make_query_req(handle, data_buf);
    n = handler_task_query(&req, resp, sizeof(resp), 1);
    EXPECT("Failed → Status=0x02, SW=0x9000",
           n == 3 && resp[0] == 0x02 && get_u16(resp + 1) == 0x9000);
    EXPECT("Failed handle released",
           task_pool_find_handle(handle, 1) == NULL);

    /* ── TC-QUERY-007: Timeout state ─────────────────────── */
    printf("\n[TC-QUERY-007: Timeout state — handle released]\n");
    task_pool_init();
    handle = task_pool_alloc(1, "mysql", 300);
    e = task_pool_find_handle(handle, 1);
    if (e) e->status = TASK_TIMEOUT;
    req = make_query_req(handle, data_buf);
    n = handler_task_query(&req, resp, sizeof(resp), 1);
    EXPECT("Timeout → Status=0x03, SW=0x9000",
           n == 3 && resp[0] == 0x03 && get_u16(resp + 1) == 0x9000);
    EXPECT("Timeout handle released",
           task_pool_find_handle(handle, 1) == NULL);

    /* ── TC-QUERY-008: sweep_timeouts triggered inside handler */
    printf("\n[TC-QUERY-008: sweep triggered by handler call]\n");
    task_pool_init();
    handle = task_pool_alloc(1, "nginx", 400);
    e = task_pool_find_handle(handle, 1);
    EXPECT("entry found", e != NULL);
    if (e) {
        /* backdate to force timeout on next sweep */
        e->created_at = time(NULL) - (TASK_TIMEOUT_SEC + 1);
        req = make_query_req(handle, data_buf);
        n = handler_task_query(&req, resp, sizeof(resp), 1);
        /* handler calls task_pool_sweep_timeouts() before lookup */
        EXPECT("sweep-triggered timeout → Status=0x03",
               n == 3 && resp[0] == 0x03 && get_u16(resp + 1) == 0x9000);
        EXPECT("handle released after timeout",
               task_pool_find_handle(handle, 1) == NULL);
    }

    /* ── Summary ─────────────────────────────────────────── */
    printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    if (g_fail == 0)
        printf("ALL TESTS PASSED — TASK_QUERY handler functional\n");
    else
        printf("SOME TESTS FAILED — check output above\n");

    return g_fail ? 1 : 0;
}
