/*
 * test_handlers.c — Core ISA Handler & Dispatcher Conformance Tests
 *
 * Tests:
 *   Dispatcher
 *     1.  Unknown INS → SW 0x6A81
 *     2.  INS in bitmap, no handler (phase-1 stub) → SW 0x6D00
 *   SYS_CAPS (0x00)
 *     3.  Response is exactly 36 bytes
 *     4.  SW bytes [34-35] = 0x9000
 *     5.  Core bitmap [0-3] has bits 0-3 set (SYS_CAPS/HELLO/STATUS/PROCS)
 *     6.  Protocol version [8-9] = 0x0100
 *     7.  Kernel hash [10-13] non-zero (version parsed)
 *     8.  CPU_Static [14-15] (ncpus) > 0
 *     9.  Memory_Static [18-21] (RAM MB) > 0
 *     10. Storage_Static [26-29] (root MB) > 0
 *     11. RPI_Type [32] is 0x01 or 0x02
 *     12. Reserved byte [33] = 0x00
 *   SYS_HELLO (0x01)
 *     13. Response is exactly 18 bytes
 *     14. SW [16-17] = 0x9000
 *     15. Magic [0-3] = 0x41535953 ("ASYS")
 *     16. Timestamp [8-15] > 0
 *   SYS_STATUS (0x02)
 *     17. Response is exactly 23 bytes
 *     18. SW [21-22] = 0x9000
 *     19. RPI [16] is 0x00-0x64 or 0xFF
 *     20. Second call returns immediately (cached, < 200ms)
 *   SYS_PROCS (0x03)
 *     21. Response is exactly 44 bytes
 *     22. SW [42-43] = 0x9000
 *     23. Total_Procs [0-1] > 0
 *     24. First slot PID > 0 (at least one process found)
 *     25. First slot CPU_Usage <= 10000 (delta may be 0 on idle systems)
 *
 * Build (from tests/conformance/):
 *   gcc -O2 -Wall \
 *       test_handlers.c \
 *       ../../src/asyd/core/apdu_parser.c \
 *       ../../src/asyd/core/dispatcher.c \
 *       ../../src/asyd/handlers/sys_caps.c \
 *       ../../src/asyd/handlers/sys_hello.c \
 *       ../../src/asyd/handlers/sys_status.c \
 *       ../../src/asyd/handlers/sys_procs.c \
 *       -I../../src/asyd/core \
 *       -o test_handlers
 * Run:
 *   ./test_handlers
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include "apdu_parser.h"
#include "dispatcher.h"
#include "task_pool.h"

/* ── Test harness ──────────────────────────────────────── */
static int g_pass = 0, g_fail = 0;

#define EXPECT(label, expr) do {                                   \
    if (expr) { printf("  PASS  %s\n", (label)); g_pass++; }       \
    else      { printf("  FAIL  %s (line %d)\n", (label), __LINE__); g_fail++; } \
} while(0)

/* ── Helpers ───────────────────────────────────────────── */
static uint16_t get_u16(const uint8_t *b) { return ((uint16_t)b[0]<<8)|b[1]; }
static uint32_t get_u32(const uint8_t *b)
{
    return ((uint32_t)b[0]<<24)|((uint32_t)b[1]<<16)|
           ((uint32_t)b[2]<< 8)|b[3];
}
static uint64_t get_u64(const uint8_t *b)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | b[i];
    return v;
}

/* Build a minimal APDU request frame for testing */
static ApduFrame make_req(uint8_t ins)
{
    ApduFrame f;
    memset(&f, 0, sizeof(f));
    f.cla = 0x00;
    f.ins = ins;
    return f;
}

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000);
}

/* ── Main ──────────────────────────────────────────────── */
int main(void)
{
    printf("=== ASys Core ISA Handler Conformance Test ===\n\n");

    task_pool_init();

    uint8_t    resp[DISP_RESP_MAX];
    ApduFrame  req;
    int        n;

    /* ── Dispatcher ─────────────────────────────────────── */
    printf("[Dispatcher]\n");

    /* 1. Unknown INS → 0x6A81 */
    req = make_req(0xEE);
    n = dispatch(&req, resp, sizeof(resp), 0);
    EXPECT("unknown INS → 0x6A81", n == 2 && get_u16(resp) == 0x6A81);

    /* 2. Unimplemented Core slot (INS=0x04, in bitmap? No — bitmap only has 0-3)
     *    → 0x6A81 (not found in bitmap) */
    req = make_req(0x04);
    n = dispatch(&req, resp, sizeof(resp), 0);
    EXPECT("INS=0x04 not in bitmap → 0x6A81", n == 2 && get_u16(resp) == 0x6A81);

    /* ── SYS_CAPS ────────────────────────────────────────── */
    printf("\n[SYS_CAPS 0x00]\n");

    req = make_req(0x00);
    n = dispatch(&req, resp, sizeof(resp), 0);

    EXPECT("response length = 36",          n == 36);
    EXPECT("SW [34-35] = 0x9000",           get_u16(resp+34) == 0x9000);
    EXPECT("core bitmap has bits 0-3 set",  (get_u32(resp+0) & 0xF) == 0xF);
    EXPECT("protocol version = 0x0100",     get_u16(resp+8) == 0x0100);
    EXPECT("kernel hash [10-13] non-zero",  (resp[10]|resp[11]|resp[12]|resp[13]) != 0);
    EXPECT("ncpus [14-15] > 0",             get_u16(resp+14) > 0);
    EXPECT("RAM MB [18-21] > 0",            get_u32(resp+18) > 0);
    EXPECT("root size [26-29] > 0",         get_u32(resp+26) > 0);
    EXPECT("RPI_Type in {0x01,0x02}",       resp[32]==0x01 || resp[32]==0x02);
    EXPECT("reserved byte [33] = 0x00",     resp[33] == 0x00);

    /* ── SYS_HELLO ───────────────────────────────────────── */
    printf("\n[SYS_HELLO 0x01]\n");

    req = make_req(0x01);
    n = dispatch(&req, resp, sizeof(resp), 0);

    EXPECT("response length = 18",          n == 18);
    EXPECT("SW [16-17] = 0x9000",           get_u16(resp+16) == 0x9000);
    EXPECT("magic [0-3] = 'ASYS'",          get_u32(resp+0) == 0x41535953u);
    EXPECT("timestamp [8-15] > 0",          get_u64(resp+8) > 0);

    /* ── SYS_STATUS ──────────────────────────────────────── */
    printf("\n[SYS_STATUS 0x02]\n");

    req = make_req(0x02);
    n = dispatch(&req, resp, sizeof(resp), 0);

    EXPECT("response length = 23",          n == 23);
    EXPECT("SW [21-22] = 0x9000",           get_u16(resp+21) == 0x9000);
    {
        uint8_t rpi = resp[16];
        EXPECT("RPI in {0x00-0x64, 0xFF}",  rpi <= 0x64 || rpi == 0xFF);
    }

    /* Second call: must return quickly (cached) */
    {
        uint64_t t0 = now_ms();
        req = make_req(0x02);
        dispatch(&req, resp, sizeof(resp), 0);
        uint64_t elapsed = now_ms() - t0;
        EXPECT("second call < 200ms (cached)", elapsed < 200);
    }

    /* ── SYS_PROCS ───────────────────────────────────────── */
    printf("\n[SYS_PROCS 0x03]\n");

    req = make_req(0x03);
    n = dispatch(&req, resp, sizeof(resp), 0);

    EXPECT("response length = 44",           n == 44);
    EXPECT("SW [42-43] = 0x9000",            get_u16(resp+42) == 0x9000);
    EXPECT("Total_Procs [0-1] > 0",          get_u16(resp+0) > 0);
    {
        /* First slot starts at byte 2 */
        uint32_t pid = get_u32(resp+2);
        EXPECT("slot[0] PID > 0",            pid > 0);
        uint16_t cpu_x100 = get_u16(resp+6);
        EXPECT("slot[0] CPU_Usage <= 10000", cpu_x100 <= 10000);
    }

    /* ── Summary ─────────────────────────────────────────── */
    printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    if (g_fail == 0)
        printf("ALL TESTS PASSED — Core ISA handlers functional\n");
    else
        printf("SOME TESTS FAILED — check output above\n");

    return g_fail ? 1 : 0;
}
