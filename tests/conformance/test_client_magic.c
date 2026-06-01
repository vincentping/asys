/*
 * Copyright (c) 2026 Vincent Ping (vincentping@gmail.com)
 * SPDX-License-Identifier: Apache-2.0
 */
/*
 * test_client_magic.c — Client-Speak-First Magic conformance tests (v0.3.1)
 *
 * Tests the wait_for_client_magic() contract using socketpair(2) so no
 * running asyd is required.  The helper is reimplemented here verbatim
 * from asyd.c to test the specified behaviour in isolation.
 *
 *   TC-MAG-001: valid Magic (0x41535953) → accepted (returns 0)
 *   TC-MAG-002: invalid Magic (0xDEADBEEF) → rejected (returns -1)
 *   TC-MAG-003: no data sent → timeout after ~1 s (returns -1)
 *
 * Build (from project root):
 *   make tests && tests/conformance/test_client_magic
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <pthread.h>

/* ── Test harness ─────────────────────────────────────────── */
static int g_pass = 0, g_fail = 0;

#define EXPECT(label, cond) do { \
    if (cond) { printf("  PASS  %s\n", label); g_pass++; } \
    else       { printf("  FAIL  %s\n", label); g_fail++; } \
} while (0)

/* ── wait_for_client_magic — mirrors asyd.c exactly ─────── */
static ssize_t recv_exact(int fd, uint8_t *buf, size_t n)
{
    size_t got = 0;
    while (got < n) {
        ssize_t r = recv(fd, buf + got, n - got, 0);
        if (r <= 0) return r;
        got += (size_t)r;
    }
    return (ssize_t)got;
}

static int wait_for_client_magic(int fd)
{
    struct timeval tv1 = { .tv_sec = 1, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv1, sizeof(tv1));

    uint8_t buf[4];
    if (recv_exact(fd, buf, 4) != 4)
        return -1;

    uint32_t magic = ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16)
                   | ((uint32_t)buf[2] <<  8) |  (uint32_t)buf[3];
    return (magic == 0x41535953U) ? 0 : -1;
}

/* ── Helpers ─────────────────────────────────────────────── */

/* Send 4-byte big-endian uint32 to fd. Used by client-side of socketpair. */
static void send_magic(int fd, uint32_t val)
{
    uint8_t buf[4] = {
        (uint8_t)(val >> 24), (uint8_t)(val >> 16),
        (uint8_t)(val >>  8), (uint8_t)(val      )
    };
    send(fd, buf, 4, 0);
}

/* Returns monotonic milliseconds. */
static long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

/* ── Tests ───────────────────────────────────────────────── */

/*
 * TC-MAG-001: client sends correct Magic → wait_for_client_magic returns 0.
 */
static void tc_mag_001(void)
{
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        printf("  SKIP  TC-MAG-001: socketpair failed\n");
        return;
    }
    send_magic(sv[1], 0x41535953U);   /* client side */
    int rc = wait_for_client_magic(sv[0]);   /* server side */
    close(sv[0]); close(sv[1]);
    EXPECT("TC-MAG-001: valid magic accepted", rc == 0);
}

/*
 * TC-MAG-002: client sends wrong Magic → wait_for_client_magic returns -1.
 */
static void tc_mag_002(void)
{
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        printf("  SKIP  TC-MAG-002: socketpair failed\n");
        return;
    }
    send_magic(sv[1], 0xDEADBEEFU);   /* wrong magic */
    int rc = wait_for_client_magic(sv[0]);
    close(sv[0]); close(sv[1]);
    EXPECT("TC-MAG-002: invalid magic rejected", rc == -1);
}

/*
 * TC-MAG-003: client sends nothing → server times out in ~1 s, returns -1.
 * Validates both the return value and that the timeout is ≥900 ms and <3 s.
 */
static void tc_mag_003(void)
{
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        printf("  SKIP  TC-MAG-003: socketpair failed\n");
        return;
    }
    /* sv[1] (client side) left idle — nothing sent */
    long t0 = now_ms();
    int rc = wait_for_client_magic(sv[0]);
    long elapsed = now_ms() - t0;
    close(sv[0]); close(sv[1]);

    EXPECT("TC-MAG-003: no magic → rejected",  rc == -1);
    EXPECT("TC-MAG-003: timeout ≥ 900 ms",     elapsed >= 900);
    EXPECT("TC-MAG-003: timeout < 3000 ms",    elapsed < 3000);
}

/* ── main ────────────────────────────────────────────────── */
int main(void)
{
    printf("=== ASys Client-Speak-First Magic Tests ===\n\n");
    printf("(TC-MAG-003 waits ~1 s for timeout — expected)\n\n");

    tc_mag_001();
    tc_mag_002();
    tc_mag_003();

    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
