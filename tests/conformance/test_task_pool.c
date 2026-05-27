/*
 * test_task_pool.c — Task Handle Pool Conformance Tests (Phase 3)
 *
 * Tests:
 *   TC-POOL-001: basic alloc / free cycle
 *   TC-POOL-002: handle ownership isolation across sessions
 *   TC-POOL-003: idempotency — find_pending returns existing handle
 *   TC-POOL-004: find_pending with different svc name returns 0
 *   TC-POOL-005: find_pending with different session returns 0
 *   TC-POOL-006: pool full → alloc returns 0; available() reflects capacity
 *   TC-POOL-007: update_by_pid sets task to TASK_SUCCESS
 *   TC-POOL-008: update_by_pid with unknown pid is a no-op
 *   TC-POOL-009: sweep_timeouts marks expired PENDING as TASK_TIMEOUT
 *   TC-POOL-010: release_session clears only matching session slots
 *   TC-POOL-011: task_pool_free zeroes all slot fields
 *
 * Build (from tests/conformance/):
 *   gcc -O2 -Wall \
 *       test_task_pool.c \
 *       ../../src/asyd/core/task_pool.c \
 *       -I../../src/asyd/core \
 *       -o test_task_pool
 * Run:
 *   ./test_task_pool
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include "task_pool.h"

static int g_pass = 0, g_fail = 0;

#define EXPECT(label, expr) do {                                            \
    if (expr) { printf("  PASS  %s\n", (label)); g_pass++; }               \
    else      { printf("  FAIL  %s (line %d)\n", (label), __LINE__); g_fail++; } \
} while(0)

int main(void)
{
    printf("=== ASys Task Pool Conformance Test ===\n\n");

    uint32_t   handle, handle_A;
    TaskEntry *e;

    /* ── TC-POOL-001: basic alloc / free ──────────────────── */
    printf("[TC-POOL-001: basic alloc / free]\n");
    task_pool_init();

    handle = task_pool_alloc(1, "nginx", 100);
    EXPECT("alloc returns non-zero handle",    handle != 0);
    EXPECT("high 16 bits == session_id (1)",   (handle >> 16) == 1);
    EXPECT("low 16 bits non-zero (random)",    (handle & 0xFFFF) != 0);
    EXPECT("find_handle succeeds before free", task_pool_find_handle(handle, 1) != NULL);
    task_pool_free(handle);
    EXPECT("find_handle returns NULL after free",
           task_pool_find_handle(handle, 1) == NULL);

    /* ── TC-POOL-002: ownership isolation ─────────────────── */
    printf("\n[TC-POOL-002: ownership isolation]\n");
    task_pool_init();

    handle = task_pool_alloc(1, "redis", 200);
    EXPECT("alloc session=1 succeeds", handle != 0);
    EXPECT("find_handle session=2 returns NULL (isolation)",
           task_pool_find_handle(handle, 2) == NULL);
    EXPECT("find_handle session=1 succeeds (ownership)",
           task_pool_find_handle(handle, 1) != NULL);
    task_pool_free(handle);

    /* ── TC-POOL-003: idempotency ──────────────────────────── */
    printf("\n[TC-POOL-003: idempotency find_pending]\n");
    task_pool_init();

    handle_A = task_pool_alloc(1, "nginx", 100);
    EXPECT("alloc succeeds", handle_A != 0);
    EXPECT("find_pending same session+svc returns handle_A",
           task_pool_find_pending(1, "nginx") == handle_A);
    task_pool_free(handle_A);

    /* ── TC-POOL-004: different svc name not idempotent ────── */
    printf("\n[TC-POOL-004: different svc name not idempotent]\n");
    task_pool_init();

    handle_A = task_pool_alloc(1, "nginx", 100);
    EXPECT("find_pending different svc returns 0",
           task_pool_find_pending(1, "redis") == 0);
    task_pool_free(handle_A);

    /* ── TC-POOL-005: different session not idempotent ──────── */
    printf("\n[TC-POOL-005: different session not idempotent]\n");
    task_pool_init();

    handle_A = task_pool_alloc(1, "nginx", 100);
    EXPECT("find_pending different session returns 0",
           task_pool_find_pending(2, "nginx") == 0);
    task_pool_free(handle_A);

    /* ── TC-POOL-006: pool full ────────────────────────────── */
    printf("\n[TC-POOL-006: pool full]\n");
    task_pool_init();

    uint32_t handles[TASK_POOL_SIZE];
    for (int i = 0; i < TASK_POOL_SIZE; i++) {
        char svc[16];
        snprintf(svc, sizeof(svc), "svc%d", i);
        handles[i] = task_pool_alloc((uint16_t)(i + 1), svc, (pid_t)(1000 + i));
    }
    EXPECT("all 64 slots allocated",             handles[TASK_POOL_SIZE - 1] != 0);
    EXPECT("available() returns 0 when full",    task_pool_available() == 0);
    EXPECT("65th alloc returns 0 (pool full)",   task_pool_alloc(99, "overflow", 9999) == 0);
    task_pool_free(handles[0]);
    EXPECT("available() returns 1 after free",   task_pool_available() == 1);
    /* clean up remaining slots */
    for (int i = 1; i < TASK_POOL_SIZE; i++)
        task_pool_free(handles[i]);

    /* ── TC-POOL-007: update_by_pid sets TASK_SUCCESS ───────── */
    printf("\n[TC-POOL-007: update_by_pid]\n");
    task_pool_init();

    handle = task_pool_alloc(1, "nginx", 100);
    task_pool_update_by_pid(100, TASK_SUCCESS);
    e = task_pool_find_handle(handle, 1);
    EXPECT("entry found after update",               e != NULL);
    EXPECT("status == TASK_SUCCESS after update_by_pid",
           e != NULL && e->status == TASK_SUCCESS);
    task_pool_free(handle);

    /* ── TC-POOL-008: update_by_pid unknown pid is no-op ────── */
    printf("\n[TC-POOL-008: update_by_pid unknown pid]\n");
    task_pool_init();

    handle = task_pool_alloc(1, "nginx", 100);
    task_pool_update_by_pid(99999, TASK_SUCCESS);   /* wrong pid */
    e = task_pool_find_handle(handle, 1);
    EXPECT("status still TASK_PENDING after wrong pid update",
           e != NULL && e->status == TASK_PENDING);
    task_pool_free(handle);

    /* ── TC-POOL-009: sweep_timeouts ───────────────────────── */
    printf("\n[TC-POOL-009: sweep_timeouts]\n");
    task_pool_init();

    handle = task_pool_alloc(1, "nginx", 100);
    e = task_pool_find_handle(handle, 1);
    EXPECT("entry found", e != NULL);
    if (e) {
        /* backdate created_at past the timeout threshold */
        e->created_at = time(NULL) - (TASK_TIMEOUT_SEC + 1);
        task_pool_sweep_timeouts();
        EXPECT("status == TASK_TIMEOUT after sweep", e->status == TASK_TIMEOUT);
    }
    task_pool_free(handle);

    /* ── TC-POOL-010: release_session ──────────────────────── */
    printf("\n[TC-POOL-010: release_session]\n");
    task_pool_init();

    uint32_t h1 = task_pool_alloc(1, "nginx", 101);
    uint32_t h2 = task_pool_alloc(1, "redis", 102);
    uint32_t h3 = task_pool_alloc(1, "mysql", 103);
    uint32_t h4 = task_pool_alloc(2, "nginx", 104);   /* different session */
    task_pool_release_session(1);
    EXPECT("session=1 slot 1 freed",      task_pool_find_handle(h1, 1) == NULL);
    EXPECT("session=1 slot 2 freed",      task_pool_find_handle(h2, 1) == NULL);
    EXPECT("session=1 slot 3 freed",      task_pool_find_handle(h3, 1) == NULL);
    EXPECT("session=2 slot unaffected",   task_pool_find_handle(h4, 2) != NULL);
    task_pool_free(h4);

    /* ── TC-POOL-011: task_pool_free zeroes all fields ──────── */
    printf("\n[TC-POOL-011: free zeroes fields]\n");
    task_pool_init();

    handle = task_pool_alloc(1, "nginx", 100);
    e = task_pool_find_handle(handle, 1);
    EXPECT("entry found before free", e != NULL);
    if (e) {
        /* Keep pointer to the static slot; safe — g_pool is a static array,
         * not heap-allocated.  task_pool_free() memsets the slot to zero. */
        TaskEntry *slot = e;
        task_pool_free(handle);
        EXPECT("handle_id zeroed after free",   slot->handle_id == 0);
        EXPECT("child_pid zeroed after free",   slot->child_pid == 0);
        EXPECT("svc_name[0] zeroed after free", slot->svc_name[0] == '\0');
        EXPECT("status == TASK_EMPTY after free", slot->status == TASK_EMPTY);
    }

    /* ── Summary ─────────────────────────────────────────── */
    printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    if (g_fail == 0)
        printf("ALL TESTS PASSED — task_pool functional\n");
    else
        printf("SOME TESTS FAILED — check output above\n");

    return g_fail ? 1 : 0;
}
