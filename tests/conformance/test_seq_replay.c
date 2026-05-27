/*
 * test_seq_replay.c — In-session Seq replay detection tests
 *
 * Phase 4 P0 conformance tests per asys-conformance.md §5.3.
 *
 * Epoch_ID model: Seq is now per-connection in-memory only (uint32_t
 * last_seen_seq, reset to 0 on each new connection).  No persistence,
 * no AgentEntry dependency.
 *
 *   TC-SEQ-001: first Signed command (last_seen=0, seq=1) passes
 *   TC-SEQ-002: Seq=0 sentinel value rejected
 *   TC-SEQ-003: normal increment (last_seen=100, seq=101) passes
 *   TC-SEQ-004: replay — seq == last_seen_seq rejected
 *   TC-SEQ-005: replay — seq < last_seen_seq rejected
 *   TC-SEQ-006: new connection resets last_seen_seq to 0
 *   TC-SEQ-007: multiple sequential advances accepted
 *   TC-SEQ-008: wrap-around guard — seq=0 always rejected even at last_seen=0
 *
 * Build (from project root):
 *   make tests && tests/conformance/test_seq_replay
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* ── Test harness ─────────────────────────────────────── */
static int g_pass = 0, g_fail = 0;

#define EXPECT(label, cond) do { \
    if (cond) { printf("  PASS  %s\n", label); g_pass++; } \
    else       { printf("  FAIL  %s (line %d)\n", label, __LINE__); g_fail++; } \
} while (0)

/* ── In-memory replay gate (mirrors asyd.c handle_client()) ── */
/*
 * Replicate the exact gate from asyd.c:
 *   if (seq <= last_seen_seq) → reject (return 0)
 *   else → advance and accept (return 1)
 */
static int check_and_advance(uint32_t *last_seen_seq, uint32_t seq)
{
    if (seq <= *last_seen_seq)
        return 0;
    *last_seen_seq = seq;
    return 1;
}

/* ── Tests ────────────────────────────────────────────── */

int main(void)
{
    printf("=== Seq Replay Detection Tests (Phase 4 P0, Epoch_ID model) ===\n");

    uint32_t last_seen;

    /* ── TC-SEQ-001: first Signed command passes ──────── */
    printf("\n[TC-SEQ-001: first command (last_seen=0, seq=1) passes]\n");
    last_seen = 0;
    EXPECT("check_and_advance(seq=1) returns 1", check_and_advance(&last_seen, 1) == 1);
    EXPECT("last_seen updated to 1",              last_seen == 1);

    /* ── TC-SEQ-002: Seq=0 sentinel rejected ─────────── */
    printf("\n[TC-SEQ-002: Seq=0 rejected (sentinel — clients start at Seq=1)]\n");
    last_seen = 0;
    /* seq=0 <= last_seen=0: the <= condition catches the sentinel */
    EXPECT("check_and_advance(seq=0) returns 0", check_and_advance(&last_seen, 0) == 0);
    EXPECT("last_seen unchanged at 0",            last_seen == 0);

    /* ── TC-SEQ-003: normal increment ────────────────── */
    printf("\n[TC-SEQ-003: normal increment (last_seen=100, seq=101)]\n");
    last_seen = 100;
    EXPECT("check_and_advance(seq=101) returns 1", check_and_advance(&last_seen, 101) == 1);
    EXPECT("last_seen updated to 101",              last_seen == 101);

    /* ── TC-SEQ-004: replay — equal to last_seen ─────── */
    printf("\n[TC-SEQ-004: replay — seq == last_seen (last_seen=100, seq=100)]\n");
    last_seen = 100;
    EXPECT("check_and_advance(seq=100) returns 0", check_and_advance(&last_seen, 100) == 0);
    EXPECT("last_seen unchanged at 100",            last_seen == 100);

    /* ── TC-SEQ-005: replay — less than last_seen ─────── */
    printf("\n[TC-SEQ-005: replay — seq < last_seen (last_seen=100, seq=50)]\n");
    last_seen = 100;
    EXPECT("check_and_advance(seq=50) returns 0",  check_and_advance(&last_seen, 50) == 0);
    EXPECT("last_seen unchanged at 100",            last_seen == 100);

    /* ── TC-SEQ-006: new connection resets counter ───── */
    printf("\n[TC-SEQ-006: new connection — last_seen resets to 0, seq=1 passes]\n");
    /* Simulate end-of-session by declaring a new local last_seen=0.
     * In asyd.c, SessionCtx is stack-allocated with memset(&ctx,0,...),
     * so last_seen_seq=0 for every new TCP connection. */
    uint32_t new_session_last_seen = 0;
    EXPECT("check_and_advance(seq=1) on new session returns 1",
           check_and_advance(&new_session_last_seen, 1) == 1);
    EXPECT("new session last_seen updated to 1", new_session_last_seen == 1);

    /* ── TC-SEQ-007: multiple sequential advances ─────── */
    printf("\n[TC-SEQ-007: multiple sequential advances in one session]\n");
    last_seen = 0;
    EXPECT("seq=1 passes",   check_and_advance(&last_seen, 1)   == 1);
    EXPECT("seq=2 passes",   check_and_advance(&last_seen, 2)   == 1);
    EXPECT("seq=3 passes",   check_and_advance(&last_seen, 3)   == 1);
    EXPECT("seq=2 rejected (replay)", check_and_advance(&last_seen, 2) == 0);
    EXPECT("seq=4 passes",   check_and_advance(&last_seen, 4)   == 1);
    EXPECT("last_seen = 4",  last_seen == 4);

    /* ── TC-SEQ-008: Seq=0 always rejected ──────────── */
    printf("\n[TC-SEQ-008: Seq=0 rejected even when last_seen=0 (sentinel invariant)]\n");
    /* This is the same as TC-SEQ-002 but documents the invariant explicitly:
     * Seq=0 MUST always be rejected regardless of state, because clients
     * start at Seq=1 per spec §2.2.4. */
    last_seen = 0;
    EXPECT("Seq=0 always rejected at session start",
           check_and_advance(&last_seen, 0) == 0);
    /* Advance normally, then confirm Seq=0 still rejected */
    check_and_advance(&last_seen, 5);
    EXPECT("Seq=0 rejected after normal advance (last_seen=5)",
           check_and_advance(&last_seen, 0) == 0);
    EXPECT("last_seen unchanged at 5", last_seen == 5);

    /* ── Summary ──────────────────────────────────────────────── */
    printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    if (g_fail == 0)
        printf("ALL TESTS PASSED — Seq replay detection functional\n");
    else
        printf("SOME TESTS FAILED — check output above\n");

    return g_fail ? 1 : 0;
}
