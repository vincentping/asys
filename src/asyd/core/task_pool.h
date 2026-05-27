/*
 * Copyright (c) 2026 Vincent Ping (vincentping@gmail.com)
 * SPDX-License-Identifier: Apache-2.0
 */
/*
 * task_pool.h — Async Task Handle Pool
 *
 * Shared by svc_restart.c and task_query.c.
 * Static pre-allocation, zero malloc. 64 concurrent task slots.
 *
 * Handle structure: [Session_ID(16bit) | Random(16bit)]
 *   High 16 bits identify the owning session for O(1) ownership check.
 *   Low  16 bits are random to prevent guessing across sessions.
 *
 * Thread / signal safety:
 *   status field is volatile — written from SIGCHLD handler (async-signal-safe
 *   path: only waitpid + integer write), read from main thread under
 *   g_dispatch_lock. Integer-size writes are atomic on x86/arm64.
 */

#ifndef TASK_POOL_H
#define TASK_POOL_H

#include <stdint.h>
#include <sys/types.h>
#include <time.h>

#define TASK_POOL_SIZE    64
#define TASK_SVC_NAME_MAX 64
#define TASK_TIMEOUT_SEC  30

typedef enum {
    TASK_EMPTY     = 0,
    TASK_PENDING   = 1,
    TASK_SUCCESS   = 2,
    TASK_FAILED    = 3,
    TASK_TIMEOUT   = 4,
    TASK_CANCELLED = 5,
} TaskStatus;

typedef struct {
    uint32_t          handle_id;                     /* [Session_ID(16) | Rand(16)] */
    uint16_t          session_id;
    pid_t             child_pid;
    volatile TaskStatus status;
    time_t            created_at;
    char              svc_name[TASK_SVC_NAME_MAX + 1];
} TaskEntry;

/* One-time init: seed RNG, zero pool */
void      task_pool_init(void);

/* Returns 1 if pool has at least one EMPTY slot, 0 if full */
int       task_pool_available(void);

/* Allocate a new slot; returns handle_id, or 0 if pool full */
uint32_t  task_pool_alloc(uint16_t session_id, const char *svc_name, pid_t child_pid);

/* Idempotency: find PENDING task for same session + service; returns 0 if none */
uint32_t  task_pool_find_pending(uint16_t session_id, const char *svc_name);

/* Lookup by handle with ownership check; returns NULL if not found / wrong session */
TaskEntry *task_pool_find_handle(uint32_t handle_id, uint16_t session_id);

/* Release a slot back to the pool */
void      task_pool_free(uint32_t handle_id);

/* Called from SIGCHLD handler: mark task TASK_SUCCESS or TASK_FAILED by child PID */
void      task_pool_update_by_pid(pid_t pid, TaskStatus new_status);

/* Called on session disconnect: release all slots owned by session */
void      task_pool_release_session(uint16_t session_id);

/* Mark timed-out PENDING tasks as TASK_TIMEOUT; call before each TASK_QUERY */
void      task_pool_sweep_timeouts(void);

#endif /* TASK_POOL_H */
