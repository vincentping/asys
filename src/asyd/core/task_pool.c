/*
 * Copyright (c) 2026 Vincent Ping (vincentping@gmail.com)
 * SPDX-License-Identifier: Apache-2.0
 */
/*
 * task_pool.c — Async Task Handle Pool Implementation
 */

#include "task_pool.h"

#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

static TaskEntry    g_pool[TASK_POOL_SIZE];
static unsigned int g_rand_seed;

void task_pool_init(void)
{
    memset(g_pool, 0, sizeof(g_pool));
    g_rand_seed = (unsigned int)((unsigned long)time(NULL) ^ (unsigned long)getpid());
}

int task_pool_available(void)
{
    for (int i = 0; i < TASK_POOL_SIZE; i++) {
        if (g_pool[i].status == TASK_EMPTY) return 1;
    }
    return 0;
}

uint32_t task_pool_alloc(uint16_t session_id, const char *svc_name, pid_t child_pid)
{
    for (int i = 0; i < TASK_POOL_SIZE; i++) {
        if (g_pool[i].status == TASK_EMPTY) {
            uint16_t rnd = (uint16_t)(rand_r(&g_rand_seed) & 0xFFFF);
            if (rnd == 0) rnd = 1;  /* 0 is reserved as "not found" sentinel */

            g_pool[i].handle_id  = ((uint32_t)session_id << 16) | rnd;
            g_pool[i].session_id = session_id;
            g_pool[i].child_pid  = child_pid;
            g_pool[i].status     = TASK_PENDING;
            g_pool[i].created_at = time(NULL);
            strncpy(g_pool[i].svc_name, svc_name, TASK_SVC_NAME_MAX);
            g_pool[i].svc_name[TASK_SVC_NAME_MAX] = '\0';
            return g_pool[i].handle_id;
        }
    }
    return 0;  /* pool full */
}

uint32_t task_pool_find_pending(uint16_t session_id, const char *svc_name)
{
    for (int i = 0; i < TASK_POOL_SIZE; i++) {
        if (g_pool[i].status == TASK_PENDING &&
            g_pool[i].session_id == session_id &&
            strcmp(g_pool[i].svc_name, svc_name) == 0) {
            return g_pool[i].handle_id;
        }
    }
    return 0;
}

TaskEntry *task_pool_find_handle(uint32_t handle_id, uint16_t session_id)
{
    if (handle_id == 0) return NULL;

    /* Ownership check via Session_ID embedded in high 16 bits */
    uint16_t sid = (uint16_t)(handle_id >> 16);
    if (sid != session_id) return NULL;

    for (int i = 0; i < TASK_POOL_SIZE; i++) {
        if (g_pool[i].handle_id == handle_id &&
            g_pool[i].status != TASK_EMPTY) {
            return &g_pool[i];
        }
    }
    return NULL;
}

void task_pool_free(uint32_t handle_id)
{
    for (int i = 0; i < TASK_POOL_SIZE; i++) {
        if (g_pool[i].handle_id == handle_id) {
            memset(&g_pool[i], 0, sizeof(TaskEntry));
            return;
        }
    }
}

/* Called from SIGCHLD handler — only async-signal-safe ops used */
void task_pool_update_by_pid(pid_t pid, TaskStatus new_status)
{
    for (int i = 0; i < TASK_POOL_SIZE; i++) {
        if (g_pool[i].child_pid == pid &&
            g_pool[i].status == TASK_PENDING) {
            g_pool[i].status = new_status;
            return;
        }
    }
}

void task_pool_release_session(uint16_t session_id)
{
    /*
     * Release all task slots owned by this session.
     *
     * Note: any child processes (systemctl) already forked will continue
     * running independently. When they exit, SIGCHLD fires and
     * task_pool_update_by_pid() will find no matching slot (already EMPTY)
     * and silently ignore the update. This is intentional — per spec §1.4.3,
     * disconnecting only means abandoning the result, not cancelling the
     * underlying operation.
     */
    for (int i = 0; i < TASK_POOL_SIZE; i++) {
        if (g_pool[i].session_id == session_id &&
            g_pool[i].status != TASK_EMPTY) {
            memset(&g_pool[i], 0, sizeof(TaskEntry));
        }
    }
}

void task_pool_sweep_timeouts(void)
{
    time_t now = time(NULL);
    for (int i = 0; i < TASK_POOL_SIZE; i++) {
        if (g_pool[i].status == TASK_EMPTY)
            continue;
        if (now - g_pool[i].created_at <= TASK_TIMEOUT_SEC)
            continue;

        if (g_pool[i].status == TASK_PENDING) {
            /* Pending past TTL → mark Timeout so next TASK_QUERY returns 0x03 */
            g_pool[i].status = TASK_TIMEOUT;
        } else {
            /* Terminal state past TTL → free slot (agent abandoned the result) */
            memset(&g_pool[i], 0, sizeof(TaskEntry));
        }
    }
}
