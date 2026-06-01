/*
 * Copyright (c) 2026 Vincent Ping (vincentping@gmail.com)
 * SPDX-License-Identifier: Apache-2.0
 */
/*
 * svc_restart.c — 0x22 SVC_RESTART Handler
 *
 * Phase 3 implementation: fork/exec systemctl (see asys-design-notes.md ADR-20)
 * Execution mode: async — returns Task_Handle(4B) + SW=0x9000 on success.
 * Agent uses TASK_QUERY(0x11) to poll for the final result.
 *
 * Request layout (spec §1.4.1, Standard ISA):
 *
 *   CLA  = 0x04   (Sec=01: signed)
 *   INS  = 0x22
 *   P1   = 0x00   reserved
 *   P2   = 0x00   reserved
 *   Lc   = 4 + N  (Seq(4B) + SvcName(N bytes), auth_tag stripped by parser)
 *   Data = [Seq(4B BE)][SvcName(N bytes)]
 *
 * SvcName constraints:
 *   - charset: [a-z0-9_\-.]
 *   - length:  1–64 bytes
 *   - no ".service" suffix — asyd appends it internally
 *
 * Response (6 bytes):
 *   [Task_Handle(4B BE)][SW=0x9000]
 *
 * Status words:
 *   0x9000  Success (task enqueued)
 *   0x6700  Wrong Lc (< 5: Seq + at least 1 char)
 *   0x6982  CLA.Sec != Signed
 *   0x6A80  SvcName invalid (empty, too long, illegal chars)
 *   0x6400  Task pool full (transient, retry)
 *   0x6F00  fork() failed
 *
 * Idempotency: same session + same SvcName already Pending → return
 * existing Task_Handle without fork()ing again (spec §1.5.2).
 *
 * Seq replay check: not yet enforced in Phase 3.
 * Auth_Tag: placeholder zeros accepted in Phase 3 (validated in Phase 4).
 */

#include "../core/dispatcher.h"
#include "../core/task_pool.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>

#define OFF_SEQ       0   /* [0-3] Seq uint32 BE — skipped in Phase 3 */
#define OFF_SVC_NAME  4   /* [4..] SvcName bytes                       */
#define MIN_DATA_LEN  5   /* Seq(4B) + at least 1 char service name    */

static int svc_name_valid(const char *name, int len)
{
    if (len < 1 || len > TASK_SVC_NAME_MAX) return 0;
    for (int i = 0; i < len; i++) {
        char c = name[i];
        if (!((c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') ||
              c == '_' || c == '-' || c == '.'))
            return 0;
    }
    /* Reject .service suffix — asyd appends it internally */
    if (len > 8 && memcmp(name + len - 8, ".service", 8) == 0)
        return 0;
    return 1;
}

int handler_svc_restart(const ApduFrame *req, uint8_t *resp, size_t sz, uint16_t session_id)
{
    (void)sz;

    if (req->sec != APDU_SEC_SIGNED)
        return sw_write(resp, SW_ACCESS_DENIED);

    if (req->data_len < MIN_DATA_LEN)
        return sw_write(resp, SW_WRONG_LEN);

    int name_len = (int)req->data_len - OFF_SVC_NAME;
    const char *svc_name_ptr = (const char *)(req->data + OFF_SVC_NAME);

    if (!svc_name_valid(svc_name_ptr, name_len))
        return sw_write(resp, SW_WRONG_DATA);

    char name_buf[TASK_SVC_NAME_MAX + 1];
    memcpy(name_buf, svc_name_ptr, (size_t)name_len);
    name_buf[name_len] = '\0';
    (void)name_len;  /* used only for validation and copy above */

    /* Idempotency: reuse existing Pending handle for same session + service */
    task_pool_sweep_timeouts();
    uint32_t handle = task_pool_find_pending(session_id, name_buf);
    if (handle != 0) {
        resp[0] = (uint8_t)(handle >> 24);
        resp[1] = (uint8_t)(handle >> 16);
        resp[2] = (uint8_t)(handle >>  8);
        resp[3] = (uint8_t)(handle & 0xFF);
        return sw_write(resp + 4, SW_OK) + 4;
    }

    /* Check pool capacity BEFORE fork — avoid executing systemctl with no
     * slot to track it, which would make SW_BLOCKED misleading to Agent */
    if (!task_pool_available())
        return sw_write(resp, SW_BLOCKED);

    /* fork/exec systemctl restart <svc_name>.service */
    pid_t pid = fork();
    if (pid < 0) {
        if (errno == ENOMEM)
            return sw_write(resp, SW_SYS_ERR_NOMEM);
        return sw_write(resp, SW_SYS_ERR);
    }

    if (pid == 0) {
        /* child: append ".service" suffix asyd strips at input, exec */
        char svc_full[TASK_SVC_NAME_MAX + 9];  /* max name + ".service\0" */
        snprintf(svc_full, sizeof(svc_full), "%s.service", name_buf);
        execl("/usr/bin/systemctl", "systemctl", "restart", svc_full, (char *)NULL);
        _exit(1);  /* execl failed */
    }

    /* parent: allocate Task_Handle */
    handle = task_pool_alloc(session_id, name_buf, pid);
    if (handle == 0)
        return sw_write(resp, SW_BLOCKED);  /* pool full — child will be reaped by SIGCHLD */

    resp[0] = (uint8_t)(handle >> 24);
    resp[1] = (uint8_t)(handle >> 16);
    resp[2] = (uint8_t)(handle >>  8);
    resp[3] = (uint8_t)(handle & 0xFF);
    return sw_write(resp + 4, SW_OK) + 4;
}
