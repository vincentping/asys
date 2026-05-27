/*
 * Copyright (c) 2026 Vincent Ping (vincentping@gmail.com)
 * SPDX-License-Identifier: Apache-2.0
 */
/*
 * task_query.c — 0x11 TASK_QUERY Handler
 *
 * Protocol Control instruction — CLA=0x00 (no signature required).
 * Agent polls this with a Task_Handle received from an async instruction
 * (e.g. SVC_RESTART) to retrieve the final execution result.
 *
 * Request layout (spec §1.4.2):
 *
 *   CLA  = 0x00   (Plain, no signature)
 *   INS  = 0x11
 *   P1   = 0x00   reserved
 *   P2   = 0x00   reserved
 *   Lc   = 0x04
 *   Data = [Task_Handle(4B BE)]
 *
 * Response (3 bytes):
 *   [Status(1B)][SW=0x9000]
 *
 * Status byte values:
 *   0x00  Pending    — task still running, poll again later
 *   0x01  Success    — completed successfully, Handle released
 *   0x02  Failed     — systemctl returned non-zero, Handle released
 *   0x03  Timeout    — 30s elapsed without child exit, Handle released
 *   0x04  Cancelled  — reserved for TASK_CANCEL (0x12)
 *   0xFF  Not Found  — handle invalid, expired, or wrong session
 *
 * Security: ownership check via Session_ID in high 16 bits of Handle.
 * Cross-session queries always return 0xFF without leaking task info.
 *
 * Handle lifecycle: released immediately on any terminal state
 * (Success / Failed / Timeout / Cancelled).
 */

#include "../core/dispatcher.h"
#include "../core/task_pool.h"

#include <stdint.h>

/* Wire status byte values per spec §1.4.2 */
#define QSTATUS_PENDING   0x00u
#define QSTATUS_SUCCESS   0x01u
#define QSTATUS_FAILED    0x02u
#define QSTATUS_TIMEOUT   0x03u
#define QSTATUS_CANCELLED 0x04u
#define QSTATUS_NOT_FOUND 0xFFu

static uint8_t to_wire(TaskStatus s)
{
    switch (s) {
        case TASK_PENDING:   return QSTATUS_PENDING;
        case TASK_SUCCESS:   return QSTATUS_SUCCESS;
        case TASK_FAILED:    return QSTATUS_FAILED;
        case TASK_TIMEOUT:   return QSTATUS_TIMEOUT;
        case TASK_CANCELLED: return QSTATUS_CANCELLED;
        default:             return QSTATUS_NOT_FOUND;
    }
}

int handler_task_query(const ApduFrame *req, uint8_t *resp, size_t sz, uint16_t session_id)
{
    (void)sz;

    if (req->data_len < 4)
        return sw_write(resp, SW_WRONG_LEN);

    uint32_t handle = ((uint32_t)req->data[0] << 24) |
                      ((uint32_t)req->data[1] << 16) |
                      ((uint32_t)req->data[2] <<  8) |
                       (uint32_t)req->data[3];

    task_pool_sweep_timeouts();

    TaskEntry *e = task_pool_find_handle(handle, session_id);
    if (!e) {
        resp[0] = QSTATUS_NOT_FOUND;
        return sw_write(resp + 1, SW_OK) + 1;
    }

    uint8_t wire = to_wire(e->status);
    resp[0] = wire;

    /* Release handle on any terminal state */
    if (e->status != TASK_PENDING)
        task_pool_free(handle);

    return sw_write(resp + 1, SW_OK) + 1;
}
