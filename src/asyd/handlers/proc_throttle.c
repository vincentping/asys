/*
 * Copyright (c) 2026 Vincent Ping (vincentping@gmail.com)
 * SPDX-License-Identifier: Apache-2.0
 */
/*
 * proc_throttle.c — 0x20 PROC_THROTTLE Handler
 *
 * Phase 3 implementation: SIGSTOP/SIGCONT  (see asys-design-notes.md ADR-19)
 *
 * Request layout (spec §2.2.1-2.2.2, Standard ISA):
 *
 *   CLA  = 0x04   (Sec=01: instruction signed, Standard ISA)
 *   INS  = 0x20
 *   P1   = 0x00   STOP (throttle)
 *          0x01   CONT (resume)
 *   P2   = 0x00
 *   Lc   = 0x08
 *   Data = [Seq(4B BE)][PID(4B BE)]
 *
 * Response: SW only (2 bytes)
 *
 *   0x9000  Success
 *   0x6700  Wrong Lc (must be 0x08)
 *   0x6982  Access denied (CAP_KILL not held — EPERM)
 *   0x6A80  Invalid target (PID=0, process not found, or bad P1)
 *   0x6F00  Unexpected system error
 *
 * Idempotency: SIGSTOP on an already-stopped process is a no-op at the
 * kernel level; SIGCONT on a running process is likewise harmless.
 * Both operations are therefore idempotent per spec §1.5.2.
 *
 * Seq replay check: enforced in asyd.c before dispatch (spec §2.2.4).
 */

#include "../core/dispatcher.h"

#include <signal.h>
#include <errno.h>
#include <stdint.h>

/* Data layout offsets within req->data */
#define OFF_SEQ  0   /* [0-3] Seq uint32 BE  */
#define OFF_PID  4   /* [4-7] PID uint32 BE  */
#define PROC_THROTTLE_DATA_LEN  8

int handler_proc_throttle(const ApduFrame *req, uint8_t *resp, size_t sz, uint16_t session_id)
{
    (void)sz;
    (void)session_id;

    /* Standard ISA requires CLA.Sec=01 */
    if (req->sec != APDU_SEC_SIGNED)
        return sw_write(resp, SW_ACCESS_DENIED);

    if (req->data_len < PROC_THROTTLE_DATA_LEN)
        return sw_write(resp, SW_WRONG_LEN);

    /* P1: 0x00=STOP, 0x01=CONT — any other value is invalid */
    if (req->p1 != 0x00 && req->p1 != 0x01)
        return sw_write(resp, SW_WRONG_DATA);

    /* Extract PID; data[0-3] is Seq (verified by dispatcher) */
    uint32_t pid = ((uint32_t)req->data[OFF_PID + 0] << 24) |
                   ((uint32_t)req->data[OFF_PID + 1] << 16) |
                   ((uint32_t)req->data[OFF_PID + 2] <<  8) |
                    (uint32_t)req->data[OFF_PID + 3];

    if (pid == 0)
        return sw_write(resp, SW_WRONG_DATA);

    int sig = (req->p1 == 0x01) ? SIGCONT : SIGSTOP;

    if (kill((pid_t)pid, sig) != 0) {
        if (errno == ESRCH || errno == EINVAL)
            return sw_write(resp, SW_WRONG_DATA);    /* process not found  */
        if (errno == EPERM)
            return sw_write(resp, SW_ACCESS_DENIED); /* no CAP_KILL        */
        return sw_write(resp, SW_SYS_ERR);
    }

    return sw_write(resp, SW_OK);
}
