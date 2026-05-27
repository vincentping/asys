/*
 * Copyright (c) 2026 Vincent Ping (vincentping@gmail.com)
 * SPDX-License-Identifier: Apache-2.0
 */
/*
 * dispatcher.c — ASys Instruction Dispatcher
 */

#include "dispatcher.h"

/* Forward declarations of all Core ISA handlers */
int handler_sys_caps      (const ApduFrame *req, uint8_t *resp, size_t sz, uint16_t session_id);
int handler_sys_hello     (const ApduFrame *req, uint8_t *resp, size_t sz, uint16_t session_id);
int handler_sys_status    (const ApduFrame *req, uint8_t *resp, size_t sz, uint16_t session_id);
int handler_sys_procs     (const ApduFrame *req, uint8_t *resp, size_t sz, uint16_t session_id);

/* Forward declarations of Standard ISA handlers (Phase 3) */
int handler_proc_throttle (const ApduFrame *req, uint8_t *resp, size_t sz, uint16_t session_id);
int handler_svc_restart   (const ApduFrame *req, uint8_t *resp, size_t sz, uint16_t session_id);
int handler_task_query    (const ApduFrame *req, uint8_t *resp, size_t sz, uint16_t session_id);

/* ── Core ISA dispatch table (INS 0x00-0x1F) ────────────── */
static const HandlerFn core_table[32] = {
    [0x00] = handler_sys_caps,
    [0x01] = handler_sys_hello,
    [0x02] = handler_sys_status,
    [0x03] = handler_sys_procs,
    [0x11] = handler_task_query,     /* 0x11 TASK_QUERY */
    /* other slots: unimplemented → NULL → 0x6D00 */
};

/* ── Standard ISA dispatch table (INS 0x20-0x2F) ────────── */
static const HandlerFn standard_table[16] = {
    [0x00] = handler_proc_throttle,  /* 0x20 PROC_THROTTLE */
    /* 0x01 NET_ISOLATE — deferred */
    [0x02] = handler_svc_restart,    /* 0x22 SVC_RESTART   */
};

/* ── Capability bitmap helpers ───────────────────────────── */

/*
 * Check whether INS is present in the Phase 2 capability bitmap.
 * Core ISA: INS 0x00-0x0F → check CORE_CAPS_BITMAP bit N.
 * All other ranges: not implemented → not found.
 */
static int in_caps_bitmap(uint8_t ins)
{
    if (ins <= 0x1F)
        return (CORE_CAPS_BITMAP >> ins) & 1u;
    if (ins <= 0x3F)
        return (EXT_CAPS_BITMAP >> (ins - 0x20)) & 1u;
    /*
     * Standard ISA 0x40-0x8F (Diagnostics, Storage, Security, etc.) and
     * Vendor Extensions 0x90-0xFF are not yet registered in Phase 3.
     * Expand this function when new instruction groups are implemented.
     */
    return 0;
}

/* ── dispatch ────────────────────────────────────────────── */

int dispatch(const ApduFrame *req, uint8_t *resp_out, size_t resp_size,
             uint16_t session_id)
{
    if (!req || !resp_out || resp_size < 2)
        return sw_write(resp_out, SW_SYS_ERR);

    /* Layer 1: existence check (O(1) bitmap) — spec §1.7 */
    if (!in_caps_bitmap(req->ins))
        return sw_write(resp_out, SW_NOT_FOUND);

    /* Layer 2: permission check — Phase 2 always grants Core ISA */
    /* (Full Capability Map integration in Phase 3) */

    /* Layer 3: handler dispatch */
    HandlerFn fn = NULL;
    if (req->ins <= 0x1F)
        fn = core_table[req->ins];
    else if (req->ins <= 0x2F)
        fn = standard_table[req->ins - 0x20];

    if (!fn) {
        /*
         * Instruction is in the capability bitmap but has no handler yet.
         * Per spec §1.6: platform lacks execution capability → 0x6D00.
         */
        return sw_write(resp_out, SW_NOT_SUPPORTED);
    }

    int n = fn(req, resp_out, resp_size, session_id);
    if (n < 0)
        return sw_write(resp_out, SW_SYS_ERR);
    return n;
}
