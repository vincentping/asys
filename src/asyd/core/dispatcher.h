/*
 * Copyright (c) 2026 Vincent Ping (vincentping@gmail.com)
 * SPDX-License-Identifier: Apache-2.0
 */
/*
 * dispatcher.h — ASys Instruction Dispatcher
 *
 * Implements the 3-layer dispatch topology from spec §1.7:
 *   1. Bitmap check  → 0x6A81 if instruction not in capability map
 *   2. Permission check → 0x6982 if access denied (placeholder for Phase 2)
 *   3. Handler dispatch → handler writes full response including SW bytes
 *
 * Phase 2 capability bitmap: Core ISA bits 0-3 (SYS_CAPS / SYS_HELLO /
 * SYS_STATUS / SYS_PROCS). All other slots return 0x6D00 or 0x6A81.
 */

#ifndef DISPATCHER_H
#define DISPATCHER_H

#include <stdint.h>
#include <stddef.h>
#include "apdu_parser.h"

/* ── Status words (spec §1.6) ───────────────────────────── */
#define SW_OK            0x9000u
#define SW_NOT_FOUND     0x6A81u  /* Instruction not in capability map  */
#define SW_ACCESS_DENIED 0x6982u  /* Identity OK, target access denied  */
#define SW_NOT_SUPPORTED 0x6D00u  /* Instruction exists, platform can't */
#define SW_WRONG_DATA    0x6A80u  /* Payload internal data invalid      */
#define SW_WRONG_LEN     0x6700u  /* Wrong Lc/Le length                 */
#define SW_BLOCKED       0x6400u  /* Transient unavailability           */
#define SW_REPLAY_DETECTED 0x6985u /* In-session Seq replay detected      */
#define SW_SYS_ERR       0x6F00u  /* System emergency (low byte = errno)*/

/* Maximum response buffer size (handlers must not exceed this) */
#define DISP_RESP_MAX    256

/* ── Handler type ────────────────────────────────────────── */
/*
 * Each handler writes a complete response (payload + 2-byte SW) into
 * resp_out and returns the total bytes written (always ≥ 2).
 * Returns -1 only on catastrophic internal error (caller sends SW_SYS_ERR).
 * session_id identifies the calling session; handlers that don't need it
 * should suppress the unused-parameter warning with (void)session_id.
 */
typedef int (*HandlerFn)(const ApduFrame *req,
                          uint8_t        *resp_out,
                          size_t          resp_size,
                          uint16_t        session_id);

/* ── Capability bitmap (spec §1.3.1) ─────────────────────── */
/*
 * Core bitmap   (4B, 32 bits): bit N = INS N    (covers 0x00-0x1F)
 * Extended bitmap (4B, 32 bits): bit N = INS 0x20+N (covers 0x20-0x3F)
 *
 * Core Phase 2: bits 0-3 → SYS_CAPS/SYS_HELLO/SYS_STATUS/SYS_PROCS
 * Core Phase 3: bit 17  → TASK_QUERY (0x11)
 * Extended Phase 3: bit 0 → PROC_THROTTLE (0x20)
 *                   bit 2 → SVC_RESTART   (0x22)
 */
#define CORE_CAPS_BITMAP   0x0002000Fu  /* bits 0-3, 17 */
#define EXT_CAPS_BITMAP    0x00000005u  /* bits 0, 2    */

/* ── Public API ─────────────────────────────────────────── */

/*
 * Dispatch an APDU request to the appropriate handler.
 * session_id is forwarded to the handler (used by svc_restart, task_query).
 * Pass 0 for warmup / background calls with no real session.
 *
 * Returns the number of bytes written to resp_out (always ≥ 2).
 * If the handler cannot be found or permission is denied, a 2-byte
 * SW error word is written to resp_out and 2 is returned.
 */
int dispatch(const ApduFrame *req,
             uint8_t         *resp_out,
             size_t           resp_size,
             uint16_t         session_id);

/* Write a 2-byte SW word at buf[0..1]. Returns 2. */
static inline int sw_write(uint8_t *buf, uint16_t sw)
{
    buf[0] = (uint8_t)(sw >> 8);
    buf[1] = (uint8_t)(sw & 0xFF);
    return 2;
}

#endif /* DISPATCHER_H */
