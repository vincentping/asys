/*
 * Copyright (c) 2026 Vincent Ping (vincentping@gmail.com)
 * SPDX-License-Identifier: Apache-2.0
 */
/*
 * whitelist.h — Agent public-key whitelist for ASys
 *
 * Sole trust model: public-key whitelist (spec §2.1).
 * asyd loads /etc/asyd/authorized_agents at startup; after the Noise IK handshake,
 * the agent's static public key is checked against the list. Agents not
 * in the list are rejected with SW=0x6982 and disconnected.
 *
 * File I/O only at startup (whitelist_load). Never in the request path.
 * If /etc/asyd/authorized_agents does not exist, whitelist_load() creates it with
 * format comments so the administrator knows what to add.
 *
 * To register an agent, the administrator adds its public key:
 *   echo "<agent_pub_key_hex>" >> /etc/asyd/authorized_agents
 */

#ifndef WHITELIST_H
#define WHITELIST_H

#include <stdint.h>
#include "noise_ik.h"   /* NOISE_KEY_SIZE = 32 */

/* ── Limits ─────────────────────────────────────────────── */
#define WHITELIST_MAX_AGENTS  64
#define WHITELIST_LABEL_SIZE  32
#define WHITELIST_KEYFILE     "/etc/asyd/authorized_agents"

/* ── Whitelist entry ─────────────────────────────────────── */
typedef struct {
    uint8_t pub  [NOISE_KEY_SIZE];       /* 32-byte Curve25519 public key  */
    char    label[WHITELIST_LABEL_SIZE]; /* optional human-readable label  */
} AgentEntry;                            /* 64 bytes, 4-byte aligned        */

/* ── Whitelist (zero-malloc, statically allocated) ──────── */
typedef struct {
    AgentEntry entries[WHITELIST_MAX_AGENTS];
    int        count;
} Whitelist;

/* ── Error codes ─────────────────────────────────────────── */
#define WL_OK         0
#define WL_ERR_DENIED -1
#define WL_ERR_IO     -2

/* ── API ─────────────────────────────────────────────────── */

/*
 * Load authorized_keys into wl. Missing file → WL_OK with count=0
 * (prints WARNING). Parse-error lines are silently skipped.
 * Call once at daemon startup.
 */
int  whitelist_load(Whitelist *wl);

/*
 * Check whether pub[32] is in the whitelist.
 * Returns WL_OK if found, WL_ERR_DENIED if not.
 * Uses constant-time comparison (crypto_verify32).
 */
int  whitelist_check(const Whitelist *wl, const uint8_t pub[NOISE_KEY_SIZE]);

/*
 * Zero all key material in wl. Call before process exit.
 */
void whitelist_wipe(Whitelist *wl);

#endif /* WHITELIST_H */
