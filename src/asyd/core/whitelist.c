/*
 * Copyright (c) 2026 Vincent Ping (vincentping@gmail.com)
 * SPDX-License-Identifier: Apache-2.0
 */
/*
 * whitelist.c — Agent public-key whitelist implementation
 *
 * File I/O contract:
 *   - whitelist_load():  reads /etc/asyd/authorized_agents (startup only)
 *   - All other functions: pure in-memory, no syscalls
 */

#include "whitelist.h"
#include "monocypher.h"

#include <stdio.h>
#include <string.h>

/* Decode a single hex nibble; returns -1 on bad input */
static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decode a 32-byte (64-char) hex string into buf.
 * Returns 0 on success, -1 on parse error. */
static int hex_decode32(const char *hex, uint8_t buf[NOISE_KEY_SIZE])
{
    for (int i = 0; i < NOISE_KEY_SIZE; i++) {
        int hi = hex_nibble(hex[2*i]);
        int lo = hex_nibble(hex[2*i + 1]);
        if (hi < 0 || lo < 0) return -1;
        buf[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

/* ── whitelist_load ─────────────────────────────────────── */

int whitelist_load(Whitelist *wl)
{
    if (!wl) return WL_ERR_IO;
    memset(wl, 0, sizeof(*wl));

    FILE *f = fopen(WHITELIST_KEYFILE, "r");
    if (!f) {
        /* Auto-create with format comments so admin knows what to add */
        FILE *nf = fopen(WHITELIST_KEYFILE, "w");
        if (nf) {
            fputs(
                "# /etc/asyd/authorized_agents — authorized agent public keys\n"
                "#\n"
                "# One entry per line:\n"
                "#   <64-char hex Curve25519 pubkey>  [optional-label]\n"
                "#\n"
                "# Example:\n"
                "#   9d0c10df7237b1cf77380ae676ee500fe4da9873476c2e46378cad5e3cc2ba52  my-agent\n"
                "#\n"
                "# To add an agent, run asys_keygen.py on the client, then copy\n"
                "# the printed Fingerprint hex to this file:\n"
                "#   echo \"<pubkey_hex>  <label>\" >> /etc/asyd/authorized_agents\n",
                nf);
            fclose(nf);
            printf("[asyd] created %s — add agent pubkeys to allow connections\n",
                   WHITELIST_KEYFILE);
        } else {
            printf("[asyd] WARNING: %s not found and could not be created — "
                   "no agents can connect\n", WHITELIST_KEYFILE);
        }
        return WL_OK;   /* empty whitelist; admin must add keys */
    }

    char line[128];
    while (fgets(line, sizeof(line), f) && wl->count < WHITELIST_MAX_AGENTS) {
        /* Skip blank lines and comments */
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == '\0') continue;

        /* First token: 64-char hex pubkey */
        if (strlen(p) < 64) continue;
        AgentEntry *e = &wl->entries[wl->count];
        if (hex_decode32(p, e->pub) != 0) continue;

        /* Optional label after whitespace */
        char *label = p + 64;
        while (*label == ' ' || *label == '\t') label++;
        char *end = label;
        while (*end && *end != '\n' && *end != '\r') end++;
        *end = '\0';

        if (*label) {
            size_t llen = (size_t)(end - label);
            if (llen >= WHITELIST_LABEL_SIZE) llen = WHITELIST_LABEL_SIZE - 1;
            memcpy(e->label, label, llen);
            e->label[llen] = '\0';
        }

        wl->count++;
    }
    fclose(f);
    return WL_OK;
}

/* ── whitelist_check ────────────────────────────────────── */

int whitelist_check(const Whitelist *wl, const uint8_t pub[NOISE_KEY_SIZE])
{
    if (!wl || !pub) return WL_ERR_DENIED;
    for (int i = 0; i < wl->count; i++) {
        if (crypto_verify32(wl->entries[i].pub, pub) == 0)
            return WL_OK;
    }
    return WL_ERR_DENIED;
}

/* ── whitelist_wipe ─────────────────────────────────────── */

void whitelist_wipe(Whitelist *wl)
{
    if (!wl) return;
    crypto_wipe(wl, sizeof(*wl));
}
