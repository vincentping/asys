/*
 * Copyright (c) 2026 Vincent Ping (vincentping@gmail.com)
 * SPDX-License-Identifier: Apache-2.0
 */
/*
 * sys_hello.c — 0x01 SYS_HELLO Handler
 *
 * Response layout (18 bytes, spec §1.3.2):
 *
 *   [0-3]   Magic           0x41535953 ("ASYS")
 *   [4-7]   Node_UID        Machine unique fingerprint (first 4B of /etc/machine-id)
 *   [8-15]  Server_Timestamp  Nanosecond Unix Epoch (CLOCK_REALTIME)
 *   [16-17] SW              0x9000
 */

#include "../core/dispatcher.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#define HELLO_RESP_LEN  18

static void put_u32(uint8_t *b, uint32_t v)
{
    b[0]=(uint8_t)(v>>24); b[1]=(uint8_t)(v>>16);
    b[2]=(uint8_t)(v>>8);  b[3]=(uint8_t)(v&0xFF);
}
static void put_u64(uint8_t *b, uint64_t v)
{
    b[0]=(uint8_t)(v>>56); b[1]=(uint8_t)(v>>48);
    b[2]=(uint8_t)(v>>40); b[3]=(uint8_t)(v>>32);
    b[4]=(uint8_t)(v>>24); b[5]=(uint8_t)(v>>16);
    b[6]=(uint8_t)(v>>8);  b[7]=(uint8_t)(v&0xFF);
}

/*
 * Node_UID: read the first 8 hex chars of /etc/machine-id and parse
 * them as a big-endian uint32_t. Falls back to 0x00000000 on failure.
 */
static uint32_t read_node_uid(void)
{
    FILE *f = fopen("/etc/machine-id", "r");
    if (!f) return 0;

    char buf[9]; /* 8 hex digits + NUL */
    if (fread(buf, 1, 8, f) != 8) { fclose(f); return 0; }
    buf[8] = '\0';
    fclose(f);

    uint32_t uid = 0;
    for (int i = 0; i < 8; i++) {
        char c = buf[i];
        uint8_t nib;
        if      (c >= '0' && c <= '9') nib = (uint8_t)(c - '0');
        else if (c >= 'a' && c <= 'f') nib = (uint8_t)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') nib = (uint8_t)(c - 'A' + 10);
        else return 0;
        uid = (uid << 4) | nib;
    }
    return uid;
}

int handler_sys_hello(const ApduFrame *req, uint8_t *resp, size_t sz, uint16_t session_id)
{
    (void)req;
    (void)session_id;
    if (sz < HELLO_RESP_LEN) return sw_write(resp, SW_SYS_ERR);

    /* [0-3] Magic "ASYS" */
    put_u32(resp + 0, 0x41535953u);

    /* [4-7] Node UID */
    put_u32(resp + 4, read_node_uid());

    /* [8-15] Server timestamp (nanoseconds) */
    struct timespec ts;
    uint64_t ns = 0;
    if (clock_gettime(CLOCK_REALTIME, &ts) == 0)
        ns = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
    put_u64(resp + 8, ns);

    /* [16-17] SW 0x9000 */
    resp[16] = 0x90;
    resp[17] = 0x00;

    return HELLO_RESP_LEN;
}
