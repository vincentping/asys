/*
 * Copyright (c) 2026 Vincent Ping (vincentping@gmail.com)
 * SPDX-License-Identifier: Apache-2.0
 */
/*
 * sys_procs.c — 0x03 SYS_PROCS Handler
 *
 * CPU measurement: cross-call delta (top-style).
 *   - Persistent T1 snapshot saved from the previous call.
 *   - Each new call reads T2, computes delta against T1, saves T2 as new T1.
 *   - Cold start (first call): 200 ms blocking sample to establish baseline.
 *   - Warm calls: single /proc scan, ~10 ms response time.
 *
 * Response layout (44 bytes, spec §1.3.4):
 *
 *   [0-1]   Total_Procs   System-wide process count
 *   [2-41]  Top 5 Slots   5 × 8 bytes
 *   [42-43] SW            0x9000
 *
 * Each 8-byte slot:
 *   [0-3] PID          (0x00000000 = empty)
 *   [4-5] CPU_Usage    ×100 (precision 0.01%), uint16_t big-endian
 *   [6]   MEM_Usage    integer %
 *   [7]   Status_Flag  bit0=Zombie, bit1=Unresponsive, bit2=Privileged
 *
 * No malloc. Two static scan buffers for up to MAX_PROCS_SCAN processes.
 */

#include "../core/dispatcher.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <dirent.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>

#define PROCS_RESP_LEN   44
#define SLOT_SIZE         8
#define TOP_N             5
#define MAX_PROCS_SCAN  512
#define COLD_SAMPLE_MS  200   /* blocking interval on first call only */

/* ── Big-endian write helpers ───────────────────────────── */
static void put_u16(uint8_t *b, uint16_t v)
{
    b[0] = (uint8_t)(v >> 8); b[1] = (uint8_t)(v & 0xFF);
}
static void put_u32(uint8_t *b, uint32_t v)
{
    b[0]=(uint8_t)(v>>24); b[1]=(uint8_t)(v>>16);
    b[2]=(uint8_t)(v>>8);  b[3]=(uint8_t)(v&0xFF);
}

/* ── Per-process snapshot ────────────────────────────────── */
typedef struct {
    uint32_t pid;
    uint64_t jiffies;    /* utime + stime */
    uint8_t  mem_pct;
    uint8_t  status_flag;
} ProcSnap;

/* ── Top-N entry ─────────────────────────────────────────── */
typedef struct {
    uint32_t pid;
    uint64_t delta;
    uint8_t  mem_pct;
    uint8_t  status_flag;
} ProcInfo;

/*
 * Two static scan buffers — safe under g_dispatch_lock (TD-01).
 * g_prev: T1 snapshot from the previous call (persists between calls).
 * g_curr: T2 snapshot built on the current call.
 */
static ProcSnap g_prev[MAX_PROCS_SCAN];
static int      g_n_prev     = 0;
static uint64_t g_total_prev = 0;

static ProcSnap g_curr[MAX_PROCS_SCAN];
static int      g_n_curr;
static uint64_t g_total_curr;

/* ── /proc/stat: total jiffies ──────────────────────────── */
static uint64_t read_total_jiffies(void)
{
    typedef unsigned long long ull;
    ull u,n,s,i,w,x,y,z;
    FILE *f = fopen("/proc/stat", "r");
    if (!f) return 1;
    int ok = (fscanf(f, "cpu %llu %llu %llu %llu %llu %llu %llu %llu",
                     &u,&n,&s,&i,&w,&x,&y,&z) == 8);
    fclose(f);
    if (!ok) return 1;
    return u+n+s+i+w+x+y+z;
}

/* ── /proc/meminfo: MemTotal in kB ─────────────────────── */
static unsigned long read_mem_total_kb(void)
{
    FILE *f = fopen("/proc/meminfo", "r");
    if (!f) return 1;
    char key[32];
    unsigned long val;
    while (fscanf(f, "%31s %lu kB\n", key, &val) == 2) {
        if (strcmp(key, "MemTotal:") == 0) { fclose(f); return val ? val : 1; }
    }
    fclose(f);
    return 1;
}

/* ── /proc/<pid>/stat: state + utime+stime ─────────────── */
static int parse_proc_stat(uint32_t pid,
                            char     *state_out,
                            uint64_t *jiffies_out)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%u/stat", pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;

    char buf[512];
    if (!fgets(buf, sizeof(buf), f)) { fclose(f); return 0; }
    fclose(f);

    char *rp = strrchr(buf, ')');
    if (!rp) return 0;
    rp++;

    while (*rp == ' ') rp++;
    char state = *rp++;

    unsigned long dummy;
    for (int i = 0; i < 10; i++) {
        if (sscanf(rp, " %lu", &dummy) < 1) return 0;
        while (*rp == ' ') rp++;
        while (*rp && *rp != ' ') rp++;
    }

    unsigned long long utime = 0, stime = 0;
    if (sscanf(rp, " %llu %llu", &utime, &stime) < 2) return 0;

    *state_out   = state;
    *jiffies_out = utime + stime;
    return 1;
}

/* ── /proc/<pid>/status: uid + VmRSS ───────────────────── */
static int parse_proc_status(uint32_t pid,
                              int *privileged_out,
                              unsigned long *vmrss_kb_out)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%u/status", pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;

    int got_uid = 0, got_rss = 0;
    unsigned uid = 9999;
    *vmrss_kb_out = 0;

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "Uid: %u", &uid)            == 1) got_uid = 1;
        if (sscanf(line, "VmRSS: %lu", vmrss_kb_out) == 1) got_rss = 1;
        if (got_uid && got_rss) break;
    }
    fclose(f);

    *privileged_out = (uid == 0) ? 1 : 0;
    return 1;
}

/* ── Scan /proc into dst[], return count ────────────────── */
static int scan_proc(ProcSnap *dst, int max,
                     uint64_t *total_out,
                     uint16_t *total_procs_out,
                     unsigned long mem_total_kb)
{
    *total_out       = read_total_jiffies();
    *total_procs_out = 0;

    DIR *dp = opendir("/proc");
    if (!dp) return -1;

    int n = 0;
    struct dirent *de;
    while ((de = readdir(dp)) != NULL) {
        if (!isdigit((unsigned char)de->d_name[0])) continue;

        uint32_t pid = (uint32_t)atoi(de->d_name);
        if (pid == 0) continue;
        (*total_procs_out)++;

        if (n >= max) continue;

        char state = 'R';
        uint64_t jiffies = 0;
        if (!parse_proc_stat(pid, &state, &jiffies)) continue;

        int privileged = 0;
        unsigned long vmrss_kb = 0;
        parse_proc_status(pid, &privileged, &vmrss_kb);

        uint8_t flags = 0;
        if (state == 'Z') flags |= 0x01;
        if (state == 'D') flags |= 0x02;
        if (privileged)   flags |= 0x04;

        unsigned long mp = (vmrss_kb > 0 && mem_total_kb > 0)
                           ? vmrss_kb * 100UL / mem_total_kb : 0;

        dst[n].pid         = pid;
        dst[n].jiffies     = jiffies;
        dst[n].mem_pct     = (mp > 255) ? 255 : (uint8_t)mp;
        dst[n].status_flag = flags;
        n++;
    }
    closedir(dp);
    return n;
}

/* ── Insertion-sort into top-N by delta (descending) ────── */
static void insert_top(ProcInfo *top, int *count, const ProcInfo *p)
{
    int pos = *count;
    for (int i = 0; i < *count; i++) {
        if (p->delta > top[i].delta) { pos = i; break; }
    }
    if (pos >= TOP_N) return;

    int end = (*count < TOP_N) ? *count : TOP_N - 1;
    for (int i = end; i > pos; i--) top[i] = top[i-1];
    top[pos] = *p;
    if (*count < TOP_N) (*count)++;
}

/* ── Handler ─────────────────────────────────────────────── */

int handler_sys_procs(const ApduFrame *req, uint8_t *resp, size_t sz, uint16_t session_id)
{
    (void)req;
    (void)session_id;
    if (sz < PROCS_RESP_LEN) return sw_write(resp, SW_SYS_ERR);

    unsigned long mem_total_kb = read_mem_total_kb();
    uint16_t total_procs = 0;

    /* Cold start: no previous snapshot — build T1, sleep, build T2 */
    if (g_n_prev == 0) {
        uint16_t dummy_count;
        g_n_prev = scan_proc(g_prev, MAX_PROCS_SCAN,
                             &g_total_prev, &dummy_count, mem_total_kb);
        if (g_n_prev < 0) return sw_write(resp, SW_SYS_ERR);

        struct timespec ts = { 0, COLD_SAMPLE_MS * 1000000L };
        nanosleep(&ts, NULL);
    }

    /* Scan current state into g_curr (T2) */
    g_n_curr = scan_proc(g_curr, MAX_PROCS_SCAN,
                         &g_total_curr, &total_procs, mem_total_kb);
    if (g_n_curr < 0) return sw_write(resp, SW_SYS_ERR);

    uint64_t total_delta = g_total_curr - g_total_prev;
    if (total_delta == 0) total_delta = 1;

    /* Compute per-process deltas: match g_prev (T1) → g_curr (T2) by PID */
    ProcInfo top[TOP_N];
    memset(top, 0, sizeof(top));
    int top_count = 0;

    for (int i = 0; i < g_n_prev; i++) {
        uint32_t pid = g_prev[i].pid;

        /* Find this PID in g_curr */
        uint64_t jiffies_t2 = 0;
        uint8_t  mem_pct    = g_prev[i].mem_pct;
        uint8_t  flags      = g_prev[i].status_flag;

        for (int j = 0; j < g_n_curr; j++) {
            if (g_curr[j].pid == pid) {
                jiffies_t2 = g_curr[j].jiffies;
                mem_pct    = g_curr[j].mem_pct;
                flags      = g_curr[j].status_flag;
                break;
            }
        }

        if (jiffies_t2 == 0) continue; /* process exited between T1 and T2 */

        uint64_t delta = (jiffies_t2 >= g_prev[i].jiffies)
                         ? jiffies_t2 - g_prev[i].jiffies : 0;

        ProcInfo pi = { pid, delta, mem_pct, flags };
        insert_top(top, &top_count, &pi);
    }

    /* Promote g_curr → g_prev for next call */
    memcpy(g_prev, g_curr, (size_t)g_n_curr * sizeof(ProcSnap));
    g_n_prev     = g_n_curr;
    g_total_prev = g_total_curr;

    /* ── Build response ── */
    long ncpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpus < 1) ncpus = 1;

    memset(resp, 0, PROCS_RESP_LEN);
    put_u16(resp + 0, total_procs);

    for (int i = 0; i < TOP_N; i++) {
        uint8_t *slot = resp + 2 + i * SLOT_SIZE;
        if (i >= top_count || top[i].pid == 0) continue;

        put_u32(slot + 0, top[i].pid);

        uint64_t cpu_x100 = top[i].delta * 10000ULL * (uint64_t)ncpus / total_delta;
        if (cpu_x100 > 10000ULL * (uint64_t)ncpus) cpu_x100 = 10000ULL * (uint64_t)ncpus;
        if (cpu_x100 > 0xFFFF) cpu_x100 = 0xFFFF;
        put_u16(slot + 4, (uint16_t)cpu_x100);

        slot[6] = top[i].mem_pct;
        slot[7] = top[i].status_flag;
    }

    resp[42] = 0x90;
    resp[43] = 0x00;
    return PROCS_RESP_LEN;
}
