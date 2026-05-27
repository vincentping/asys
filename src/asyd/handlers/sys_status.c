/*
 * Copyright (c) 2026 Vincent Ping (vincentping@gmail.com)
 * SPDX-License-Identifier: Apache-2.0
 */
/*
 * sys_status.c — 0x02 SYS_STATUS Handler
 *
 * Response layout (23 bytes, spec §1.3.3):
 *
 *   [0-2]   CPU_Dyn     [1B load1×10][1B load5×10][1B total_cpu%]
 *   [3-6]   Mem_Dyn     [4B Available_MB]
 *   [7-11]  Store_Dyn   [1B root_usage%][4B IO_Wait_ms]
 *   [12-15] Net_Dyn     [2B Inbound_Mbps][2B Outbound_Mbps]
 *   [16]    RPI         Resource Pressure Index 0-100, 0xFF=NOT_SUPPORTED
 *   [17-20] Reserve     4 bytes, 0x00
 *   [21-22] SW          0x9000
 *
 * All multi-byte fields big-endian. No floats. No malloc.
 *
 * Caching strategy: a static snapshot is refreshed at most once per
 * REFRESH_INTERVAL_MS. High-frequency callers (10Hz+) receive the cached
 * value with < 1ms response time; the first call after staleness does the
 * actual /proc reads plus a 50ms CPU sample.
 */

#include "../core/dispatcher.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <sys/statvfs.h>

#define STATUS_RESP_LEN   23
#define REFRESH_INTERVAL_MS  500   /* re-sample at most every 500ms */

/* ── Helpers ─────────────────────────────────────────────── */
static void put_u16(uint8_t *b, uint16_t v)
{
    b[0] = (uint8_t)(v >> 8); b[1] = (uint8_t)(v & 0xFF);
}
static void put_u32(uint8_t *b, uint32_t v)
{
    b[0]=(uint8_t)(v>>24); b[1]=(uint8_t)(v>>16);
    b[2]=(uint8_t)(v>>8);  b[3]=(uint8_t)(v&0xFF);
}

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000);
}

/* ── Cached snapshot ─────────────────────────────────────── */
typedef struct {
    uint8_t  load1_x10;      /* 1-min load average × 10           */
    uint8_t  load5_x10;      /* 5-min load average × 10           */
    uint8_t  cpu_pct;        /* total CPU usage %                 */
    uint32_t mem_avail_mb;   /* MemAvailable in MB                */
    uint8_t  root_usage_pct; /* root partition used %             */
    uint32_t iowait_ms;      /* cumulative I/O wait ms (delta)    */
    uint16_t in_mbps;        /* inbound  Mbps (integer)           */
    uint16_t out_mbps;       /* outbound Mbps (integer)           */
    uint8_t  rpi;            /* Resource Pressure Index           */
} StatusSnap;

static StatusSnap      g_snap;
static uint64_t        g_snap_time_ms = 0;       /* 0 = never sampled     */
static pthread_mutex_t s_cache_lock   = PTHREAD_MUTEX_INITIALIZER;

/* ── /proc readers ───────────────────────────────────────── */

static void read_loadavg(uint8_t *load1_x10, uint8_t *load5_x10)
{
    *load1_x10 = 0; *load5_x10 = 0;
    FILE *f = fopen("/proc/loadavg", "r");
    if (!f) return;
    unsigned l1_int, l1_frac, l5_int, l5_frac;
    if (fscanf(f, "%u.%u %u.%u", &l1_int, &l1_frac, &l5_int, &l5_frac) == 4) {
        /* ×10: e.g. 1.23 → 12 (truncate to 1 decimal) */
        *load1_x10 = (uint8_t)(l1_int * 10 + l1_frac / 10);
        *load5_x10 = (uint8_t)(l5_int * 10 + l5_frac / 10);
    }
    fclose(f);
}

/*
 * CPU usage: two /proc/stat samples 50ms apart.
 * Returns 0-100.
 */
static uint8_t read_cpu_pct(void)
{
    typedef unsigned long long ull;
    ull u1,n1,s1,i1,w1,x1,y1,z1;
    ull u2,n2,s2,i2,w2,x2,y2,z2;

    FILE *f = fopen("/proc/stat", "r");
    if (!f) return 0;
    if (fscanf(f, "cpu %llu %llu %llu %llu %llu %llu %llu %llu",
               &u1,&n1,&s1,&i1,&w1,&x1,&y1,&z1) != 8) { fclose(f); return 0; }
    fclose(f);

    usleep(50000); /* 50ms sample window */

    f = fopen("/proc/stat", "r");
    if (!f) return 0;
    if (fscanf(f, "cpu %llu %llu %llu %llu %llu %llu %llu %llu",
               &u2,&n2,&s2,&i2,&w2,&x2,&y2,&z2) != 8) { fclose(f); return 0; }
    fclose(f);

    ull idle  = (i2-i1) + (w2-w1);
    ull total = (u2-u1)+(n2-n1)+(s2-s1)+(i2-i1)+(w2-w1)+(x2-x1)+(y2-y1)+(z2-z1);
    if (total == 0) return 0;
    return (uint8_t)(100ULL * (total - idle) / total);
}

static uint32_t read_mem_avail_mb(void)
{
    FILE *f = fopen("/proc/meminfo", "r");
    if (!f) return 0;
    char key[32];
    unsigned long val;
    while (fscanf(f, "%31s %lu kB\n", key, &val) == 2) {
        if (strcmp(key, "MemAvailable:") == 0) {
            fclose(f);
            return (uint32_t)(val / 1024);
        }
    }
    fclose(f);
    return 0;
}

static void read_root_disk(uint8_t *usage_pct, uint32_t *iowait_ms)
{
    *usage_pct = 0; *iowait_ms = 0;

    /* Root partition usage */
    {
        struct statvfs s;
        if (statvfs("/", &s) == 0 && s.f_blocks > 0) {
            unsigned long long used = s.f_blocks - s.f_bfree;
            *usage_pct = (uint8_t)(used * 100ULL / s.f_blocks);
        }
    }

    /* I/O wait: read iowait jiffies from /proc/stat (cumulative) */
    {
        /* We compute a delta against a previous reading */
        static unsigned long long prev_iowait = 0;
        static uint64_t           prev_time_ms = 0;

        unsigned long long u,n,s,idle,w,x,y,z;
        FILE *f = fopen("/proc/stat", "r");
        if (f) {
            if (fscanf(f, "cpu %llu %llu %llu %llu %llu %llu %llu %llu",
                       &u,&n,&s,&idle,&w,&x,&y,&z) == 8) {
                uint64_t t = now_ms();
                unsigned long long delta_iow = (w >= prev_iowait) ? w - prev_iowait : 0;
                uint64_t delta_ms            = (t > prev_time_ms) ? t - prev_time_ms : 1;
                /*
                 * iowait jiffies × (1000 / HZ) ≈ ms of iowait in the interval
                 * HZ is typically 100 on Linux → 1 jiffy = 10ms
                 * We report delta_iow × 10 as iowait_ms for the interval.
                 */
                unsigned long long hz = 100; /* sysconf(_SC_CLK_TCK) in production */
                *iowait_ms = (uint32_t)(delta_iow * 1000ULL / hz);
                if (*iowait_ms > delta_ms) *iowait_ms = (uint32_t)delta_ms; /* cap at interval */

                prev_iowait = w;
                prev_time_ms = t;
            }
            fclose(f);
        }
    }
}

static void read_net_mbps(uint16_t *in_mbps, uint16_t *out_mbps)
{
    *in_mbps = 0; *out_mbps = 0;

    static unsigned long long prev_rx = 0, prev_tx = 0;
    static uint64_t           prev_net_ms = 0;

    unsigned long long rx_total = 0, tx_total = 0;
    FILE *f = fopen("/proc/net/dev", "r");
    if (!f) return;

    char line[256];
    /* Skip header lines */
    fgets(line, sizeof(line), f);
    fgets(line, sizeof(line), f);

    while (fgets(line, sizeof(line), f)) {
        char iface[32];
        unsigned long long rx, tx;
        unsigned long long dummy;
        /* /proc/net/dev fields: iface: rx_bytes ... tx_bytes ... */
        if (sscanf(line, " %31[^:]: %llu %llu %llu %llu %llu %llu %llu %llu %llu",
                   iface, &rx,
                   &dummy,&dummy,&dummy,&dummy,&dummy,&dummy,&dummy,
                   &tx) >= 10) {
            /* Skip loopback */
            if (iface[0] == 'l' && iface[1] == 'o') continue;
            rx_total += rx;
            tx_total += tx;
        }
    }
    fclose(f);

    uint64_t t = now_ms();
    if (prev_net_ms > 0 && t > prev_net_ms) {
        uint64_t delta_ms = t - prev_net_ms;
        unsigned long long delta_rx = (rx_total >= prev_rx) ? rx_total - prev_rx : 0;
        unsigned long long delta_tx = (tx_total >= prev_tx) ? tx_total - prev_tx : 0;
        /* bytes/ms × 8 / 1000 = Mbps */
        unsigned long long in_val  = delta_rx * 8ULL / delta_ms / 1000ULL;
        unsigned long long out_val = delta_tx * 8ULL / delta_ms / 1000ULL;
        *in_mbps  = (in_val  > 0xFFFF) ? 0xFFFF : (uint16_t)in_val;
        *out_mbps = (out_val > 0xFFFF) ? 0xFFFF : (uint16_t)out_val;
    }
    prev_rx = rx_total;
    prev_tx = tx_total;
    prev_net_ms = t;
}

/*
 * load1_x10: 1-min load average × 10 (already sampled by caller).
 * Used as USER_SIMULATED fallback when PSI is unavailable.
 */
static uint8_t read_rpi(uint8_t load1_x10)
{
    /* PSI availability and CPU count are immutable for process lifetime. */
    static int  psi_available = -1;   /* -1=unknown, 0=no, 1=yes */
    static long ncpus         = 0;

    if (psi_available == -1) {
        FILE *probe = fopen("/proc/pressure/cpu", "r");
        psi_available = (probe != NULL) ? 1 : 0;
        if (probe) fclose(probe);
        ncpus = sysconf(_SC_NPROCESSORS_ONLN);
        if (ncpus < 1) ncpus = 1;
    }

    /* NATIVE_KERNEL path: read PSI "some avg10" from /proc/pressure/cpu */
    if (psi_available) {
        FILE *f = fopen("/proc/pressure/cpu", "r");
        if (f) {
            unsigned some_int, some_frac;
            uint8_t rpi = 0;
            if (fscanf(f, "some avg10=%u.%u", &some_int, &some_frac) == 2) {
                /* avg10 is 0.00–100.00; map to 0–100 */
                unsigned pct = some_int;
                if (pct > 100) pct = 100;
                rpi = (uint8_t)pct;
            }
            fclose(f);
            return rpi;
        }
    }

    /*
     * USER_SIMULATED path: /proc/pressure/cpu unavailable (PSI disabled
     * or old kernel). Derive RPI from 1-min load average:
     *   rpi = min(100, load_avg_1min × 100 / ncpus)
     * load1_x10 = load × 10, so: rpi = load1_x10 × 10 / ncpus
     */
    unsigned rpi = (unsigned)load1_x10 * 10U / (unsigned)ncpus;
    if (rpi > 100) rpi = 100;
    return (uint8_t)rpi;
}

/* ── Refresh ─────────────────────────────────────────────── */

static void refresh_snapshot(void)
{
    StatusSnap s;
    read_loadavg(&s.load1_x10, &s.load5_x10);
    s.cpu_pct      = read_cpu_pct();
    s.mem_avail_mb = read_mem_avail_mb();
    read_root_disk(&s.root_usage_pct, &s.iowait_ms);
    read_net_mbps(&s.in_mbps, &s.out_mbps);
    s.rpi          = read_rpi(s.load1_x10);

    g_snap         = s;
    g_snap_time_ms = now_ms();
}

/* ── Handler ─────────────────────────────────────────────── */

int handler_sys_status(const ApduFrame *req, uint8_t *resp, size_t sz, uint16_t session_id)
{
    (void)req;
    (void)session_id;
    if (sz < STATUS_RESP_LEN) return sw_write(resp, SW_SYS_ERR);

    /* Refresh cache under lock; copy snapshot before releasing.
     * Other instructions run concurrently — this lock only serialises
     * cache refresh (≤50ms for CPU dual-sample), not all dispatches. */
    pthread_mutex_lock(&s_cache_lock);
    uint64_t now = now_ms();
    if (g_snap_time_ms == 0 || (now - g_snap_time_ms) >= REFRESH_INTERVAL_MS)
        refresh_snapshot();
    StatusSnap snap = g_snap;
    pthread_mutex_unlock(&s_cache_lock);

    memset(resp, 0, STATUS_RESP_LEN);

    /* [0] 1-min load × 10 */
    resp[0] = snap.load1_x10;
    /* [1] 5-min load × 10 */
    resp[1] = snap.load5_x10;
    /* [2] total CPU % */
    resp[2] = snap.cpu_pct;

    /* [3-6] Available RAM MB */
    put_u32(resp + 3, snap.mem_avail_mb);

    /* [7] root partition usage % */
    resp[7] = snap.root_usage_pct;
    /* [8-11] IO wait ms */
    put_u32(resp + 8, snap.iowait_ms);

    /* [12-13] Inbound Mbps */
    put_u16(resp + 12, snap.in_mbps);
    /* [14-15] Outbound Mbps */
    put_u16(resp + 14, snap.out_mbps);

    /* [16] RPI */
    resp[16] = snap.rpi;

    /* [17-20] Reserve: 0x00 */

    /* [21-22] SW 0x9000 */
    resp[21] = 0x90;
    resp[22] = 0x00;

    return STATUS_RESP_LEN;
}
