/*
 * Copyright (c) 2026 Vincent Ping (vincentping@gmail.com)
 * SPDX-License-Identifier: Apache-2.0
 */
/*
 * sys_caps.c — 0x00 SYS_CAPS Handler
 *
 * Response layout (36 bytes, spec §1.3.1):
 *
 *   [0-7]   Instruction Bitmap  [Core(4B)][Extended(4B)]
 *   [8-9]   Protocol_Version    0x0100
 *   [10-13] Kernel_Hash         4-byte kernel version digest
 *   [14-17] CPU_Static          [2B ncpus][2B arch_code]
 *   [18-25] Memory_Static       [4B Total_RAM_MB][4B Total_Swap_MB]
 *   [26-31] Storage_Static      [4B Root_Size_MB][2B FS_Type_Code]
 *   [32]    RPI_Type            0x01=NATIVE_KERNEL, 0x02=USER_SIMULATED
 *   [33]    Reserved            0x00
 *   [34-35] SW                  0x9000
 *
 * All multi-byte fields big-endian. No floats. No malloc.
 */

#include "../core/dispatcher.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/utsname.h>
#include <sys/statvfs.h>
#include <sys/vfs.h>
#include <unistd.h>

#define CAPS_RESP_LEN  36

/* ── Arch codes ─────────────────────────────────────────── */
#define ARCH_X86_64   0x0001u
#define ARCH_AARCH64  0x0002u
#define ARCH_RISCV64  0x0003u
#define ARCH_UNKNOWN  0xFFFFu

/* ── FS type codes ──────────────────────────────────────── */
#define FS_EXT4       0x0001u   /* EXT2/3/4 magic 0xEF53   */
#define FS_XFS        0x0002u   /* XFS      magic 0x58465342 */
#define FS_BTRFS      0x0003u   /* BTRFS    magic 0x9123683E */
#define FS_TMPFS      0x0004u   /* TMPFS    magic 0x01021994 */
#define FS_NFS        0x0005u   /* NFS      magic 0x6969     */
#define FS_UNKNOWN    0xFFFFu

/* ── RPI type codes ─────────────────────────────────────── */
#define RPI_NATIVE_KERNEL    0x01u
#define RPI_USER_SIMULATED   0x02u

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

/* ── Helpers ─────────────────────────────────────────────── */

static uint16_t detect_arch(const char *machine)
{
    if (strncmp(machine, "x86_64",  6) == 0) return ARCH_X86_64;
    if (strncmp(machine, "aarch64", 7) == 0) return ARCH_AARCH64;
    if (strncmp(machine, "riscv64", 7) == 0) return ARCH_RISCV64;
    return ARCH_UNKNOWN;
}

/*
 * Kernel_Hash: pack major.minor.patch from uts.release into 4 bytes.
 * Format: [major(1B)][minor(1B)][patch_hi(1B)][patch_lo(1B)]
 * Example: "6.12.0" → 0x060C0000
 */
static void build_kernel_hash(const char *release, uint8_t out[4])
{
    unsigned major = 0, minor = 0, patch = 0;
    sscanf(release, "%u.%u.%u", &major, &minor, &patch);
    out[0] = (uint8_t)(major & 0xFF);
    out[1] = (uint8_t)(minor & 0xFF);
    out[2] = (uint8_t)(patch >> 8);
    out[3] = (uint8_t)(patch & 0xFF);
}

static uint16_t detect_fs_type(long f_type)
{
    switch ((unsigned long)f_type) {
        case 0xEF53ul:       return FS_EXT4;
        case 0x58465342ul:   return FS_XFS;
        case 0x9123683Eul:   return FS_BTRFS;
        case 0x01021994ul:   return FS_TMPFS;
        case 0x6969ul:       return FS_NFS;
        default:             return FS_UNKNOWN;
    }
}

/* Check if PSI is available on this kernel */
static uint8_t detect_rpi_type(void)
{
    FILE *f = fopen("/proc/pressure/cpu", "r");
    if (f) { fclose(f); return RPI_NATIVE_KERNEL; }
    return RPI_USER_SIMULATED;
}

/* ── Handler ─────────────────────────────────────────────── */

int handler_sys_caps(const ApduFrame *req, uint8_t *resp, size_t sz, uint16_t session_id)
{
    (void)req;
    (void)session_id;
    if (sz < CAPS_RESP_LEN) return sw_write(resp, SW_SYS_ERR);

    memset(resp, 0, CAPS_RESP_LEN);

    /* [0-3] Core instruction bitmap */
    put_u32(resp + 0, CORE_CAPS_BITMAP);
    /* [4-7] Extended instruction bitmap */
    put_u32(resp + 4, EXT_CAPS_BITMAP);

    /* [8-9] Protocol version: v1.0 */
    put_u16(resp + 8, 0x0100u);

    /* [10-13] Kernel hash */
    struct utsname uts;
    if (uname(&uts) == 0) {
        build_kernel_hash(uts.release, resp + 10);

        /* [14-15] CPU count */
        long ncpus = sysconf(_SC_NPROCESSORS_ONLN);
        if (ncpus < 1) ncpus = 1;
        put_u16(resp + 14, (uint16_t)ncpus);

        /* [16-17] Arch code */
        put_u16(resp + 16, detect_arch(uts.machine));
    } else {
        /* uname failed — leave kernel hash + CPU zero, arch unknown */
        put_u16(resp + 16, ARCH_UNKNOWN);
    }

    /* [18-21] Total RAM MB, [22-25] Total Swap MB */
    {
        uint32_t total_ram_mb = 0, total_swap_mb = 0;
        FILE *f = fopen("/proc/meminfo", "r");
        if (f) {
            char key[32];
            unsigned long val;
            char unit[8];
            while (fscanf(f, "%31s %lu %7s\n", key, &val, unit) >= 2) {
                if      (strcmp(key, "MemTotal:") == 0)  total_ram_mb  = (uint32_t)(val / 1024);
                else if (strcmp(key, "SwapTotal:") == 0) total_swap_mb = (uint32_t)(val / 1024);
            }
            fclose(f);
        }
        put_u32(resp + 18, total_ram_mb);
        put_u32(resp + 22, total_swap_mb);
    }

    /* [26-29] Root partition size MB, [30-31] FS type code */
    {
        struct statfs sfs;
        uint32_t root_size_mb = 0;
        uint16_t fs_code      = FS_UNKNOWN;
        if (statfs("/", &sfs) == 0) {
            uint64_t bsz = sfs.f_frsize ? (uint64_t)sfs.f_frsize
                                        : (uint64_t)sfs.f_bsize;
            root_size_mb = (uint32_t)(sfs.f_blocks * bsz / (1024 * 1024));
            fs_code = detect_fs_type(sfs.f_type);
        }
        put_u32(resp + 26, root_size_mb);
        put_u16(resp + 30, fs_code);
    }

    /* [32] RPI type */
    resp[32] = detect_rpi_type();

    /* [33] Reserved */
    resp[33] = 0x00;

    /* [34-35] SW 0x9000 */
    resp[34] = 0x90;
    resp[35] = 0x00;

    return CAPS_RESP_LEN;
}
