/*
 * Copyright (c) 2026 Vincent Ping (vincentping@gmail.com)
 * SPDX-License-Identifier: Apache-2.0
 */
/*
 * asyd.c — ASys Daemon v0.3.0 (Phase 5)
 *
 * Trust model: public-key whitelist only (spec §2.1).
 *   - whitelist_load() reads /etc/asyd/authorized_agents at startup
 *   - After Noise IK handshake, agent pubkey checked against whitelist
 *   - Unknown agent → SW=0x6982, disconnect
 *   - No token, no registration flow, no extra handshake round-trips
 *
 * Build: make  (from project root)
 * Run:   bin/asyd
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <signal.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/wait.h>
#include <getopt.h>
#include <stdlib.h>

#include "apdu_parser.h"
#include "dispatcher.h"
#include "noise_ik.h"
#include "whitelist.h"
#include "auth_verify.h"
#include "task_pool.h"
#include "crypto_utils.h"
#include "monocypher.h"

/*
 * LISTEN_BACKLOG / MAX_CLIENTS are intentionally kept equal and small (8).
 * asyd is designed for a handful of trusted AI Agents, not public traffic.
 * When the slot pool is full, new connections are rejected immediately at
 * accept() time — this is deliberate back-pressure, not a bug.
 *
 * Phase 6 TODO: split into separate #defines so LISTEN_BACKLOG (kernel queue
 * depth) and MAX_CLIENTS (concurrent session cap) can be tuned independently.
 */
#define LISTEN_BACKLOG 8
#define ASYD_VERSION   "0.3.0"

/* ── Graceful shutdown ──────────────────────────────────────── */
static volatile sig_atomic_t g_stop = 0;
static volatile sig_atomic_t g_reload_whitelist = 0;
static int g_srv_fd = -1;

int g_debug = 0;

#define DBG(fmt, ...) \
    do { if (g_debug) fprintf(stderr, "[asyd][DBG] " fmt "\n", ##__VA_ARGS__); } while(0)

/* ── Per-connection slot pool (zero-malloc, statically pre-allocated) ─ */
#define MAX_CLIENTS LISTEN_BACKLOG

typedef struct {
    int     fd;
    char    peer_ip[INET_ADDRSTRLEN];
    int     in_use;   /* 1 = occupied; 0 = free                         */
} ClientSlot;

static ClientSlot      g_cslots[MAX_CLIENTS];
static pthread_mutex_t g_cslots_lock = PTHREAD_MUTEX_INITIALIZER;

static void handle_signal(int sig)
{
    (void)sig;
    g_stop = 1;
    if (g_srv_fd >= 0) close(g_srv_fd);   /* unblocks accept()          */
    /* Close all active connections to unblock recv_exact() in each thread.
     * Reading g_cslots without the lock is safe here: the worst case is
     * missing one close(), which SO_RCVTIMEO will handle within 60s. */
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_cslots[i].in_use)
            close(g_cslots[i].fd);
    }
}

#ifndef KEY_PRIV_PATH
#define KEY_PRIV_PATH  "/etc/asyd/id_curve25519"
#endif
#ifndef KEY_PUB_PATH
#define KEY_PUB_PATH   "/etc/asyd/id_curve25519.pub"
#endif

/* ── Server static key pair ─────────────────────────────────── */
static uint8_t g_server_priv[NOISE_KEY_SIZE];
static uint8_t g_server_pub [NOISE_KEY_SIZE];

/* ── Agent whitelist (loaded once at startup) ───────────────── */
static Whitelist g_whitelist;

static void handle_sighup(int sig)
{
    (void)sig;
    g_reload_whitelist = 1;
}

/* ── Session ID counter (protected by g_session_id_lock) ────── */
static uint16_t        g_next_session_id = 1;
static pthread_mutex_t g_session_id_lock = PTHREAD_MUTEX_INITIALIZER;

/* ── Per-connection context ──────────────────────────────────── */
typedef struct {
    int          fd;
    uint16_t     session_id;
    char         peer_ip[INET_ADDRSTRLEN];  /* IPv4 only; INET_ADDRSTRLEN = 16 */
    NoiseIKState noise;
    uint8_t      agent_pub[NOISE_KEY_SIZE];
    uint8_t      epoch_id[4];       /* derived from recv_key post-handshake  */
    uint32_t     last_seen_seq;     /* in-memory replay gate, reset per conn */
} SessionCtx;

/* ── Key management ──────────────────────────────────────────── */

/* Format first 8 bytes of buf as hex into out[17]. Thread-safe (stack buffer). */
static void hex8(const uint8_t *b, char out[17])
{
    for (int i = 0; i < 8; i++)
        snprintf(out + i*2, 3, "%02x", b[i]);
    out[16] = '\0';
}

static int load_or_generate_keys(void)
{
    mkdir("/etc/asyd", 0700);        /* ignore error — may already exist */
    chmod("/etc/asyd", 0700);        /* enforce even if created externally */

    /* Early permission check — give actionable error before hitting fopen */
    if (access("/etc/asyd", R_OK | W_OK | X_OK) != 0) {
        printf("[asyd] Cannot access /etc/asyd/ (uid=%d): %s\n",
               (int)getuid(), strerror(errno));
        printf("[asyd] Fix:  sudo chown %d /etc/asyd\n", (int)getuid());
        return -1;
    }

    /* Try to load both key files */
    FILE *fp = fopen(KEY_PRIV_PATH, "rb");
    FILE *fq = fopen(KEY_PUB_PATH,  "rb");

    if (fp && fq) {
        size_t nr = fread(g_server_priv, 1, NOISE_KEY_SIZE, fp);
        size_t nq = fread(g_server_pub,  1, NOISE_KEY_SIZE, fq);
        fclose(fp);
        fclose(fq);

        if (nr == NOISE_KEY_SIZE && nq == NOISE_KEY_SIZE) {
            char fp_hex[17];
            hex8(g_server_pub, fp_hex);
            printf("[asyd] Loaded key pair from %s  fingerprint=%s\n",
                   KEY_PRIV_PATH, fp_hex);
            return 0;
        }
        printf("[asyd] Key files corrupt, regenerating\n");
    } else {
        if (fp) fclose(fp);
        if (fq) fclose(fq);
    }

    /* Generate fresh key pair */
    noise_ik_generate_keypair(g_server_priv, g_server_pub);

    /* Write private key with mode 0600 */
    int fd = open(KEY_PRIV_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        printf("[asyd] Cannot write %s: %s\n", KEY_PRIV_PATH, strerror(errno));
        return -1;
    }
    if (write(fd, g_server_priv, NOISE_KEY_SIZE) != NOISE_KEY_SIZE) {
        printf("[asyd] Write failed %s: %s\n", KEY_PRIV_PATH, strerror(errno));
        close(fd);
        return -1;
    }
    close(fd);
    chmod(KEY_PRIV_PATH, 0600);  /* enforce even if umask altered mode */

    /* Write public key with mode 0644 */
    fd = open(KEY_PUB_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        printf("[asyd] Cannot write %s: %s\n", KEY_PUB_PATH, strerror(errno));
        return -1;
    }
    if (write(fd, g_server_pub, NOISE_KEY_SIZE) != NOISE_KEY_SIZE) {
        printf("[asyd] Write failed %s: %s\n", KEY_PUB_PATH, strerror(errno));
        close(fd);
        return -1;
    }
    close(fd);

    {
        char fp_hex[17];
        hex8(g_server_pub, fp_hex);
        printf("[asyd] Generated new keypair -> %s, %s  fingerprint=%s\n",
               KEY_PRIV_PATH, KEY_PUB_PATH, fp_hex);
    }
    return 0;
}

/* ── Helpers ─────────────────────────────────────────────────── */

static const char *ins_name(uint8_t ins)
{
    switch (ins) {
        case 0x00: return "SYS_CAPS";
        case 0x01: return "SYS_HELLO";
        case 0x02: return "SYS_STATUS";
        case 0x03: return "SYS_PROCS";
        case 0x11: return "TASK_QUERY";
        case 0x20: return "PROC_THROTTLE";
        case 0x22: return "SVC_RESTART";
        default:   return "UNKNOWN";
    }
}

static uint64_t now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)(ts.tv_nsec / 1000);
}

static ssize_t recv_exact(int fd, uint8_t *buf, size_t n)
{
    size_t got = 0;
    while (got < n) {
        ssize_t r = recv(fd, buf + got, n - got, 0);
        if (r <= 0) return r;
        got += (size_t)r;
    }
    return (ssize_t)got;
}

/* ── send_sw: encrypt and send a 2-byte status word ─────────── */
static void send_sw(SessionCtx *ctx, uint8_t sw1, uint8_t sw2)
{
    uint8_t sw[2]  = {sw1, sw2};
    uint8_t enc[2 + NOISE_MAC_SIZE];
    size_t  enc_len = 2 + NOISE_MAC_SIZE;
    if (noise_ik_encrypt(&ctx->noise, sw, 2, enc) != NOISE_OK) return;
    uint8_t pfx[2] = { (uint8_t)(enc_len >> 8), (uint8_t)(enc_len & 0xFF) };
    send(ctx->fd, pfx, 2, 0);
    send(ctx->fd, enc, enc_len, 0);
}

/* ── Background status warm thread ──────────────────────────── */
static void *status_warm_thread(void *arg)
{
    (void)arg;
    ApduFrame warm;
    memset(&warm, 0, sizeof(warm));
    warm.ins = 0x02;  /* SYS_STATUS */
    uint8_t dummy[DISP_RESP_MAX];
    while (1) {
        dispatch(&warm, dummy, sizeof(dummy), 0);  /* session_id=0: background */
        sleep(1);
    }
    return NULL;
}

/* Forward declaration — handle_client is defined after client_thread */
static void handle_client(int cfd, const char *peer_ip);

/* ── Per-connection thread ───────────────────────────────────── */
static void *client_thread(void *arg)
{
    /*
     * Block SIGCHLD in every client worker thread so it is delivered only to
     * the main thread (which installed the sigchld_handler).  Without this,
     * SIGCHLD from a completed SVC_RESTART child can interrupt the recv() in
     * handle_client, causing recv() to return EINTR, which the caller
     * interprets as a connection error and tears down the session.
     */
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    pthread_sigmask(SIG_BLOCK, &mask, NULL);

    ClientSlot *slot = (ClientSlot *)arg;
    handle_client(slot->fd, slot->peer_ip);
    printf("[asyd] - %s disconnected\n", slot->peer_ip);
    close(slot->fd);
    pthread_mutex_lock(&g_cslots_lock);
    slot->in_use = 0;
    pthread_mutex_unlock(&g_cslots_lock);
    return NULL;
}

/* ── Per-connection handler ──────────────────────────────────── */
static void handle_client(int cfd, const char *peer_ip)
{
    SessionCtx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.fd = cfd;

    pthread_mutex_lock(&g_session_id_lock);
    ctx.session_id = g_next_session_id++;
    if (g_next_session_id == 0) g_next_session_id = 1;  /* skip 0 */
    pthread_mutex_unlock(&g_session_id_lock);

    strncpy(ctx.peer_ip, peer_ip, sizeof(ctx.peer_ip) - 1);

    ApduParser *p = NULL;

    /* ── Pre-Handshake Frame ─────────────────────────────── */
    /* 38-byte plaintext: Magic(4B) + Version(2B) + ServerPubKey(32B)
     * Sent before Noise IK so the client can verify server identity
     * and manage known_hosts without prior out-of-band key exchange. */
    {
        uint8_t phf[38];
        phf[0] = 0x41; phf[1] = 0x53; phf[2] = 0x59; phf[3] = 0x53; /* "ASYS" */
        phf[4] = 0x01; phf[5] = 0x00;                                  /* v1.0 BE */
        memcpy(phf + 6, g_server_pub, NOISE_KEY_SIZE);
        if (send(ctx.fd, phf, sizeof(phf), 0) != (ssize_t)sizeof(phf))
            goto cleanup;
    }

    /* ── Noise IK Handshake ─────────────────────────────── */

    noise_ik_init_server(&ctx.noise, g_server_priv, g_server_pub);

    /* Step 2: recv msg1 (96 bytes, bare TCP, no length prefix) */
    uint8_t msg1[NOISE_MSG1_SIZE];
    if (recv_exact(ctx.fd, msg1, NOISE_MSG1_SIZE) != NOISE_MSG1_SIZE)
        goto cleanup;

    /* Step 3: read msg1, extract agent public key */
    if (noise_ik_read_msg1(&ctx.noise, msg1, ctx.agent_pub) != NOISE_OK) {
        printf("[asyd] %s handshake auth failed\n", ctx.peer_ip);
        goto cleanup;
    }

    /* Step 4: write msg2 (48 bytes, bare TCP, no length prefix) */
    {
        uint8_t msg2[NOISE_MSG2_SIZE];
        noise_ik_write_msg2(&ctx.noise, msg2);
        if (send(ctx.fd, msg2, NOISE_MSG2_SIZE, 0) != NOISE_MSG2_SIZE)
            goto cleanup;
    }

    /* Step 5: derive Epoch_ID from recv_key (spec §2.2.3, Epoch_ID model).
     * HMAC-BLAKE2b(recv_key, "asys-epoch-v1")[:4] — never transmitted on wire.
     * Client derives the same value using its send_key (== server's recv_key). */
    {
        uint8_t epoch_digest[64];
        hmac_blake2b(epoch_digest, ctx.noise.recv_key, 32,
                     (const uint8_t *)"asys-epoch-v1", 13);
        memcpy(ctx.epoch_id, epoch_digest, 4);
        crypto_wipe(epoch_digest, sizeof(epoch_digest));
    }

    /* Step 6: handshake complete */
    {
        char fp[17];
        hex8(ctx.agent_pub, fp);
        printf("[asyd] %s handshake OK  agent=%s\n", ctx.peer_ip, fp);
    }

    /* ── Whitelist check ────────────────────────────────────── */
    if (whitelist_check(&g_whitelist, ctx.agent_pub) != WL_OK) {
        char fp[17];
        hex8(ctx.agent_pub, fp);
        printf("[asyd] %s agent not in whitelist (agent=%s) -> 0x6982\n",
               ctx.peer_ip, fp);
        send_sw(&ctx, 0x69, 0x82);
        goto cleanup;
    }
    printf("[asyd] %s agent known, access granted\n", ctx.peer_ip);

    /* ── Encrypted APDU loop ────────────────────────────── */

    p = apdu_pool_acquire();
    if (!p) {
        printf("[asyd] %s pool exhausted\n", ctx.peer_ip);
        goto cleanup;
    }

    {
        /*
         * Wire framing (both directions):
         *   [uint16_t BE ciphertext_len][ciphertext + MAC(16)]
         *
         * ciphertext_len = plaintext_len + NOISE_MAC_SIZE
         * One Noise packet = one APDU frame.
         */
        uint8_t cipher_buf[APDU_MAX_FRAME_SIZE + NOISE_MAC_SIZE];
        uint8_t enc_buf[DISP_RESP_MAX + NOISE_MAC_SIZE];
        uint8_t resp[DISP_RESP_MAX];

        for (;;) {
            /* Receive 2-byte length prefix (big-endian) */
            uint8_t len_buf[2];
            if (recv_exact(ctx.fd, len_buf, 2) != 2) break;
            uint16_t ciphertext_len = (uint16_t)((len_buf[0] << 8) | len_buf[1]);

            if (ciphertext_len < NOISE_MAC_SIZE || ciphertext_len > sizeof(cipher_buf)) break;

            /* Receive ciphertext */
            if (recv_exact(ctx.fd, cipher_buf, ciphertext_len) != (ssize_t)ciphertext_len) break;

            /* Decrypt directly into parser buffer */
            size_t   max_plain;
            uint8_t *dst = apdu_parser_recv_ptr(p, &max_plain);
            size_t   plain_len = ciphertext_len - NOISE_MAC_SIZE;
            if (plain_len > max_plain) break;

            if (noise_ik_decrypt(&ctx.noise, cipher_buf, ciphertext_len, dst) != NOISE_OK) {
                printf("[asyd] %s decrypt failed\n", ctx.peer_ip);
                break;
            }
            apdu_parser_recv_commit(p, plain_len);

            ApduFrame frame;
            int rc = apdu_parser_try_parse(p, &frame);

            if (rc == APDU_NEED_MORE)
                continue;

            if (rc == APDU_ERR_VERSION) {
                send_sw(&ctx, 0x6E, 0x00);
                printf("[asyd] %s CLA version error -> 0x6E00\n", ctx.peer_ip);
                break;
            }
            if (rc == APDU_ERR_RFU || rc == APDU_ERR_EXT_LC || rc == APDU_ERR_LENGTH) {
                send_sw(&ctx, 0x67, 0x00);
                printf("[asyd] %s frame parse error (rc=%d) -> 0x6700\n",
                       ctx.peer_ip, rc);
                break;
            }
            if (rc != APDU_FRAME_READY) break;

            /* ── Auth Tag verification (Epoch_ID model, spec §2.2.3) ── */
            if (frame.sec != APDU_SEC_PLAIN) {
                if (!verify_auth_tag(&ctx.noise, &frame, ctx.epoch_id)) {
                    printf("[asyd] %s auth tag verification failed -> 0x6982\n",
                           ctx.peer_ip);
                    send_sw(&ctx, 0x69, 0x82);
                    goto cleanup;
                }

                /* In-session Seq replay check (spec §2.2.4).
                 * Seq starts at 1 per connection; last_seen_seq=0 at connect.
                 * Seq=0 is permanently rejected by the <= guard. */
                uint32_t seq = ((uint32_t)frame.data[0] << 24)
                             | ((uint32_t)frame.data[1] << 16)
                             | ((uint32_t)frame.data[2] <<  8)
                             |  (uint32_t)frame.data[3];

                if (seq <= ctx.last_seen_seq) {
                    printf("[asyd] %s seq replay detected seq=%u last=%u -> 0x6985\n",
                           ctx.peer_ip, seq, ctx.last_seen_seq);
                    send_sw(&ctx, (uint8_t)(SW_REPLAY_DETECTED >> 8),
                                 (uint8_t)(SW_REPLAY_DETECTED & 0xFF));
                    goto cleanup;
                }
                ctx.last_seen_seq = seq;
            }

            uint64_t t0 = now_us();
            int resp_len = dispatch(&frame, resp, sizeof(resp), ctx.session_id);
            uint64_t elapsed_us = now_us() - t0;
            uint16_t sw = (uint16_t)(((uint16_t)resp[resp_len-2] << 8) | resp[resp_len-1]);

            printf("[asyd] %s  %-12s -> %3dB  SW=%04X  %lluus\n",
                   ctx.peer_ip, ins_name(frame.ins), resp_len, sw,
                   (unsigned long long)elapsed_us);

            apdu_parser_consume(p, &frame);

            /* Encrypt and send response */
            if (noise_ik_encrypt(&ctx.noise, resp, (size_t)resp_len, enc_buf) != NOISE_OK) break;

            size_t enc_len = (size_t)resp_len + NOISE_MAC_SIZE;
            uint8_t prefix[2] = { (uint8_t)(enc_len >> 8), (uint8_t)(enc_len & 0xFF) };
            if (send(ctx.fd, prefix, 2, 0) != 2) break;
            if (send(ctx.fd, enc_buf, enc_len, 0) != (ssize_t)enc_len) break;
        }
    }

cleanup:
    noise_ik_wipe(&ctx.noise);
    if (p) apdu_pool_release(p);
    task_pool_release_session(ctx.session_id);
    /* close(cfd) is handled by caller (main) */
}

/* ── SIGCHLD handler: reap SVC_RESTART children ─────────────── */
static void sigchld_handler(int sig)
{
    (void)sig;
    int   status;
    pid_t pid;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        int exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        task_pool_update_by_pid(pid,
            exit_code == 0 ? TASK_SUCCESS : TASK_FAILED);
    }
}

/* ── Command-line arguments ──────────────────────────────────── */
typedef struct {
    uint16_t port;
    char     listen[46];  /* IPv4 or IPv6 address string */
    int      debug;
} AsydConfig;

static const struct option long_opts[] = {
    { "port",   required_argument, NULL, 'p' },
    { "listen", required_argument, NULL, 'l' },
    { "debug",  no_argument,       NULL, 'd' },
    { NULL, 0, NULL, 0 }
};

static AsydConfig parse_args(int argc, char **argv)
{
    AsydConfig cfg = { .port = 7816, .listen = "0.0.0.0", .debug = 0 };

    int opt;
    while ((opt = getopt_long(argc, argv, "p:l:d", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'p':
            cfg.port = (uint16_t)atoi(optarg);
            if (cfg.port == 0) {
                fprintf(stderr, "asyd: invalid port: %s\n", optarg);
                exit(1);
            }
            break;
        case 'l':
            strncpy(cfg.listen, optarg, sizeof(cfg.listen) - 1);
            cfg.listen[sizeof(cfg.listen) - 1] = '\0';
            break;
        case 'd':
            cfg.debug = 1;
            break;
        default:
            fprintf(stderr, "Usage: asyd [--port <n>] [--listen <addr>] [--debug]\n");
            exit(1);
        }
    }
    return cfg;
}

/* ── main ────────────────────────────────────────────────────── */
int main(int argc, char **argv)
{
    AsydConfig cfg = parse_args(argc, argv);
    g_debug = cfg.debug;

    /* Line-buffer stdout so each printf flushes immediately when stdout is a
     * pipe (systemd StandardOutput=journal).  Without this, C stdio defaults
     * to fully-buffered mode on non-tty output and log lines may be lost on
     * crash or delayed until the buffer fills. */
    setlinebuf(stdout);

    printf("\n");
    printf("  ___   _____              \n");
    printf(" / _ \\ / ____|             \n");
    printf("| |_| | (___  _   _ ___   \n");
    printf("|  _  |\\___ \\| | | / __|  \n");
    printf("| | | |____) | |_| \\__ \\  \n");
    printf("|_| |_|_____/ \\__, |___/  \n");
    printf("                __/ |      \n");
    printf("               |___/       \n");
    printf("\n");
    printf("  ASys Daemon  v%s  —  Agentic System Interface\n", ASYD_VERSION);
    printf("  Protocol : Noise_IK_25519_ChaChaPoly_BLAKE2b\n");
    printf("  Port     : TCP %d\n", cfg.port);
    printf("  ISA      : SYS_CAPS(00) SYS_HELLO(01) SYS_STATUS(02) SYS_PROCS(03)\n");
    printf("             TASK_QUERY(11) PROC_THROTTLE(20) SVC_RESTART(22)\n");
    printf("\n");

    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, handle_signal);
    signal(SIGINT,  handle_signal);

    /* Reap SVC_RESTART children and update Task_Handle status */
    signal(SIGCHLD, sigchld_handler);

    /*
     * Lock current memory pages against OOM eviction.
     * MCL_CURRENT only — MCL_FUTURE would require thread stacks to be locked
     * at mmap time and exceeds RLIMIT_MEMLOCK in non-root dev environments.
     * Add MCL_FUTURE in production after raising the limit via /etc/security/limits.conf.
     */
    if (mlockall(MCL_CURRENT) != 0)
        printf("[asyd] mlockall failed (non-fatal): %s\n", strerror(errno));

    task_pool_init();

    /* Load or generate server static key pair */
    if (load_or_generate_keys() != 0)
        return 1;

    /* Load agent whitelist */
    if (whitelist_load(&g_whitelist) != WL_OK) {
        printf("[asyd] whitelist_load failed\n");
        return 1;
    }
    printf("[asyd] agents=%d\n", g_whitelist.count);
    /* Use sigaction without SA_RESTART so SIGHUP interrupts accept() with
     * EINTR, allowing the main loop to check g_reload_whitelist immediately. */
    {
        struct sigaction sa_hup = {0};
        sa_hup.sa_handler = handle_sighup;
        sigemptyset(&sa_hup.sa_mask);
        /* sa_flags = 0: no SA_RESTART, so accept() returns EINTR on SIGHUP */
        sigaction(SIGHUP, &sa_hup, NULL);
    }

    /* Warm up status cache before accepting connections */
    printf("[asyd] Warming SYS_STATUS cache...\n");
    {
        ApduFrame warm; memset(&warm, 0, sizeof(warm)); warm.ins = 0x02;
        uint8_t dummy[DISP_RESP_MAX];
        dispatch(&warm, dummy, sizeof(dummy), 0);
    }

    /* Background cache refresh thread */
    pthread_t warm_tid;
    if (pthread_create(&warm_tid, NULL, status_warm_thread, NULL) != 0) {
        printf("[asyd] pthread_create (warm thread): %s\n", strerror(errno));
        return 1;
    }
    pthread_detach(warm_tid);

    /* TCP socket */
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) {
        printf("[asyd] socket: %s\n", strerror(errno));
        return 1;
    }

    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, cfg.listen, &addr.sin_addr) != 1) {
        printf("[asyd] invalid listen address: %s\n", cfg.listen);
        return 1;
    }
    addr.sin_port = htons(cfg.port);

    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        printf("[asyd] bind: %s\n", strerror(errno));
        return 1;
    }
    if (listen(srv, LISTEN_BACKLOG) < 0) {
        printf("[asyd] listen: %s\n", strerror(errno));
        return 1;
    }
    g_srv_fd = srv;

    printf("[asyd] Ready on %s:%d\n\n", cfg.listen, cfg.port);

    while (!g_stop) {
        if (g_reload_whitelist) {
            g_reload_whitelist = 0;
            whitelist_load(&g_whitelist);
            printf("[asyd] SIGHUP received, whitelist reloaded — agents=%d\n",
                   g_whitelist.count);
        }

        struct sockaddr_in caddr;
        socklen_t clen = sizeof(caddr);
        int cfd = accept(srv, (struct sockaddr *)&caddr, &clen);
        if (cfd < 0) {
            if (g_stop) break;
            if (g_reload_whitelist) continue;
            printf("[asyd] accept: %s\n", strerror(errno));
            continue;
        }

        /* Disable Nagle — we send length prefix + ciphertext in separate
         * send() calls; without TCP_NODELAY the 2-byte prefix stalls for
         * one full RTT before the kernel flushes the payload. */
        int nodelay = 1;
        setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));

        /* Idle timeout: close zombie connections that hold a session slot. */
        struct timeval tv = { .tv_sec = 60, .tv_usec = 0 };
        setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        char peer_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &caddr.sin_addr, peer_ip, sizeof(peer_ip));

        /* Acquire a static slot for this connection */
        pthread_mutex_lock(&g_cslots_lock);
        ClientSlot *slot = NULL;
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (!g_cslots[i].in_use) {
                g_cslots[i].fd     = cfd;
                g_cslots[i].in_use = 1;
                memcpy(g_cslots[i].peer_ip, peer_ip, INET_ADDRSTRLEN);
                slot = &g_cslots[i];
                break;
            }
        }
        pthread_mutex_unlock(&g_cslots_lock);

        if (!slot) {
            printf("[asyd] + %s rejected (MAX_CLIENTS=%d reached)\n",
                   peer_ip, MAX_CLIENTS);
            close(cfd);
            continue;
        }

        printf("[asyd] + %s connected\n", peer_ip);

        pthread_t tid;
        if (pthread_create(&tid, NULL, client_thread, slot) != 0) {
            printf("[asyd] pthread_create: %s\n", strerror(errno));
            pthread_mutex_lock(&g_cslots_lock);
            slot->in_use = 0;
            pthread_mutex_unlock(&g_cslots_lock);
            close(cfd);
            continue;
        }
        pthread_detach(tid);
    }

    /* g_srv_fd already closed by handle_signal */
    whitelist_wipe(&g_whitelist);
    printf("[asyd] Shutting down.\n");
    return 0;
}
