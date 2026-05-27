/*
 * test_noise_ik.c — Noise IK Handshake Self-Test
 *
 * Simulates a complete client <-> server handshake in a single process.
 * Verifies:
 *   1. Handshake completes without error
 *   2. Both sides derive identical transport keys
 *   3. Encrypt/decrypt round-trip works correctly
 *
 * Build:
 *   gcc -O2 -Wall test_noise_ik.c monocypher.c noise_ik.c -o test_noise_ik
 * Run:
 *   ./test_noise_ik
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "noise_ik.h"

/* Print a byte array as hex */
static void print_hex(const char *label, const uint8_t *buf, size_t len)
{
    printf("  %-20s: ", label);
    for (size_t i = 0; i < len; i++) printf("%02x", buf[i]);
    printf("\n");
}

int main(void)
{
    printf("=== ASys Noise IK Handshake Self-Test ===\n\n");

    /* ── Step 1: Generate static keypairs ── */
    uint8_t server_spriv[NOISE_KEY_SIZE], server_spub[NOISE_KEY_SIZE];
    uint8_t client_spriv[NOISE_KEY_SIZE], client_spub[NOISE_KEY_SIZE];

    noise_ik_generate_keypair(server_spriv, server_spub);
    noise_ik_generate_keypair(client_spriv, client_spub);

    printf("[Keys]\n");
    print_hex("server_pub", server_spub, NOISE_KEY_SIZE);
    print_hex("client_pub", client_spub, NOISE_KEY_SIZE);
    printf("\n");

    /* ── Step 2: Initialize states ── */
    NoiseIKState server, client;

    int rc = noise_ik_init_server(&server, server_spriv, server_spub);
    printf("[Init] server: %s\n", rc == NOISE_OK ? "OK" : "FAIL");

    rc = noise_ik_init_client(&client, client_spriv, client_spub, server_spub);
    printf("[Init] client: %s\n\n", rc == NOISE_OK ? "OK" : "FAIL");

    /* ── Step 3: Client writes msg1 ── */
    uint8_t msg1[NOISE_MSG1_SIZE];
    rc = noise_ik_write_msg1(&client, msg1);
    printf("[Msg1] client write: %s (%d bytes)\n",
           rc == NOISE_OK ? "OK" : "FAIL", NOISE_MSG1_SIZE);
    print_hex("msg1", msg1, NOISE_MSG1_SIZE);
    printf("\n");

    /* ── Step 4: Server reads msg1 ── */
    uint8_t recovered_client_pub[NOISE_KEY_SIZE];
    rc = noise_ik_read_msg1(&server, msg1, recovered_client_pub);
    printf("[Msg1] server read: %s\n", rc == NOISE_OK ? "OK" : "FAIL");
    print_hex("recovered_pub", recovered_client_pub, NOISE_KEY_SIZE);

    /* Verify recovered client public key matches */
    if (memcmp(recovered_client_pub, client_spub, NOISE_KEY_SIZE) == 0)
        printf("  client_pub match: OK\n\n");
    else
        printf("  client_pub match: FAIL !!!\n\n");

    /* ── Step 5: Server writes msg2 ── */
    uint8_t msg2[NOISE_MSG2_SIZE];
    rc = noise_ik_write_msg2(&server, msg2);
    printf("[Msg2] server write: %s (%d bytes)\n",
           rc == NOISE_OK ? "OK" : "FAIL", NOISE_MSG2_SIZE);
    print_hex("msg2", msg2, NOISE_MSG2_SIZE);
    printf("\n");

    /* ── Step 6: Client reads msg2 ── */
    rc = noise_ik_read_msg2(&client, msg2);
    printf("[Msg2] client read: %s\n\n", rc == NOISE_OK ? "OK" : "FAIL");

    /* ── Step 7: Verify transport keys match ── */
    printf("[Transport Keys]\n");
    print_hex("server send_key", server.send_key, NOISE_KEY_SIZE);
    print_hex("client recv_key", client.recv_key, NOISE_KEY_SIZE);
    print_hex("server recv_key", server.recv_key, NOISE_KEY_SIZE);
    print_hex("client send_key", client.send_key, NOISE_KEY_SIZE);

    int keys_ok =
        memcmp(server.send_key, client.recv_key, NOISE_KEY_SIZE) == 0 &&
        memcmp(server.recv_key, client.send_key, NOISE_KEY_SIZE) == 0;
    printf("  key match: %s\n\n", keys_ok ? "OK" : "FAIL !!!");

    /* ── Step 8: Encrypt/decrypt round-trip ── */
    printf("[Transport Encrypt/Decrypt]\n");

    const char *plaintext = "SYS_HELLO 9000 OK";
    size_t pt_len = strlen(plaintext);

    uint8_t ciphertext[256];
    uint8_t decrypted[256];

    /* Client encrypts → Server decrypts */
    rc = noise_ik_encrypt(&client,
                           (const uint8_t*)plaintext, pt_len,
                           ciphertext);
    printf("  client encrypt: %s\n", rc == NOISE_OK ? "OK" : "FAIL");

    rc = noise_ik_decrypt(&server,
                           ciphertext, pt_len + NOISE_MAC_SIZE,
                           decrypted);
    printf("  server decrypt: %s\n", rc == NOISE_OK ? "OK" : "FAIL");

    int roundtrip_ok = (rc == NOISE_OK) &&
                       (memcmp(decrypted, plaintext, pt_len) == 0);
    printf("  roundtrip match: %s\n\n", roundtrip_ok ? "OK" : "FAIL !!!");

    /* ── Step 9: Verify MAC tamper detection ── */
    printf("[MAC Tamper Detection]\n");
    ciphertext[0] ^= 0xFF;  /* corrupt first byte */
    uint8_t tampered_out[256];
    rc = noise_ik_decrypt(&server,
                           ciphertext, pt_len + NOISE_MAC_SIZE,
                           tampered_out);
    printf("  tampered decrypt: %s\n\n",
           rc == NOISE_ERR_AUTH ? "correctly rejected" : "FAIL - accepted tampered data !!!");

    /* ── Summary ── */
    printf("=== Summary ===\n");
    if (keys_ok && roundtrip_ok && rc == NOISE_ERR_AUTH)
        printf("ALL TESTS PASSED — Noise IK handshake is functional\n");
    else
        printf("SOME TESTS FAILED — check output above\n");

    /* Wipe key material */
    noise_ik_wipe(&server);
    noise_ik_wipe(&client);

    return (keys_ok && roundtrip_ok) ? 0 : 1;
}