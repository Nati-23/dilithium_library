#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "dilithium/dilithium.h"

/* ── Helpers ── */

static void read_line(char *buf, size_t max_len, int web_mode, const char *prompt) {
  if (!web_mode && prompt) { printf("%s", prompt); fflush(stdout); }
  if (fgets(buf, max_len, stdin) == NULL) { buf[0] = '\0'; return; }
  size_t len = strlen(buf);
  while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r')) buf[--len] = '\0';
}

static int hex_to_val(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

/* Save raw bytes as a continuous hex string in a text file */
static int save_file_hex(const char *filename, const uint8_t *data, size_t len) {
  FILE *f = fopen(filename, "w");
  if (!f) return -1;
  for (size_t i = 0; i < len; i++) fprintf(f, "%02x", data[i]);
  fclose(f);
  return 0;
}

/* Load hex string from a text file back into raw bytes */
static int load_file_hex(const char *filename, uint8_t *data, size_t max_len, size_t *loaded_len) {
  FILE *f = fopen(filename, "r");
  if (!f) return -1;
  size_t count = 0;
  while (count < max_len) {
    int c1 = fgetc(f);
    if (c1 == EOF || c1 == '\n' || c1 == '\r' || c1 == ' ' || c1 == '\t') break;
    int c2 = fgetc(f);
    if (c2 == EOF || c2 == '\n' || c2 == '\r') { fclose(f); return -1; }
    int v1 = hex_to_val(c1), v2 = hex_to_val(c2);
    if (v1 < 0 || v2 < 0) { fclose(f); return -1; }
    data[count++] = (uint8_t)((v1 << 4) | v2);
  }
  fclose(f);
  *loaded_len = count;
  return 0;
}

/* Save a plain text message to file exactly as typed */
static int save_message_file(const char *filename, const char *msg) {
  FILE *f = fopen(filename, "w");
  if (!f) return -1;
  fprintf(f, "%s", msg);
  fclose(f);
  return 0;
}

/* Load a plain text message from file; strips trailing newlines */
static int load_message_file(const char *filename, char *buf, size_t max_len, size_t *mlen_out) {
  FILE *f = fopen(filename, "r");
  if (!f) return -1;
  size_t total = 0;
  int c;
  while (total < max_len - 1 && (c = fgetc(f)) != EOF) buf[total++] = (char)c;
  fclose(f);
  buf[total] = '\0';
  while (total > 0 && (buf[total - 1] == '\n' || buf[total - 1] == '\r')) buf[--total] = '\0';
  *mlen_out = total;
  return 0;
}

/* ── Main ── */

int main(int argc, char **argv) {
  int web_mode = 0;
  if (argc > 1 && strcmp(argv[1], "--web") == 0) web_mode = 1;

  char option_buf[32];
  char input1[512];   /* key / pub key filename */
  char input2[2048];  /* message text  / message filename */
  char input3[512];   /* output name   / sig filename */

  while (1) {
    if (!web_mode) {
      printf("\n--- Dilithium Signature CLI ---\n");
      printf("1. Generate Keypair\n");
      printf("2. Sign a Message\n");
      printf("3. Verify a Signature\n");
      printf("4. Exit\n");
    }

    read_line(option_buf, sizeof(option_buf), web_mode, "Enter option: ");
    if (strlen(option_buf) == 0) { if (feof(stdin)) break; continue; }
    int option = atoi(option_buf);

    /* ───────────────────────────────── Option 1: Generate Keypair */
    if (option == 1) {
      read_line(input1, sizeof(input1), web_mode, "Enter key name: ");

      uint8_t pk[CRYPTO_PUBLICKEYBYTES];
      uint8_t sk[CRYPTO_SECRETKEYBYTES];

      if (crypto_sign_keypair(pk, sk) != 0) {
        fprintf(stderr, "Error: Key generation failed\n");
        continue;
      }

      char pub_fn[512 + 16], sec_fn[512 + 16];
      sprintf(pub_fn, "%s_pub.txt", input1);
      sprintf(sec_fn, "%s_sec.txt", input1);

      if (save_file_hex(pub_fn, pk, CRYPTO_PUBLICKEYBYTES) != 0) {
        fprintf(stderr, "Error: Could not save public key\n"); continue;
      }
      if (save_file_hex(sec_fn, sk, CRYPTO_SECRETKEYBYTES) != 0) {
        fprintf(stderr, "Error: Could not save secret key\n"); continue;
      }

      printf("Public Key: %u bytes  ->  %s\n", (unsigned)CRYPTO_PUBLICKEYBYTES, pub_fn);
      printf("Secret Key: %u bytes  ->  %s\n", (unsigned)CRYPTO_SECRETKEYBYTES, sec_fn);
      fflush(stdout);

    /* ───────────────────────────────── Option 2: Sign a Message */
    } else if (option == 2) {
      /*
       * Inputs:
       *   1. Secret key filename  (e.g. alice_sec.txt)
       *   2. Message text         (typed by user, saved to <name>_msg.txt)
       *   3. Output name          (signature -> <name>.sig, message -> <name>_msg.txt)
       *
       * Any later edit to <name>_msg.txt will cause verification to fail.
       */
      read_line(input1, sizeof(input1), web_mode, "Enter secret key filename: ");
      read_line(input2, sizeof(input2), web_mode, "Enter message to sign: ");
      read_line(input3, sizeof(input3), web_mode, "Enter output name (for message + signature files): ");

      /* Load secret key */
      uint8_t sk[CRYPTO_SECRETKEYBYTES];
      size_t sk_len;
      if (load_file_hex(input1, sk, CRYPTO_SECRETKEYBYTES, &sk_len) != 0 || sk_len != CRYPTO_SECRETKEYBYTES) {
        fprintf(stderr, "Error: Could not read secret key from %s\n", input1);
        continue;
      }

      /* Save the message as a plain text file */
      char msg_fn[512 + 16];
      sprintf(msg_fn, "%s_msg.txt", input3);
      if (save_message_file(msg_fn, input2) != 0) {
        fprintf(stderr, "Error: Could not save message file %s\n", msg_fn);
        continue;
      }

      /* Sign the message */
      uint8_t sig[CRYPTO_BYTES];
      size_t siglen;
      if (crypto_sign_signature(sig, &siglen, (const uint8_t *)input2, strlen(input2), sk) != 0) {
        fprintf(stderr, "Error: Signing failed\n");
        continue;
      }

      /* Save signature as hex text file */
      char sig_fn[512 + 16];
      sprintf(sig_fn, "%s.sig", input3);
      if (save_file_hex(sig_fn, sig, siglen) != 0) {
        fprintf(stderr, "Error: Could not save signature file %s\n", sig_fn);
        continue;
      }

      printf("Message saved to  : %s\n", msg_fn);
      printf("Signature saved to: %s\n", sig_fn);
      printf("Signature Size    : %zu bytes\n", siglen);
      fflush(stdout);

    /* ───────────────────────────────── Option 3: Verify a Signature */
    } else if (option == 3) {
      /*
       * Inputs:
       *   1. Public key filename   (e.g. alice_pub.txt)
       *   2. Message filename      (e.g. alicesig_msg.txt  — the file saved during signing)
       *   3. Signature filename    (e.g. alicesig.sig)
       *
       * Message is read from the FILE — if anyone edited it, verification will print INVALID.
       */
      read_line(input1, sizeof(input1), web_mode, "Enter public key filename: ");
      read_line(input2, sizeof(input2), web_mode, "Enter message filename: ");
      read_line(input3, sizeof(input3), web_mode, "Enter signature filename: ");

      /* Load public key */
      uint8_t pk[CRYPTO_PUBLICKEYBYTES];
      size_t pk_len;
      if (load_file_hex(input1, pk, CRYPTO_PUBLICKEYBYTES, &pk_len) != 0 || pk_len != CRYPTO_PUBLICKEYBYTES) {
        fprintf(stderr, "Error: Could not read public key from %s\n", input1);
        printf("INVALID\n"); fflush(stdout); continue;
      }

      /* Load message from plain text file */
      char msg_buf[2048];
      size_t mlen;
      if (load_message_file(input2, msg_buf, sizeof(msg_buf), &mlen) != 0) {
        fprintf(stderr, "Error: Could not read message file %s\n", input2);
        printf("INVALID\n"); fflush(stdout); continue;
      }

      /* Load signature */
      uint8_t sig[CRYPTO_BYTES];
      size_t sig_len;
      if (load_file_hex(input3, sig, CRYPTO_BYTES, &sig_len) != 0) {
        fprintf(stderr, "Error: Could not read signature from %s\n", input3);
        printf("INVALID\n"); fflush(stdout); continue;
      }

      /* Verify */
      if (crypto_sign_verify(sig, sig_len, (const uint8_t *)msg_buf, mlen, pk) == 0) {
        printf("VALID\n");
      } else {
        printf("INVALID\n");
      }
      fflush(stdout);

    /* ───────────────────────────────── Option 4: Exit */
    } else if (option == 4) {
      if (!web_mode) printf("Exiting.\n");
      break;
    } else {
      if (!web_mode) printf("Invalid option. Please try again.\n");
    }
  }

  return 0;
}
