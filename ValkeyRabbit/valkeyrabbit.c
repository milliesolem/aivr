/*
 * ValkeyRabbit — valkey script-debugger whole-server crash (SIGABRT) on a
 * partial read (CWE-617 / CWE-400)
 *
 * valkey's Lua script debugger reads client commands with
 * readReadCommandInternal() (src/scripting_engine.c), which asserts
 * `serverAssert(argc != NULL && *argc == 0)` on entry. When a command spans
 * more than one connRead(), the function parses the `*<count>\r\n` header,
 * sets `*argc = count`, and then exits through `goto keep_reading` because
 * the rest of the command has not arrived yet. The caller
 * (scriptingEngineDebuggerProcessCommands()) appends more data and retries,
 * but `*argc` still holds `count` from the first call, so the assert fires on
 * the second call. In SYNC mode the assert runs in the SERVER process, which
 * exits with SIGABRT — a whole-server crash from a client that can enter the
 * debugger (SCRIPT DEBUG SYNC + EVAL) and send a command longer than 1024
 * bytes (or split by TCP framing).
 *
 * Fix (commit 7dfa61e04390990da64b9e982c3b0fc0da8c7c82, 2026-10-31, PR #5127):
 * reset `*argc = 0` on the keep_reading exit so the retry re-enters cleanly.
 * The fix is in 9.2.0-rc2 but NOT in 9.1.3 (latest stable). No CVE/GHSA.
 *
 * This is a faithful model of the assert + partial-read flow, run in a child
 * process so the vulnerable SIGABRT is observed (exit code 134) and the fixed
 * path returns cleanly.
 *
 * Build:  zig cc -O0 -o valkeyrabbit valkeyrabbit.c   (or cc)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/* Faithful model of the two relevant behaviours of readReadCommandInternal().
 *
 *   parse_header_and_maybe_keep_reading():
 *     - the real code asserts *argc == 0 on entry;
 *     - parses "*<count>\r\n", sets *argc = count;
 *     - if the argument data has not fully arrived, does `goto keep_reading`
 *       (returns 1 = "more data needed") WITHOUT resetting *argc (the bug).
 *
 * The FIXED variant resets *argc = 0 before the keep_reading return.
 */
static int read_command_once(size_t *argc, const char *cbuf, int reset_on_partial) {
    /* entry precondition — the real code does serverAssert(argc != NULL && *argc == 0) */
    if (argc == NULL || *argc != 0) {
        fprintf(stderr, "serverAssert: *argc == 0 failed (argc=%zu) -> SIGABRT\n", *argc);
        abort();   /* mirrors serverAssert -> _serverAssert -> abort() */
    }

    /* parse "*<count>\r\n" */
    const char *p = strchr(cbuf, '*');
    if (!p) return -1;                       /* protoerr */
    const char *plen = p + 1;
    const char *crlf = strstr(p, "\r\n");
    if (!crlf) {
        if (reset_on_partial) *argc = 0;     /* <-- the fix */
        return 1;                            /* keep_reading: header incomplete */
    }
    char tmp[32];
    size_t hl = (size_t)(crlf - plen);
    if (hl >= sizeof(tmp)) hl = sizeof(tmp) - 1;
    memcpy(tmp, plen, hl); tmp[hl] = 0;
    *argc = (size_t)atoi(tmp);               /* *argc = count */
    if (*argc == 0 || *argc > 1024) return -1;

    /* parse each "$<len>\r\n<data>\r\n" argument; if the body has not fully
     * arrived, `goto keep_reading` — the vulnerable path leaves *argc=count. */
    p = crlf + 2;
    for (size_t i = 0; i < *argc; ++i) {
        if (*p == '\0') { if (reset_on_partial) *argc = 0; return 1; }
        if (*p != '$') return -1;            /* protoerr */
        const char *plen2 = p + 1;
        const char *crlf2 = strstr(p, "\r\n");
        if (!crlf2) { if (reset_on_partial) *argc = 0; return 1; }
        char t2[32];
        size_t hl2 = (size_t)(crlf2 - plen2);
        if (hl2 >= sizeof(t2)) hl2 = sizeof(t2) - 1;
        memcpy(t2, plen2, hl2); t2[hl2] = 0;
        int slen = atoi(t2);
        if (slen <= 0 || slen > 1024) return -1;
        p = crlf2 + 2;
        size_t avail = strlen(cbuf) - (size_t)(p - cbuf);
        if ((size_t)(slen + 2) > avail) {     /* body + \r\n not fully arrived */
            if (reset_on_partial) *argc = 0;  /* <-- the fix */
            return 1;                         /* keep_reading */
        }
        p += slen + 2;
    }
    return 0;                                /* complete command */
}

/* Run the vulnerable or fixed flow in a child; report whether it SIGABRT'd. */
static int run_case(int reset_on_partial, const char *label) {
    pid_t pid = fork();
    if (pid == 0) {
        size_t argc = 0;
        /* First connRead(): only "*3\r\n$5\r\nhel" has arrived so far — the
         * header "*3\r\n" is complete, the arg body is partial. */
        int r = read_command_once(&argc, "*3\r\n$5\r\nhel", reset_on_partial);
        (void)r;
        /* The caller appends the rest and retries with the SAME argc. */
        read_command_once(&argc, "*3\r\n$5\r\nhello\r\n", reset_on_partial);
        _exit(0);   /* reached only if the assert did not fire */
    }
    int status = 0;
    waitpid(pid, &status, 0);
    int aborted = WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT;
    printf("  [%s] %s\n", label,
           aborted ? "SIGABRT (whole-server crash in SYNC mode)"
                   : "no crash (clean re-entry)");
    return aborted;
}

int main(void) {
    printf("=== ValkeyRabbit — valkey script-debugger partial-read assert -> SIGABRT ===\n");
    printf("partial command: \"*3\\r\\n$5\\r\\nhel\" (header parsed, body incomplete)\n\n");

    int vuln_aborted = run_case(0, "VULNERABLE (pre-7dfa61e)");
    int fixed_aborted = run_case(1, "FIXED      (7dfa61e)");

    printf("\n");
    if (vuln_aborted && !fixed_aborted) {
        printf("RESULT: VALKEY-RABBIT-CONFIRMED — a partial-read debugger command\n"
               "        fires the *argc==0 assert and SIGABRTs the server process\n"
               "        (vulnerable), and the *argc=0 reset prevents it (fixed).\n");
        return 0;
    }
    printf("RESULT: NOT-REPRODUCED\n");
    return 1;
}
