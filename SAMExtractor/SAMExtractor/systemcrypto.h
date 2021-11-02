#pragma once
#include "global.h"

#define	MD5_DIGEST_LENGTH	16

#define RtlDecryptData2 SystemFunction033
#define RtlDecryptNtOwfPwdWithIndex	SystemFunction027

typedef struct _CRYPT_BUFFER {
	DWORD Length;
	DWORD MaximumLength;
	PVOID Buffer;
} CRYPT_BUFFER, * PCRYPT_BUFFER, DATA_KEY, * PDATA_KEY, CLEAR_DATA, * PCLEAR_DATA, CYPHER_DATA, * PCYPHER_DATA;

typedef struct _MD5_CTX {
	DWORD count[2];
	DWORD state[4];
	BYTE buffer[64];
	BYTE digest[MD5_DIGEST_LENGTH];
} MD5_CTX, * PMD5_CTX;

VOID WINAPI MD5Init(PMD5_CTX pCtx);
VOID WINAPI MD5Update(PMD5_CTX pCtx, LPCVOID data, DWORD cbData);
VOID WINAPI MD5Final(PMD5_CTX pCtx);