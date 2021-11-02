#pragma once
#include "global.h"

typedef struct _GENERICKEY_BLOB {
	BLOBHEADER Header;
	DWORD dwKeyLen;
} GENERICKEY_BLOB, * PGENERICKEY_BLOB;

BOOL AES128Decrypt(LPCVOID pKey, LPCVOID pIV, LPCVOID pData, DWORD dwDataLen, LPVOID* pOut, DWORD* dwOutLen);
BOOL CryptoHKey(HCRYPTPROV hProv, ALG_ID calgid, LPCVOID key, DWORD keyLen, DWORD flags, HCRYPTKEY* hKey, HCRYPTPROV* hSessionProv);