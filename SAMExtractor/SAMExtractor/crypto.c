#include "global.h"
#include "crypto.h"

BOOL CryptoHKey(HCRYPTPROV hProv, ALG_ID calgid, LPCVOID key, DWORD keyLen, DWORD flags, HCRYPTKEY* hKey, HCRYPTPROV* hSessionProv)
{
	BOOL status = FALSE;
	PGENERICKEY_BLOB keyBlob;
	DWORD szBlob = sizeof(GENERICKEY_BLOB) + keyLen;

	if (calgid != CALG_3DES)
	{
		if (keyBlob = (PGENERICKEY_BLOB)LocalAlloc(LPTR, szBlob))
		{
			keyBlob->Header.bType = PLAINTEXTKEYBLOB;
			keyBlob->Header.bVersion = CUR_BLOB_VERSION;
			keyBlob->Header.reserved = 0;
			keyBlob->Header.aiKeyAlg = calgid;
			keyBlob->dwKeyLen = keyLen;
			RtlCopyMemory((PBYTE)keyBlob + sizeof(GENERICKEY_BLOB), key, keyBlob->dwKeyLen);
			status = CryptImportKey(hProv, (LPCBYTE)keyBlob, szBlob, 0, flags, hKey);
			LocalFree(keyBlob);
		}
	}

	return status;
}


BOOL AES128Decrypt(LPCVOID pKey, LPCVOID pIV, LPCVOID pData, DWORD dwDataLen, LPVOID* pOut, DWORD* dwOutLen)
{
	BOOL status = FALSE;
	HCRYPTPROV hProv;
	HCRYPTKEY hKey;
	DWORD mode = CRYPT_MODE_CBC;

	if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
	{
		if (CryptoHKey(hProv, CALG_AES_128, pKey, 16, 0, &hKey, NULL))
		{
			if (CryptSetKeyParam(hKey, KP_MODE, (LPCBYTE)&mode, 0))
			{
				if (CryptSetKeyParam(hKey, KP_IV, (LPCBYTE)pIV, 0))
				{
					if (*pOut = LocalAlloc(LPTR, dwDataLen))
					{
						*dwOutLen = dwDataLen;
						RtlCopyMemory(*pOut, pData, dwDataLen);
						if (!(status = CryptDecrypt(hKey, 0, TRUE, 0, (PBYTE)*pOut, dwOutLen)))
						{
							wprintf(L"CryptDecrypt");
							*pOut = LocalFree(*pOut);
							*dwOutLen = 0;
						}
					}
				}
				else wprintf(L"CryptSetKeyParam (IV)");
			}
			else wprintf(L"CryptSetKeyParam (MODE)");
			CryptDestroyKey(hKey);
		}
		else wprintf(L"kull_m_crypto_hkey");
		CryptReleaseContext(hProv, 0);
	}
	else wprintf(L"CryptAcquireContext");
	return status;
}