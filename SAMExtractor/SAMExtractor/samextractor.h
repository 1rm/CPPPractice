#pragma once
#include "global.h"

#define	SYSKEY_LENGTH	16
#define	SAM_KEY_DATA_SALT_LENGTH	16
#define	SAM_KEY_DATA_KEY_LENGTH		16
#define	MD5_DIGEST_LENGTH	16

typedef struct _SAM_ENTRY {
	DWORD offset;
	DWORD lenght;
	DWORD unk;
} SAM_ENTRY, * PSAM_SENTRY;

typedef struct _SAM_HASH {
	WORD PEKID;
	WORD Revision;
	BYTE data[ANYSIZE_ARRAY];
} SAM_HASH, * PSAM_HASH;

typedef struct _SAM_HASH_AES {
	WORD PEKID;
	WORD Revision;
	DWORD dataOffset;
	BYTE Salt[SAM_KEY_DATA_SALT_LENGTH];
	BYTE data[ANYSIZE_ARRAY]; // Data
} SAM_HASH_AES, * PSAM_HASH_AES;

typedef struct _SAM_KEY_DATA_AES {
	DWORD Revision; // 2
	DWORD Length;
	DWORD CheckLen;
	DWORD DataLen;
	BYTE Salt[SAM_KEY_DATA_SALT_LENGTH];
	BYTE data[ANYSIZE_ARRAY]; // Data, then Check
} SAM_KEY_DATA_AES, * PSAM_KEY_DATA_AES;

typedef struct _OLD_LARGE_INTEGER {
	ULONG LowPart;
	LONG HighPart;
} OLD_LARGE_INTEGER, * POLD_LARGE_INTEGER;

typedef  enum _DOMAIN_SERVER_ENABLE_STATE
{
	DomainServerEnabled = 1,
	DomainServerDisabled
} DOMAIN_SERVER_ENABLE_STATE, * PDOMAIN_SERVER_ENABLE_STATE;

typedef  enum _DOMAIN_SERVER_ROLE
{
	DomainServerRoleBackup = 2,
	DomainServerRolePrimary = 3
} DOMAIN_SERVER_ROLE, * PDOMAIN_SERVER_ROLE;

typedef struct _SAM_KEY_DATA {
	DWORD Revision;
	DWORD Length;
	BYTE Salt[SAM_KEY_DATA_SALT_LENGTH];
	BYTE Key[SAM_KEY_DATA_KEY_LENGTH];
	BYTE CheckSum[MD5_DIGEST_LENGTH];
	DWORD unk0;
	DWORD unk1;
} SAM_KEY_DATA, * PSAM_KEY_DATA;

typedef struct _DOMAIN_ACCOUNT_F {
	WORD Revision;
	WORD unk0;
	DWORD unk1;
	OLD_LARGE_INTEGER CreationTime;
	OLD_LARGE_INTEGER DomainModifiedCount;
	OLD_LARGE_INTEGER MaxPasswordAge;
	OLD_LARGE_INTEGER MinPasswordAge;
	OLD_LARGE_INTEGER ForceLogoff;
	OLD_LARGE_INTEGER LockoutDuration;
	OLD_LARGE_INTEGER LockoutObservationWindow;
	OLD_LARGE_INTEGER ModifiedCountAtLastPromotion;
	DWORD NextRid;
	DWORD PasswordProperties;
	WORD MinPasswordLength;
	WORD PasswordHistoryLength;
	WORD LockoutThreshold;
	DOMAIN_SERVER_ENABLE_STATE ServerState;
	DOMAIN_SERVER_ROLE ServerRole;
	BOOL UasCompatibilityRequired;
	DWORD unk2;
	SAM_KEY_DATA keys1;
	SAM_KEY_DATA keys2;
	DWORD unk3;
	DWORD unk4;
} DOMAIN_ACCOUNT_F, * PDOMAIN_ACCOUNT_F;

typedef struct _USER_ACCOUNT_V {
	SAM_ENTRY unk0_header;
	SAM_ENTRY Username;
	SAM_ENTRY Fullname;
	SAM_ENTRY Comment;
	SAM_ENTRY UserComment;
	SAM_ENTRY unk1;
	SAM_ENTRY Homedir;
	SAM_ENTRY HomedirConnect;
	SAM_ENTRY ScriptPath;
	SAM_ENTRY ProfilePath;
	SAM_ENTRY Workstations;
	SAM_ENTRY HoursAllowed;
	SAM_ENTRY unk2;
	SAM_ENTRY LMHash;
	SAM_ENTRY NTLMHash;
	SAM_ENTRY NTLMHistory;
	SAM_ENTRY LMHistory;
	BYTE datas[ANYSIZE_ARRAY];
} USER_ACCOUNT_V, * PUSER_ACCOUNT_V;