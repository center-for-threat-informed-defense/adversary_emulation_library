/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include "kull_m_dpapi.h"
#include "kull_m_string.h"

#define KIWI_DPAPI_ENTROPY_CAPI_KEY_EXPORTFLAGS	"Hj1diQ6kpUx7VC4m"
#define KIWI_DPAPI_ENTROPY_CNG_KEY_PROPERTIES	"6jnkd5J3ZdQDtrsu"
#define KIWI_DPAPI_ENTROPY_CNG_KEY_BLOB			"xT5rZW5qVVbrvpuA"

//#define KIWI_DPAPI_ENTROPY_NGC_unk				0x62 6B ED CB CA 02 5E 41  84 7E 33 93 36 9C 2E 5E

#pragma pack(push, 4) 
typedef struct _KULL_M_KEY_CAPI_BLOB {
	DWORD	dwVersion;
	DWORD	unk0;	// maybe flags somewhere ?
	DWORD	dwNameLen;
	DWORD	dwSiPublicKeyLen;
	DWORD	dwSiPrivateKeyLen;
	DWORD	dwExPublicKeyLen;
	DWORD	dwExPrivateKeyLen;
	DWORD	dwHashLen; // hmac ?
	DWORD	dwSiExportFlagLen;
	DWORD	dwExExportFlagLen;

	PSTR	pName;
	PVOID	pHash;
	PVOID	pSiPublicKey;
	PVOID	pSiPrivateKey;
	PVOID	pSiExportFlag;
	PVOID	pExPublicKey;
	PVOID	pExPrivateKey;
	PVOID	pExExportFlag;
} KULL_M_KEY_CAPI_BLOB, *PKULL_M_KEY_CAPI_BLOB;

typedef struct _KULL_M_KEY_CNG_PROPERTY {
	DWORD	dwStructLen;
	DWORD	type;
	DWORD	unk;
	DWORD	dwNameLen;
	DWORD	dwPropertyLen;

	PSTR	pName;
	PVOID	pProperty;
} KULL_M_KEY_CNG_PROPERTY, *PKULL_M_KEY_CNG_PROPERTY;

typedef struct _KULL_M_KEY_CNG_BLOB {
	DWORD	dwVersion;
	DWORD	unk;	// maybe flags somewhere ?
	DWORD	dwNameLen;
	DWORD	type;
	DWORD	dwPublicPropertiesLen;
	DWORD	dwPrivatePropertiesLen;
	DWORD	dwPrivateKeyLen;
	BYTE	unkArray[16];

	PSTR	pName;
	
	DWORD						cbPublicProperties;
	PKULL_M_KEY_CNG_PROPERTY	*pPublicProperties;
	
	PVOID	pPrivateProperties;
	PVOID	pPrivateKey;
} KULL_M_KEY_CNG_BLOB, *PKULL_M_KEY_CNG_BLOB;
#pragma pack(pop)

PKULL_M_KEY_CAPI_BLOB kull_m_key_capi_create(PVOID data/*, DWORD size*/);
void kull_m_key_capi_delete(PKULL_M_KEY_CAPI_BLOB capiKey);
void kull_m_key_capi_descr(DWORD level, PKULL_M_KEY_CAPI_BLOB capiKey);
BOOL kull_m_key_capi_write(PKULL_M_KEY_CAPI_BLOB capiKey, PVOID *data, DWORD *size);
BOOL kull_m_key_capi_decryptedkey_to_raw(LPCVOID publickey, DWORD publickeyLen, LPCVOID decrypted, DWORD decryptedLen, ALG_ID keyAlg, PRSA_GENERICKEY_BLOB *blob, DWORD *blobLen, DWORD *dwProviderType);

PKULL_M_KEY_CNG_BLOB kull_m_key_cng_create(PVOID data/*, DWORD size*/);
void kull_m_key_cng_delete(PKULL_M_KEY_CNG_BLOB cngKey);
void kull_m_key_cng_descr(DWORD level, PKULL_M_KEY_CNG_BLOB cngKey);
//
PKULL_M_KEY_CNG_PROPERTY kull_m_key_cng_property_create(PVOID data/*, DWORD size*/);
void kull_m_key_cng_property_delete(PKULL_M_KEY_CNG_PROPERTY property);
void kull_m_key_cng_property_descr(DWORD level, PKULL_M_KEY_CNG_PROPERTY property);
//
BOOL kull_m_key_cng_properties_create(PVOID data, DWORD size, PKULL_M_KEY_CNG_PROPERTY ** properties, DWORD *count);
void kull_m_key_cng_properties_delete(PKULL_M_KEY_CNG_PROPERTY *properties, DWORD count);
void kull_m_key_cng_properties_descr(DWORD level, PKULL_M_KEY_CNG_PROPERTY *properties, DWORD count);
//