#pragma once
#include "windows.h"

#define RVATOVA( base, offset ) ( (SIZE_T)base + (SIZE_T)offset )

// Function definitions

typedef unsigned char byte;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef DWORD(WINAPI* typeFuncThread)(LPVOID);
typedef unsigned int ADDR;

typedef SIZE_T(*typeInjectCode)(HANDLE hprocess, typeFuncThread startFunc, HMODULE* newBaseImage);
typedef bool (*typeRunInjectCode)(HANDLE hprocess, HANDLE hthread, typeFuncThread startFunc, typeInjectCode func);


// Declarations
#define STATUS_SUCCESS ((NTSTATUS)0)

typedef enum _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, * PSECTION_INHERIT;

SIZE_T InjectCode2(HANDLE hprocess, typeFuncThread startFunc, HMODULE* newBaseImage);
bool RunInjectCode3(HANDLE hprocess, HANDLE hthread, typeFuncThread startFunc, typeInjectCode func);
DWORD WINAPI injectFunc(void*);

namespace PE
{

	HMODULE GetImageBase(void* funcAddr = 0);
	HMODULE GetImageBaseProcess();
	DWORD SizeOfImage(HMODULE imageBase);
	void ProcessRelocs(PIMAGE_BASE_RELOCATION relocs, SIZE_T imageBase, SIZE_T delta, DWORD relocSize);
	inline PIMAGE_OPTIONAL_HEADER GetOptionalHeader(HMODULE imageBase)
	{
		return (PIMAGE_OPTIONAL_HEADER)((LPVOID)((SIZE_T)imageBase + ((PIMAGE_DOS_HEADER)(imageBase))->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)));
	}

	inline PIMAGE_NT_HEADERS GetNTHeaders(HMODULE imageBase)
	{
		PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)imageBase;
		return (PIMAGE_NT_HEADERS)((SIZE_T)imageBase + dos_header->e_lfanew);
	}

	bool ConvertExeToDll(void* module);

	bool IsValid(const void* module);

}
