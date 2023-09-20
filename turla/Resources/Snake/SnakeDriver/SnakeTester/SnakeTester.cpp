// SnakeTester.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Shlwapi.h>
#include <winternl.h>
#include <stdlib.h>
#include <stdio.h>
//#include "..\SnakeDriver\driver.h"
#define SYSTEM_MODULE_NAME "gusb.sys"

//These defines and structs are also in ..\libinfinityhook\ntint.h, but including them in a userspace application causes all sorts of redefines

#define SystemModuleInformation 11
#define SystemHandleInformation 16

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
	USHORT UniqueProcessId;
	USHORT CreatorBackTraceIndex;
	UCHAR  ObjectTypeIndex;
	UCHAR  HandleAttributes;
	USHORT HandleValue;
	PVOID  Object;
	ULONG  GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

int main()
{
	ULONG len;
	NTSTATUS status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemModuleInformation, NULL, 0, &len);
	PRTL_PROCESS_MODULES SystemModules = (PRTL_PROCESS_MODULES)malloc(len);
	if (!SystemModules) {
		printf("ERROR: Malloc failed\n");
		return 1;
	}
	ULONG pmLen = len;
	//printf("STATUS: 0x%llx, len 0x%lx\n", status, len);
	status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemModuleInformation, SystemModules, pmLen, &len);
	//printf("STATUS: 0x%llx, len 0x%lx\n", status, len);
	if (!NT_SUCCESS(status)) {
		printf("NtQuerySystemInformation failed with code 0x%lx\n", status);
		free(SystemModules);
		return 1;
	}

	PRTL_PROCESS_MODULE_INFORMATION srcPmi = &SystemModules->Modules[0];
	for (ULONG i = 0; i < SystemModules->NumberOfModules; ++i)
	{
		PRTL_PROCESS_MODULE_INFORMATION ModuleInformation = &SystemModules->Modules[i];
		//printf("module name: %s, image base: %p\n", (const char*)&ModuleInformation->FullPathName[ModuleInformation->OffsetToFileName], ModuleInformation->ImageBase);
		if (!strncmp((PCHAR) & ModuleInformation->FullPathName[ModuleInformation->OffsetToFileName], SYSTEM_MODULE_NAME, strlen(SYSTEM_MODULE_NAME))) {
			free(SystemModules);
			return 2;
		}

	}

	free(SystemModules);

	// System Handles - Currently not being used in testing

	len = 0;
	status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemHandleInformation, NULL, 0, &len);
	PSYSTEM_HANDLE_INFORMATION SystemHandles = (PSYSTEM_HANDLE_INFORMATION)malloc(len);
	if (!SystemHandles) {
		printf("ERROR: Malloc failed\n");
		return 1;
	}

	ULONG phLen = len;

	for (int i = 0; i < 10; i++) {
		status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemHandleInformation, SystemHandles, phLen, &len);

		if (NT_SUCCESS(status)) {
			break;
		}

		free(SystemHandles);
		SystemHandles = (PSYSTEM_HANDLE_INFORMATION)malloc(len);
		phLen = len;
	}
	if (!NT_SUCCESS(status)) {
		printf("Failed to allocate space for Handles\n");
	}

	//for (int i = 0; i < SystemHandles->NumberOfHandles; i++) {
	//	printf("%p\n", SystemHandles->Handles[i].Object);
	//}

	free(SystemHandles);

    return 0;
}
