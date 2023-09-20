#pragma once
#include <Windows.h>
#include <winternl.h>
#include <map>
#include <expected>
#include "../common/error.hpp"

#pragma comment(lib, "ntdll")

namespace ci {

std::expected<std::map<std::string, bool>, common::windows_error>
get_settings();

std::expected<std::map<std::string, void*>, common::windows_error>
get_modules();

// http://undocumented.ntinternals.net/index.html?page=UserMode%2FStructures%2FSYSTEM_MODULE_INFORMATION.html
typedef struct _SYSTEM_MODULE {
	ULONG Reserved1;
	ULONG Reserved2;
	ULONG Reserved3;
	PVOID ImageBaseAddress;
	ULONG ImageSize;
	ULONG Flags;
	WORD  Id;
	WORD  Rank;
	WORD  w018;
	WORD  NameOffset;
	CHAR  Name[256];
} SYSTEM_MODULE, * PSYSTEM_MODULE;

// http://undocumented.ntinternals.net/index.html?page=UserMode%2FStructures%2FSYSTEM_MODULE_INFORMATION.html
typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG         ModulesCount;
	SYSTEM_MODULE Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

using NtCreateSection_t = NTSTATUS (*) (
	PHANDLE            SectionHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PLARGE_INTEGER     MaximumSize,
	ULONG              SectionPageProtection,
	ULONG              AllocationAttributes,
	HANDLE             FileHandle
);

typedef enum _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, * PSECTION_INHERIT;

using NtMapViewOfSection_t = NTSTATUS (*) (
	HANDLE          SectionHandle,
	HANDLE          ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR       ZeroBits,
	SIZE_T          CommitSize,
	PLARGE_INTEGER  SectionOffset,
	PSIZE_T         ViewSize,
	SECTION_INHERIT InheritDisposition,
	ULONG           AllocationType,
	ULONG           Win32Protect
);

using RtlImageNtHeaderEx_t = NTSTATUS (*) (
	ULONG			   Flags,
	PVOID			   Base,
	ULONG64			   Size,
	PIMAGE_NT_HEADERS* OutHeaders
);

} // namespace ci
