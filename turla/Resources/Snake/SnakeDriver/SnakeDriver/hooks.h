#pragma once

#include "driver.h"
#include "..\libinfinityhook\ntint.h"

void __fastcall SyscallStub(
    _In_ unsigned int SystemCallIndex,
    _Inout_ void** SystemCallFunction);

#ifdef WIN10_1809
// These values are defined per Windows version, as part of the NTAPI
// full list can be found here https://j00ru.vexillium.org/syscalls/nt/64/
enum sysCallNums {
    SYSCALLMIN,
    NTREADFILE               = 0x0006,
    NTOPENKEY                = 0x0012,
    NTENUMERATEVALUEKEY      = 0x0013,
    NTQUERYKEY               = 0x0016,
    NTCREATEKEY              = 0x001D,
    NTENUMERATEKEY           = 0x0032,
    NTOPENFILE               = 0x0033,
    NTQUERYSYSTEMINFORMATION = 0x0036,
    NTCREATEFILE             = 0x0055,
    NTOPENKEYEX              = 0x011A,
    NTSAVEKEY                = 0x017B,
    NTSAVEKEYEX              = 0x017C,
    SYSCALLMAX
};
#endif
#ifdef WIN10_1903
enum sysCallNums {
    SYSCALLMIN,
    NTREADFILE = 0x0006,
    NTOPENKEY = 0x0012,
    NTENUMERATEVALUEKEY = 0x0013,
    NTQUERYKEY = 0x0016,
    NTCREATEKEY = 0x001D,
    NTENUMERATEKEY = 0x0032,
    NTOPENFILE = 0x0033,
    NTQUERYSYSTEMINFORMATION = 0x0036,
    NTCREATEFILE = 0x0055,
    NTOPENKEYEX = 0x011B,
    NTSAVEKEY = 0x017C,
    NTSAVEKEYEX = 0x017D,
    SYSCALLMAX
};
#endif

// Function prototypes and hook function declarations for all hooked functions
typedef NTSYSAPI NTSTATUS (*NtOpenKey_t)(
    OUT PHANDLE            KeyHandle,
    IN  ACCESS_MASK        DesiredAccess,
    IN  POBJECT_ATTRIBUTES ObjectAttributes);
NTSTATUS DetourNtOpenKey(
    OUT PHANDLE            KeyHandle,
    IN  ACCESS_MASK        DesiredAccess,
    IN  POBJECT_ATTRIBUTES ObjectAttributes);

typedef NTSYSAPI NTSTATUS (*NtOpenKeyEx_t)(
    OUT PHANDLE            KeyHandle,
    IN  ACCESS_MASK        DesiredAccess,
    IN  POBJECT_ATTRIBUTES ObjectAttributes,
    IN  ULONG              OpenOptions);
NTSTATUS DetourNtOpenKeyEx(
    OUT PHANDLE            KeyHandle,
    IN  ACCESS_MASK        DesiredAccess,
    IN  POBJECT_ATTRIBUTES ObjectAttributes,
    IN  ULONG              OpenOptions);

typedef NTSYSAPI NTSTATUS(*NtCreateKey_t)(
    OUT           PHANDLE            KeyHandle,
    IN            ACCESS_MASK        DesiredAccess,
    IN            POBJECT_ATTRIBUTES ObjectAttributes,
                  ULONG              TitleIndex,
    IN            PUNICODE_STRING    Class,
    IN            ULONG              CreateOptions,
    OUT           PULONG             Disposition);
NTSTATUS DetourNtCreateKey(
    OUT           PHANDLE            KeyHandle,
    IN            ACCESS_MASK        DesiredAccess,
    IN            POBJECT_ATTRIBUTES ObjectAttributes,
                  ULONG              TitleIndex,
    IN            PUNICODE_STRING    Class,
    IN            ULONG              CreateOptions,
    OUT           PULONG             Disposition);

typedef NTSYSAPI NTSTATUS(*NtQueryKey_t)(
    HANDLE KeyHandle,
    KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID KeyInformation,
    ULONG Length,
    PULONG ResultLength);
NTSTATUS DetourNtQueryKey(
    HANDLE KeyHandle,
    KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID KeyInformation,
    ULONG Length,
    PULONG ResultLength);

typedef NTSYSAPI NTSTATUS (*NtEnumerateKey_t)(
    _In_ HANDLE KeyHandle,
    _In_ ULONG Index,
    _In_ KEY_INFORMATION_CLASS KeyInformationClass,
    _Out_writes_bytes_to_opt_(Length, *ResultLength) PVOID KeyInformation,
    _In_ ULONG Length,
    _Out_ PULONG ResultLength);
NTSTATUS NTAPI DetourNtEnumerateKey(
    _In_ HANDLE KeyHandle,
    _In_ ULONG Index,
    _In_ KEY_INFORMATION_CLASS KeyInformationClass,
    _Out_writes_bytes_to_opt_(Length, *ResultLength) PVOID KeyInformation,
    _In_ ULONG Length,
    _Out_ PULONG ResultLength);

typedef NTSTATUS (*NtEnumerateValueKey_t)(
    _In_ HANDLE KeyHandle,
    _In_ ULONG Index,
    _In_ KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    _Out_writes_bytes_to_opt_(Length, *ResultLength) PVOID KeyValueInformation,
    _In_ ULONG Length,
    _Out_ PULONG ResultLength);
NTSTATUS NTAPI DetourNtEnumerateValueKey(
    _In_ HANDLE KeyHandle,
    _In_ ULONG Index,
    _In_ KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    _Out_writes_bytes_to_opt_(Length, *ResultLength) PVOID KeyValueInformation,
    _In_ ULONG Length,
    _Out_ PULONG ResultLength);

typedef NTSTATUS(*NtCreateFile_t)(
    _Out_ PHANDLE FileHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_opt_ PLARGE_INTEGER AllocationSize,
    _In_ ULONG FileAttributes,
    _In_ ULONG ShareAccess,
    _In_ ULONG CreateDisposition,
    _In_ ULONG CreateOptions,
    _In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
    _In_ ULONG EaLength);
NTSTATUS NTAPI DetourNtCreateFile(
    _Out_ PHANDLE FileHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_opt_ PLARGE_INTEGER AllocationSize,
    _In_ ULONG FileAttributes,
    _In_ ULONG ShareAccess,
    _In_ ULONG CreateDisposition,
    _In_ ULONG CreateOptions,
    _In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
    _In_ ULONG EaLength);

typedef NTSTATUS (*NtOpenFile_t)(
    _Out_ PHANDLE FileHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG ShareAccess,
    _In_ ULONG OpenOptions
);
NTSTATUS NTAPI DetourNtOpenFile(
    _Out_ PHANDLE FileHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG ShareAccess,
    _In_ ULONG OpenOptions
);

#define SYSTEM_MODULE_INFORMATION 11

typedef NTSTATUS (*NtQuerySystemInformation_t)(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
);
NTSTATUS NTAPI DetourNtQuerySystemInformation(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
);