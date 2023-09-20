#include "pidlookup.h"

// Given a process name, returns a pid
int findPidByName(const char* procName, UINT64* pid) {
    if (!procName || !pid) {
        kprintf("ERROR: bad args to %s\n", __FUNCTION__);
        return -1;
    }

    // Grab the start of the EPROCESS list
    PEPROCESS system = PsInitialSystemProcess;
    if (!system) {
        kprintf("ERROR: Cannot find system process\n");
        return -1;
    }
    PEPROCESS cur = system;

    // Lookup PsGetProcessImageFileName location
    UNICODE_STRING usFuncName = RTL_CONSTANT_STRING(L"PsGetProcessImageFileName");
    PVOID pPsGetProcessImageFileName = MmGetSystemRoutineAddress(&usFuncName);
    PsGetProcessImageFileName_t PsGetProcessImageFileName = (PsGetProcessImageFileName_t)pPsGetProcessImageFileName;
    if (!PsGetProcessImageFileName) {
        kprintf("ERROR: Failed to lookup PsGetProcessImageFileName\n");
        return -1;
    }

    PVOID buf = ExAllocatePool(NonPagedPool, 16);
    if (!buf) {
        kprintf("Allocate failed\n");
        return -1;
    }

    // Iterate over each EPROCESS, and compare with the passed-in process name
    do {
        RtlZeroMemory(buf, 16);
        struct _EPROCESS* eproc = (struct _EPROCESS*)cur;
        PCHAR imageFileName = PsGetProcessImageFileName(cur);
        if (imageFileName) {
            RtlCopyMemory(buf, imageFileName, 15);
            kprintf("ImageFileName: %s, PID: %d\n", (PCHAR)buf, (UINT64)eproc->UniqueProcessId);
            if (!strncmp(procName, (PCHAR)buf, 15)) {

                // Check if the target process is running as SYSTEM
                HANDLE handle;
                auto token = PsReferencePrimaryToken(cur);
                auto status = ObOpenObjectByPointer(
                    token,
                    0,
                    nullptr,
                    TOKEN_QUERY,
                    nullptr,
                    KernelMode,
                    &handle
                );
                if (NT_ERROR(status)) {
                    PsDereferencePrimaryToken(cur);
                    kprintf("Failed to get token: 0x%lx\n", status);
                    return 0;
                }

                unsigned long len;
                status = NtQueryInformationToken(handle, TokenUser, nullptr, 0, &len);
                if (status != STATUS_BUFFER_TOO_SMALL) {
                    ZwClose(handle);
                    PsDereferencePrimaryToken(cur);
                    kprintf("Failed to query token user: 0x%lx\n", status);
                    return 0;
                }

                auto buffer = (PTOKEN_USER)ExAllocatePool(NonPagedPool, len);
                if (!buffer) {
                    ZwClose(handle);
                    PsDereferencePrimaryToken(cur);
                    kprintf("Failed to allocated token buffer");
                    return 0;
                }
                status = NtQueryInformationToken(handle, TokenUser, buffer, len, &len);
                if (NT_ERROR(status)) {
                    ZwClose(handle);
                    PsDereferencePrimaryToken(cur);
                    ExFreePool(buffer);
                    kprintf("Failed to query token user: 0x%lx\n", status);
                    return 0;
                }

                UCHAR sid_buffer[SECURITY_MAX_SID_SIZE];
                unsigned long sid_size;
                status = SecLookupWellKnownSid(
                    WinLocalSystemSid,
                    &sid_buffer,
                    sizeof(sid_buffer),
                    &sid_size
                );
                if (NT_ERROR(status)) {
                    ZwClose(handle);
                    PsDereferencePrimaryToken(cur);
                    ExFreePool(buffer);
                    kprintf("Failed to lookup NT AUTHORITY SID: 0x%lx\n", status);
                    return 0;
                }

                if (!RtlEqualSid(sid_buffer, buffer->User.Sid)) {
                    ZwClose(handle);
                    PsDereferencePrimaryToken(cur);
                    ExFreePool(buffer);
                    kprintf("Process is not running as SYSTEM continuing\n");
                    cur = (PEPROCESS)((UINT64)(eproc->ActiveProcessLinks.Flink) - OFFSET_ACTIVEPROCESSLINKS);
                    continue;
                }

                kprintf("Found NT AUTHORITY process\n");
                *pid = (UINT64)eproc->UniqueProcessId;
                ExFreePool(buf);
                ZwClose(handle);
                PsDereferencePrimaryToken(cur);
                ExFreePool(buffer);
                return 1;
            }
        }
        cur = (PEPROCESS)((UINT64)(eproc->ActiveProcessLinks.Flink) - OFFSET_ACTIVEPROCESSLINKS);

    } while (cur != system);
    ExFreePool(buf);
    return 0;
}