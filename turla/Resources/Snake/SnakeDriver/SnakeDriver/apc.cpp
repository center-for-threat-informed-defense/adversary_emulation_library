#include "apc.hpp"
#include "driver.h"

VOID KernelAPC(PKAPC apc, PKNORMAL_ROUTINE*, void**, void**, void**) {
    ::ExFreePool(apc);
}

// Force APC callback from Blackbone:
// https://github.com/DarthTon/Blackbone/blob/master/src/BlackBoneDrv/Loader.c#L703
VOID KernelApcPrepareCallback(
    PKAPC apc,
    PKNORMAL_ROUTINE*,
    void**,
    void**,
    void**
) {
    // Alert current thread
    KeTestAlertThread(UserMode);
    ExFreePool(apc);
}

NTSTATUS call_apc(PKTHREAD thread, PVOID function, PVOID params, bool force) {
    auto apc = static_cast<KAPC*>(ExAllocatePool(NonPagedPool, sizeof(KAPC)));
    if (nullptr == apc) {
        kprintf("Snake: Failed to allocate memory for APC\n");
        return STATUS_UNSUCCESSFUL;
    }
    KeInitializeApc(
        apc,
        thread,
        OriginalApcEnvironment,
        &KernelAPC,
        nullptr,
        reinterpret_cast<PKNORMAL_ROUTINE>(function),
        UserMode,
        params
    );

    PKAPC alert_apc = nullptr;
    if (force) {
        alert_apc = static_cast<KAPC*>(ExAllocatePool(NonPagedPool, sizeof(KAPC)));
        if (nullptr == alert_apc) {
            kprintf("Snake: Failed to allocate memory for APC\n");
            return STATUS_UNSUCCESSFUL;
        }
        KeInitializeApc(
            alert_apc,
            thread,
            OriginalApcEnvironment,
            &KernelApcPrepareCallback,
            nullptr,
            nullptr,
            KernelMode,
            nullptr
        );
    }

    if (KeInsertQueueApc(apc, nullptr, nullptr, 0)) {
        kprintf("Snake: APC queued\n");
        if (force) {
            if (KeInsertQueueApc(alert_apc, nullptr, nullptr, 0)) {
                kprintf("Snake: thread alerted\n");
            }
            return STATUS_SUCCESS;
        }
        return STATUS_SUCCESS;
    }
    else {
        kprintf("Snake: Failed to insert APC into queue\n");
        ExFreePool(apc);
        ExFreePool(alert_apc);
        return STATUS_UNSUCCESSFUL;
    }
}