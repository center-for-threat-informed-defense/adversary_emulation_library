#pragma once
#include <ntifs.h>
#include <initguid.h>
#include <guiddef.h>
#include <fwpsk.h>
#include <fwpmk.h>

namespace wfp {

NTSTATUS init(PDEVICE_OBJECT device);
NTSTATUS cleanup();

NTSTATUS register_callout();
NTSTATUS register_filter();

_Use_decl_annotations_
void injection_routine(void*, void* context, PIO_WORKITEM work);

_Use_decl_annotations_
void monitor_routine(void*, void* context, PIO_WORKITEM work);

void classify(
    _In_ const FWPS_INCOMING_VALUES* values,
    _In_ const FWPS_INCOMING_METADATA_VALUES* meta,
    _Inout_opt_ void* layer,
    _In_opt_ const void* classify_context,
    _In_ const FWPS_FILTER* filter,
    _In_ UINT64 flow_context,
    _Inout_ FWPS_CLASSIFY_OUT* classify_out
);

NTSTATUS notify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE type,
    _In_ const GUID* key,
    _Inout_ FWPS_FILTER3* filter
);

void flow_delete(
    _In_ UINT16 layer,
    _In_ UINT32 callout_id,
    _In_ UINT64 flow_context
);

} // namespace wfp