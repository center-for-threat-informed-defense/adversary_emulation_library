#pragma once
#include <ntifs.h>

extern "C"
NTSTATUS NTAPI ZwQuerySystemInformation(
    IN  size_t SystemInformationClass,
    OUT PVOID  SystemInformation,
    IN  ULONG  SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);

struct SYSTEM_THREAD_INFORMATION {
    ULONGLONG KernelTime;
    ULONGLONG UserTime;
    ULONGLONG CreateTime;
    ULONG WaitTime;
    // Padding here in 64-bit
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    LONG BasePriority;
    ULONG ContextSwitchCount;
    ULONG State;
    KWAIT_REASON WaitReason;
};

struct SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    ULONGLONG WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG Reserved1;
    ULONGLONG CycleTime;
    ULONGLONG CreateTime;
    ULONGLONG UserTime;
    ULONGLONG KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE ProcessId;
    HANDLE ParentProcessId;
    ULONG HandleCount;
    ULONG Reserved2[2];
    // Padding here in 64-bit
    VM_COUNTERS VirtualMemoryCounters;
    size_t Reserved3;
    IO_COUNTERS IoCounters;
    SYSTEM_THREAD_INFORMATION Threads[1];
};

struct ProcessInfo {
	size_t process_id;
	size_t number_of_threads;
	size_t* threads_id;
};

ProcessInfo* get_processes_info(OUT size_t* process_count);
NTSTATUS get_process_info_by_pid(IN size_t pid, OUT ProcessInfo* info);