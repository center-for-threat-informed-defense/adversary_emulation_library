#pragma once
#include <ntifs.h>
#include "driver.h"

// EPROCESS is opaque and version dependent
#ifdef WIN10_1809
#define OFFSET_UNIQUEPROCESSID 0x2e0 // Ptr64 Void
#define OFFSET_ACTIVEPROCESSLINKS 0x2e8 // _LIST_ENTRY
#define OFFSET_TOKEN 0x358 // _EX_FAST_REF
#define OFFSET_IMAGEFILENAME 0x450 // [15] UChar
#endif

#ifdef WIN10_1903
#define OFFSET_UNIQUEPROCESSID 0x2e8 // Ptr64 Void
#define OFFSET_ACTIVEPROCESSLINKS 0x2f0 // _LIST_ENTRY
#define OFFSET_TOKEN 0x360 // _EX_FAST_REF
#define OFFSET_IMAGEFILENAME 0x450 // [15] UChar
#endif

struct _EPROCESS {
    UCHAR unused[OFFSET_UNIQUEPROCESSID];
    PVOID UniqueProcessId;
    struct _LIST_ENTRY ActiveProcessLinks;
    //UCHAR unused1[OFFSET_IMAGEFILENAME-(OFFSET_ACTIVEPROCESSLINKS+0x10)];
};

// PsGetProcessImageFileName is undocumented, we'll have to look it up
typedef PCHAR(*PsGetProcessImageFileName_t)(PEPROCESS);

// Given a process name, returns a pid
int findPidByName(const char* procName, UINT64* pid);
