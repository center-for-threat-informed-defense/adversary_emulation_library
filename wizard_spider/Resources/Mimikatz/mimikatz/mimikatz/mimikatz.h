#pragma once

#include "globals.h"
#include "modules/sekurlsa/kuhl_m_sekurlsa.h"
#include "modules/kuhl_m_privilege.h"
#include "modules/kuhl_m_lsadump.h"
#include "modules/kuhl_m_token.h"
#include "modules/kuhl_m_vault.h"

#include <io.h>
#include <fcntl.h>
#define DELAYIMP_INSECURE_WRITABLE_HOOKS
#include <delayimp.h>

extern VOID WINAPI RtlGetNtVersionNumbers(LPDWORD pMajor, LPDWORD pMinor, LPDWORD pBuild);

int wmain(int argc, wchar_t * argv[]);
void mimikatz_begin();
void mimikatz_end(NTSTATUS status);

BOOL WINAPI HandlerRoutine(DWORD dwCtrlType);

NTSTATUS mimikatz_initOrClean(BOOL Init);

NTSTATUS mimikatz_doLocal(wchar_t * input);
NTSTATUS mimikatz_dispatchCommand(wchar_t * input);

#if defined(_POWERKATZ)
__declspec(dllexport) wchar_t * powershell_reflective_mimikatz(LPCWSTR input);
#elif defined(_WINDLL)
void reatachIoHandle(DWORD nStdHandle, int flags, const char *Mode, FILE *file);
void CALLBACK mimikatz_dll(HWND hwnd, HINSTANCE hinst, LPWSTR lpszCmdLine, int nCmdShow);
#if defined(_M_X64) || defined(_M_ARM64)
#pragma comment(linker, "/export:mainW=mimikatz_dll")
#elif defined(_M_IX86)
#pragma comment(linker, "/export:mainW=_mimikatz_dll@16")
#endif
#endif