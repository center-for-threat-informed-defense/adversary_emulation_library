/*
 * Communication Module DLL for Carbon Rootkit.
 * 
 * CTI references:
 */

#include <windows.h>
#include "CommLib.hpp"

// https://docs.microsoft.com/en-us/windows/win32/dlls/dllmain
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    // silence warnings about unused parameters
    (void)hinstDLL;

    switch(fdwReason) { 
        case DLL_PROCESS_ATTACH:
            // TODO Run here
            CreateThread(
                NULL, // default security descriptor
                0, // default stack size
                CommLib::run, // function to run
                NULL, // arg for thread function
                0, // run immediately
                NULL // don't return thread identifier
            );
            break;

        case DLL_THREAD_ATTACH:
            // Do thread-specific initialization.
            break;

        case DLL_THREAD_DETACH:
             // Do thread-specific cleanup.
            break;

        case DLL_PROCESS_DETACH:
        
            if (lpvReserved != nullptr)
            {
                break; // do not do cleanup if process termination scenario
            }
            
            // Perform any necessary cleanup.
            break;
    }
    return TRUE; // Successful DLL_PROCESS_ATTACH.
}