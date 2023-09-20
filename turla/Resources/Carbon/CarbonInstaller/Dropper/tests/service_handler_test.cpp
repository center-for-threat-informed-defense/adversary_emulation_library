#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <winerror.h>
#include "service_handler.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;
using ::testing::StrEq;
using ::testing::PrintToString;
using ::testing::SetArgPointee;


// Mock the wrapper functions for unit tests
class MockSvcHandlerCallWrapper : public service_handler::SvcCallWrapperInterface {
public:
	virtual ~MockSvcHandlerCallWrapper(){}
    
    MOCK_METHOD2(CreateServiceWrapper, SC_HANDLE(SC_HANDLE hSCManager, service_handler::ServiceSettings *svcSettings));
    MOCK_METHOD3(OpenSCManagerWrapper, SC_HANDLE(
        LPCTSTR     lpMachineName,
        LPCTSTR     lpDatabaseName,
        DWORD       dwDesiredAccess
    ));
    MOCK_METHOD1(CloseServiceHandleWrapper, BOOL(SC_HANDLE hSCObject));
    MOCK_METHOD3(StartServiceWrapper, BOOL(SC_HANDLE hService, DWORD dwNumServiceArgs, LPCTSTR *lpServiceArgVectors));
    MOCK_METHOD3(OpenServiceWrapper, SC_HANDLE(SC_HANDLE hSCManager, LPCTSTR lpServiceName, DWORD dwDesiredAccess));
    MOCK_METHOD5(QueryServiceStatusExWrapper, BOOL(
        SC_HANDLE               hService,
        SC_STATUS_TYPE          InfoLevel,
        SERVICE_STATUS_PROCESS* lpBuffer,
        DWORD                   cbBufSize,
        LPDWORD                 pcbBytesNeeded
    ));
    MOCK_METHOD9(RegCreateKeyWrapper, LSTATUS(
        HKEY                        hKey,
        LPCTSTR                     lpSubKey,
        DWORD                       Reserved,
        LPTSTR                      lpClass,
        DWORD                       dwOptions,
        REGSAM                      samDesired,
        const LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        PHKEY                       phkResult,
        LPDWORD                     lpdwDisposition
    ));
    MOCK_METHOD6(RegSetKeyValueWrapper, LSTATUS(
        HKEY    hKey,
        LPCTSTR lpSubKey,
        LPCTSTR lpValueName,
        DWORD   dwType,
        LPCVOID lpData,
        DWORD   cbData
    ));
    MOCK_METHOD1(RegCloseKeyWrapper, LSTATUS(HKEY hKey));
    MOCK_METHOD0(GetLastErrorWrapper, DWORD(void));
    MOCK_METHOD1(SleepWrapper, void(DWORD));
};

// Text fixture for shared data
class ServiceHandlerTest : public ::testing::Test {
protected:
    SC_HANDLE mock_sc_handle = SC_HANDLE(1234);
    SC_HANDLE mock_service_handle = SC_HANDLE(5678);
    service_handler::ServiceSettings target_svc_settings = {
        service_handler::kLoaderSvcName, // service name
        service_handler::kLoaderSvcDisplayName, // service display name
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_SHARE_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL, // error control type 
        service_handler::kSvcBinPath, // path to service binary
        NULL, // no load ordering group 
        NULL, // no tag identifier 
        NULL, // no dependencies 
        NULL, // LocalSystem account 
        NULL  // no password 
    };
    HKEY dummy_key_handle = HKEY(1234);
    std::string mock_dll_path = "C:\\path\\to\\mock\\dll";
    SERVICE_STATUS_PROCESS stopped_status = {SERVICE_WIN32_SHARE_PROCESS, SERVICE_STOPPED};
    SERVICE_STATUS_PROCESS start_pending_status = {SERVICE_WIN32_SHARE_PROCESS, SERVICE_START_PENDING};
    SERVICE_STATUS_PROCESS running_status = {SERVICE_WIN32_SHARE_PROCESS, SERVICE_RUNNING};
};

// Define our own matching logic to compare service_handler::ServiceSettings structs.
MATCHER_P(ServiceSettingsEq, pTargetSvcSettings, "") {
    DWORD target_tag_id = (pTargetSvcSettings->lpdwTagId != NULL) ? *(pTargetSvcSettings->lpdwTagId) : 0;
    DWORD arg_tag_id =(arg->lpdwTagId != NULL) ? *(arg->lpdwTagId) : 0;
	return (PrintToString(pTargetSvcSettings->lpServiceName) == PrintToString(arg->lpServiceName)) && 
        (PrintToString(pTargetSvcSettings->lpDisplayName) == PrintToString(arg->lpDisplayName)) && 
        (pTargetSvcSettings->dwDesiredAccess == arg->dwDesiredAccess) &&
        (pTargetSvcSettings->dwServiceType == arg->dwServiceType) &&
        (pTargetSvcSettings->dwStartType == arg->dwStartType) &&
        (pTargetSvcSettings->dwErrorControl == arg->dwErrorControl) &&
        (pTargetSvcSettings->dwErrorControl == arg->dwErrorControl) &&
        (PrintToString(pTargetSvcSettings->lpBinaryPathname) == PrintToString(arg->lpBinaryPathname)) && 
        (PrintToString(pTargetSvcSettings->lpLoadOrderGroup) == PrintToString(arg->lpLoadOrderGroup)) && 
        (target_tag_id == arg_tag_id) &&
        (PrintToString(pTargetSvcSettings->lpDependencies) == PrintToString(arg->lpDependencies)) && 
        (PrintToString(pTargetSvcSettings->lpServiceStartName) == PrintToString(arg->lpServiceStartName)) && 
        (PrintToString(pTargetSvcSettings->lpPassword) == PrintToString(arg->lpPassword));
}

// Custom matcher to compare registry value data (LPCSTR type)
MATCHER_P(RegValueDataLpcstrEq, target_str, "") {
    return PrintToString(target_str) == PrintToString((LPCSTR)arg);
}

TEST_F(ServiceHandlerTest, SuccessCreateLoaderService) {
	MockSvcHandlerCallWrapper mock_sh_call_wrapper;

    EXPECT_CALL(mock_sh_call_wrapper, OpenSCManagerWrapper(_, _, _))
        .Times(0);
    EXPECT_CALL(mock_sh_call_wrapper, OpenSCManagerWrapper(NULL, NULL, SC_MANAGER_ALL_ACCESS))
        .WillOnce(Return(mock_sc_handle));
    EXPECT_CALL(mock_sh_call_wrapper, CreateServiceWrapper(_, _))
        .Times(0);
    EXPECT_CALL(mock_sh_call_wrapper, CreateServiceWrapper(mock_sc_handle, ServiceSettingsEq(&target_svc_settings)))
        .WillOnce(Return(mock_service_handle));
    EXPECT_CALL(mock_sh_call_wrapper, CloseServiceHandleWrapper(_))
        .Times(0);
    EXPECT_CALL(mock_sh_call_wrapper, CloseServiceHandleWrapper(mock_sc_handle))
        .Times(1);
    EXPECT_CALL(mock_sh_call_wrapper, CloseServiceHandleWrapper(mock_service_handle))
        .Times(1);
		
	EXPECT_EQ(service_handler::CreateLoaderService(&mock_sh_call_wrapper), ERROR_SUCCESS);
}

TEST_F(ServiceHandlerTest, FailCreateLoaderServiceFailInstallSvc) {
	MockSvcHandlerCallWrapper mock_sh_call_wrapper;

    EXPECT_CALL(mock_sh_call_wrapper, OpenSCManagerWrapper(_, _, _))
        .Times(0);
    EXPECT_CALL(mock_sh_call_wrapper, OpenSCManagerWrapper(NULL, NULL, SC_MANAGER_ALL_ACCESS))
        .WillOnce(Return(mock_sc_handle));
    EXPECT_CALL(mock_sh_call_wrapper, CreateServiceWrapper(_, _))
        .Times(0);
    EXPECT_CALL(mock_sh_call_wrapper, CreateServiceWrapper(mock_sc_handle, ServiceSettingsEq(&target_svc_settings)))
        .WillOnce(Return(SC_HANDLE(NULL)));
    EXPECT_CALL(mock_sh_call_wrapper, CloseServiceHandleWrapper(_))
        .Times(0);
    EXPECT_CALL(mock_sh_call_wrapper, CloseServiceHandleWrapper(mock_sc_handle))
        .Times(1);
	EXPECT_EQ(service_handler::CreateLoaderService(&mock_sh_call_wrapper), FAIL_INSTALL_SVC);
}

TEST_F(ServiceHandlerTest, FailCreateLoaderServiceFailGetScmHandle) {
	MockSvcHandlerCallWrapper mock_sh_call_wrapper;

    EXPECT_CALL(mock_sh_call_wrapper, OpenSCManagerWrapper(_, _, _))
        .Times(0);
    EXPECT_CALL(mock_sh_call_wrapper, OpenSCManagerWrapper(NULL, NULL, SC_MANAGER_ALL_ACCESS))
        .WillOnce(Return(SC_HANDLE(NULL)));
    EXPECT_CALL(mock_sh_call_wrapper, CreateServiceWrapper(_, _))
        .Times(0);
    EXPECT_CALL(mock_sh_call_wrapper, CloseServiceHandleWrapper(_))
        .Times(0);
	EXPECT_EQ(service_handler::CreateLoaderService(&mock_sh_call_wrapper), FAIL_GET_SCM_HANDLE);
}

TEST_F(ServiceHandlerTest, SetServiceDllPathSuccess) {
    MockSvcHandlerCallWrapper mock_sh_call_wrapper;

    EXPECT_CALL(mock_sh_call_wrapper, RegCreateKeyWrapper(
        HKEY_LOCAL_MACHINE,
        service_handler::kSvcParamSubKey,
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_WRITE,
        NULL,
        _,
        NULL
    )).WillOnce(DoAll(SetArgPointee<7>(dummy_key_handle), Return(ERROR_SUCCESS))); // set our hKey param value to our dummy handle

    EXPECT_CALL(mock_sh_call_wrapper, RegSetKeyValueWrapper(
        dummy_key_handle,
        NULL,
        StrEq(TEXT("ServiceDll")),
        REG_EXPAND_SZ,
        RegValueDataLpcstrEq(mock_dll_path.c_str()),
        mock_dll_path.size() + 1
    )).WillOnce(Return(ERROR_SUCCESS));

    EXPECT_CALL(mock_sh_call_wrapper, RegCloseKeyWrapper(dummy_key_handle))
        .Times(1);

    EXPECT_EQ(service_handler::SetServiceDllPath(&mock_sh_call_wrapper, mock_dll_path), ERROR_SUCCESS);
}

TEST_F(ServiceHandlerTest, SetServiceDllPathFailCreateKey) {
    MockSvcHandlerCallWrapper mock_sh_call_wrapper;

    EXPECT_CALL(mock_sh_call_wrapper, RegCreateKeyWrapper(
        HKEY_LOCAL_MACHINE,
        service_handler::kSvcParamSubKey,
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_WRITE,
        NULL,
        _,
        NULL
    )).WillOnce(Return(2)); // fail on purpose
    EXPECT_CALL(mock_sh_call_wrapper, RegSetKeyValueWrapper(_, _, _, _, _, _))
        .Times(0);
    EXPECT_CALL(mock_sh_call_wrapper, RegCloseKeyWrapper(_))
        .Times(0);

    EXPECT_EQ(service_handler::SetServiceDllPath(&mock_sh_call_wrapper, mock_dll_path), FAIL_REG_CREATE_KEY_DLL_PATH);
}

TEST_F(ServiceHandlerTest, SetServiceDllPathFailSetValue) {
    MockSvcHandlerCallWrapper mock_sh_call_wrapper;

    EXPECT_CALL(mock_sh_call_wrapper, RegCreateKeyWrapper(
        HKEY_LOCAL_MACHINE,
        service_handler::kSvcParamSubKey,
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_WRITE,
        NULL,
        _,
        NULL
    )).WillOnce(DoAll(SetArgPointee<7>(dummy_key_handle), Return(ERROR_SUCCESS))); // set our hKey param value to our dummy handle

    EXPECT_CALL(mock_sh_call_wrapper, RegSetKeyValueWrapper(
        dummy_key_handle,
        NULL,
        StrEq(TEXT("ServiceDll")),
        REG_EXPAND_SZ,
        RegValueDataLpcstrEq(mock_dll_path.c_str()),
        mock_dll_path.size() + 1
    )).WillOnce(Return(2)); // fail on purpose

    EXPECT_CALL(mock_sh_call_wrapper, RegCloseKeyWrapper(dummy_key_handle))
        .Times(1);;

    EXPECT_EQ(service_handler::SetServiceDllPath(&mock_sh_call_wrapper, mock_dll_path), FAIL_REG_SET_VAL_DLL_PATH);
}

TEST_F(ServiceHandlerTest, SetSvchostGroupValueSuccess) {
    MockSvcHandlerCallWrapper mock_sh_call_wrapper;

    EXPECT_CALL(mock_sh_call_wrapper, RegCreateKeyWrapper(
        HKEY_LOCAL_MACHINE,
        service_handler::kSvchostSubKey,
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_WRITE,
        NULL,
        _,
        NULL
    )).WillOnce(DoAll(SetArgPointee<7>(dummy_key_handle), Return(ERROR_SUCCESS))); // set our hKey param value to our dummy handle

    EXPECT_CALL(mock_sh_call_wrapper, RegSetKeyValueWrapper(
        dummy_key_handle,
        NULL,
        service_handler::kSvchostGroupName,
        REG_MULTI_SZ,
        service_handler::kSvchostGroupValueData,
        strlen(service_handler::kSvchostGroupValueData) + 2
    )).WillOnce(Return(ERROR_SUCCESS));

    EXPECT_CALL(mock_sh_call_wrapper, RegCloseKeyWrapper(dummy_key_handle))
        .Times(1);

    EXPECT_EQ(service_handler::SetSvchostGroupValue(&mock_sh_call_wrapper), ERROR_SUCCESS);
}

TEST_F(ServiceHandlerTest, SetSvchostGroupValueFailCreateKey) {
    MockSvcHandlerCallWrapper mock_sh_call_wrapper;

    EXPECT_CALL(mock_sh_call_wrapper, RegCreateKeyWrapper(
        HKEY_LOCAL_MACHINE,
        service_handler::kSvchostSubKey,
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_WRITE,
        NULL,
        _,
        NULL
    )).WillOnce(Return(2)); // fail on purpose
    EXPECT_CALL(mock_sh_call_wrapper, RegSetKeyValueWrapper(_, _, _, _, _, _))
        .Times(0);
    EXPECT_CALL(mock_sh_call_wrapper, RegCloseKeyWrapper(_))
        .Times(0);

    EXPECT_EQ(service_handler::SetSvchostGroupValue(&mock_sh_call_wrapper), FAIL_REG_CREATE_KEY_SVCHOST_GROUP);
}

TEST_F(ServiceHandlerTest, SetSvchostGroupValueFailSetValue) {
    MockSvcHandlerCallWrapper mock_sh_call_wrapper;

    EXPECT_CALL(mock_sh_call_wrapper, RegCreateKeyWrapper(
        HKEY_LOCAL_MACHINE,
        service_handler::kSvchostSubKey,
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_WRITE,
        NULL,
        _,
        NULL
    )).WillOnce(DoAll(SetArgPointee<7>(dummy_key_handle), Return(ERROR_SUCCESS))); // set our hKey param value to our dummy handle

    EXPECT_CALL(mock_sh_call_wrapper, RegSetKeyValueWrapper(
        dummy_key_handle,
        NULL,
        service_handler::kSvchostGroupName,
        REG_MULTI_SZ,
        service_handler::kSvchostGroupValueData,
        strlen(service_handler::kSvchostGroupValueData) + 2
    )).WillOnce(Return(2)); // fail on purpose

    EXPECT_CALL(mock_sh_call_wrapper, RegCloseKeyWrapper(dummy_key_handle))
        .Times(1);;

    EXPECT_EQ(service_handler::SetSvchostGroupValue(&mock_sh_call_wrapper), FAIL_REG_SET_VAL_SVCHOST_GROUP);
}

TEST_F(ServiceHandlerTest, StartLoaderServiceSuccessImmediate) {
    MockSvcHandlerCallWrapper mock_sh_call_wrapper;

    EXPECT_CALL(mock_sh_call_wrapper, OpenSCManagerWrapper(NULL, NULL, SC_MANAGER_ALL_ACCESS))
        .WillOnce(Return(mock_sc_handle));
    EXPECT_CALL(mock_sh_call_wrapper, OpenServiceWrapper(mock_sc_handle, service_handler::kLoaderSvcName, SERVICE_ALL_ACCESS))
        .WillOnce(Return(mock_service_handle));
    EXPECT_CALL(mock_sh_call_wrapper, StartServiceWrapper(mock_service_handle, 0, NULL))
        .WillOnce(Return(TRUE));
    EXPECT_CALL(mock_sh_call_wrapper, QueryServiceStatusExWrapper(_, _, _, _, _))
        .Times(0);
    EXPECT_CALL(mock_sh_call_wrapper, QueryServiceStatusExWrapper(
        mock_service_handle,
        SC_STATUS_PROCESS_INFO,
        _,
        sizeof(SERVICE_STATUS_PROCESS),
        _
    ))
        .WillOnce(DoAll(SetArgPointee<2>(stopped_status), Return(TRUE)))
        .WillOnce(DoAll(SetArgPointee<2>(running_status), Return(TRUE)));
    EXPECT_CALL(mock_sh_call_wrapper, CloseServiceHandleWrapper(_))
        .Times(0);
    EXPECT_CALL(mock_sh_call_wrapper, CloseServiceHandleWrapper(mock_sc_handle))
        .Times(1);
    EXPECT_CALL(mock_sh_call_wrapper, CloseServiceHandleWrapper(mock_service_handle))
        .Times(1);
		
    EXPECT_EQ(service_handler::StartLoaderService(&mock_sh_call_wrapper), ERROR_SUCCESS);
}

TEST_F(ServiceHandlerTest, StartLoaderServiceSuccessAfterOneWait) {
    MockSvcHandlerCallWrapper mock_sh_call_wrapper;

    EXPECT_CALL(mock_sh_call_wrapper, OpenSCManagerWrapper(NULL, NULL, SC_MANAGER_ALL_ACCESS))
        .WillOnce(Return(mock_sc_handle));
    EXPECT_CALL(mock_sh_call_wrapper, OpenServiceWrapper(mock_sc_handle, service_handler::kLoaderSvcName, SERVICE_ALL_ACCESS))
        .WillOnce(Return(mock_service_handle));
    EXPECT_CALL(mock_sh_call_wrapper, StartServiceWrapper(mock_service_handle, 0, NULL))
        .WillOnce(Return(TRUE));
    EXPECT_CALL(mock_sh_call_wrapper, QueryServiceStatusExWrapper(_, _, _, _, _))
        .Times(0);
    EXPECT_CALL(mock_sh_call_wrapper, QueryServiceStatusExWrapper(
        mock_service_handle,
        SC_STATUS_PROCESS_INFO,
        _,
        sizeof(SERVICE_STATUS_PROCESS),
        _
    ))
        .WillOnce(DoAll(SetArgPointee<2>(stopped_status), Return(TRUE)))
        .WillOnce(DoAll(SetArgPointee<2>(start_pending_status), Return(TRUE)))
        .WillOnce(DoAll(SetArgPointee<2>(running_status), Return(TRUE)));
    EXPECT_CALL(mock_sh_call_wrapper, SleepWrapper(2000))
        .Times(1);
    EXPECT_CALL(mock_sh_call_wrapper, CloseServiceHandleWrapper(_))
        .Times(0);
    EXPECT_CALL(mock_sh_call_wrapper, CloseServiceHandleWrapper(mock_sc_handle))
        .Times(1);
    EXPECT_CALL(mock_sh_call_wrapper, CloseServiceHandleWrapper(mock_service_handle))
        .Times(1);
		
    EXPECT_EQ(service_handler::StartLoaderService(&mock_sh_call_wrapper), ERROR_SUCCESS);
}

TEST_F(ServiceHandlerTest, StartLoaderServiceSuccessAfterThreeWaits) {
    MockSvcHandlerCallWrapper mock_sh_call_wrapper;

    EXPECT_CALL(mock_sh_call_wrapper, OpenSCManagerWrapper(NULL, NULL, SC_MANAGER_ALL_ACCESS))
        .WillOnce(Return(mock_sc_handle));
    EXPECT_CALL(mock_sh_call_wrapper, OpenServiceWrapper(mock_sc_handle, service_handler::kLoaderSvcName, SERVICE_ALL_ACCESS))
        .WillOnce(Return(mock_service_handle));
    EXPECT_CALL(mock_sh_call_wrapper, StartServiceWrapper(mock_service_handle, 0, NULL))
        .WillOnce(Return(TRUE));
    EXPECT_CALL(mock_sh_call_wrapper, QueryServiceStatusExWrapper(_, _, _, _, _))
        .Times(0);
    EXPECT_CALL(mock_sh_call_wrapper, QueryServiceStatusExWrapper(
        mock_service_handle,
        SC_STATUS_PROCESS_INFO,
        _,
        sizeof(SERVICE_STATUS_PROCESS),
        _
    ))
        .WillOnce(DoAll(SetArgPointee<2>(stopped_status), Return(TRUE)))
        .WillOnce(DoAll(SetArgPointee<2>(start_pending_status), Return(TRUE)))
        .WillOnce(DoAll(SetArgPointee<2>(start_pending_status), Return(TRUE)))
        .WillOnce(DoAll(SetArgPointee<2>(start_pending_status), Return(TRUE)))
        .WillOnce(DoAll(SetArgPointee<2>(running_status), Return(TRUE)));
    EXPECT_CALL(mock_sh_call_wrapper, SleepWrapper(2000))
        .Times(3);
    EXPECT_CALL(mock_sh_call_wrapper, CloseServiceHandleWrapper(_))
        .Times(0);
    EXPECT_CALL(mock_sh_call_wrapper, CloseServiceHandleWrapper(mock_sc_handle))
        .Times(1);
    EXPECT_CALL(mock_sh_call_wrapper, CloseServiceHandleWrapper(mock_service_handle))
        .Times(1);
		
    EXPECT_EQ(service_handler::StartLoaderService(&mock_sh_call_wrapper), ERROR_SUCCESS);
}

TEST_F(ServiceHandlerTest, StartLoaderServiceFailOpenScm) {
    MockSvcHandlerCallWrapper mock_sh_call_wrapper;

    EXPECT_CALL(mock_sh_call_wrapper, OpenSCManagerWrapper(NULL, NULL, SC_MANAGER_ALL_ACCESS))
        .WillOnce(Return(SC_HANDLE(NULL)));
    EXPECT_CALL(mock_sh_call_wrapper, OpenServiceWrapper(_, _, _))
        .Times(0);
    EXPECT_CALL(mock_sh_call_wrapper, StartServiceWrapper(_, _, NULL))
        .Times(0);
    EXPECT_CALL(mock_sh_call_wrapper, QueryServiceStatusExWrapper(_, _, _, _, _))
        .Times(0);
    EXPECT_CALL(mock_sh_call_wrapper, SleepWrapper(_))
        .Times(0);
    EXPECT_CALL(mock_sh_call_wrapper, CloseServiceHandleWrapper(_))
        .Times(0);
		
    EXPECT_EQ(service_handler::StartLoaderService(&mock_sh_call_wrapper), FAIL_GET_SCM_HANDLE);
}

TEST_F(ServiceHandlerTest, StartLoaderServiceFailOpenService) {
    MockSvcHandlerCallWrapper mock_sh_call_wrapper;

    EXPECT_CALL(mock_sh_call_wrapper, OpenSCManagerWrapper(NULL, NULL, SC_MANAGER_ALL_ACCESS))
        .WillOnce(Return(mock_sc_handle));
    EXPECT_CALL(mock_sh_call_wrapper, OpenServiceWrapper(mock_sc_handle, service_handler::kLoaderSvcName, SERVICE_ALL_ACCESS))
        .WillOnce(Return(SC_HANDLE(NULL)));
    EXPECT_CALL(mock_sh_call_wrapper, StartServiceWrapper(_, _, NULL))
        .Times(0);
    EXPECT_CALL(mock_sh_call_wrapper, QueryServiceStatusExWrapper(_, _, _, _, _))
        .Times(0);
    EXPECT_CALL(mock_sh_call_wrapper, SleepWrapper(_))
        .Times(0);
    EXPECT_CALL(mock_sh_call_wrapper, CloseServiceHandleWrapper(_))
        .Times(0);
    EXPECT_CALL(mock_sh_call_wrapper, CloseServiceHandleWrapper(mock_sc_handle))
        .Times(1);

    EXPECT_EQ(service_handler::StartLoaderService(&mock_sh_call_wrapper), FAIL_OPEN_SERVICE);
}

TEST_F(ServiceHandlerTest, StartLoaderServiceFailFirstQueryStatus) {
    MockSvcHandlerCallWrapper mock_sh_call_wrapper;

    EXPECT_CALL(mock_sh_call_wrapper, OpenSCManagerWrapper(NULL, NULL, SC_MANAGER_ALL_ACCESS))
        .WillOnce(Return(mock_sc_handle));
    EXPECT_CALL(mock_sh_call_wrapper, OpenServiceWrapper(mock_sc_handle, service_handler::kLoaderSvcName, SERVICE_ALL_ACCESS))
        .WillOnce(Return(mock_service_handle));
    EXPECT_CALL(mock_sh_call_wrapper, StartServiceWrapper(_, _, NULL))
        .Times(0);
    EXPECT_CALL(mock_sh_call_wrapper, QueryServiceStatusExWrapper(_, _, _, _, _))
        .Times(0);
    EXPECT_CALL(mock_sh_call_wrapper, QueryServiceStatusExWrapper(
        mock_service_handle,
        SC_STATUS_PROCESS_INFO,
        _,
        sizeof(SERVICE_STATUS_PROCESS),
        _
    ))
        .WillOnce(Return(FALSE));
    EXPECT_CALL(mock_sh_call_wrapper, SleepWrapper(2000))
        .Times(0);
    EXPECT_CALL(mock_sh_call_wrapper, CloseServiceHandleWrapper(_))
        .Times(0);
    EXPECT_CALL(mock_sh_call_wrapper, CloseServiceHandleWrapper(mock_sc_handle))
        .Times(1);
    EXPECT_CALL(mock_sh_call_wrapper, CloseServiceHandleWrapper(mock_service_handle))
        .Times(1);

    EXPECT_EQ(service_handler::StartLoaderService(&mock_sh_call_wrapper), FAIL_QUERY_SERVICE_STATUS);
}

TEST_F(ServiceHandlerTest, StartLoaderServiceFailStartService) {
    MockSvcHandlerCallWrapper mock_sh_call_wrapper;

    EXPECT_CALL(mock_sh_call_wrapper, OpenSCManagerWrapper(NULL, NULL, SC_MANAGER_ALL_ACCESS))
        .WillOnce(Return(mock_sc_handle));
    EXPECT_CALL(mock_sh_call_wrapper, OpenServiceWrapper(mock_sc_handle, service_handler::kLoaderSvcName, SERVICE_ALL_ACCESS))
        .WillOnce(Return(mock_service_handle));
    EXPECT_CALL(mock_sh_call_wrapper, StartServiceWrapper(mock_service_handle, 0, NULL))
        .WillOnce(Return(FALSE));
    EXPECT_CALL(mock_sh_call_wrapper, QueryServiceStatusExWrapper(_, _, _, _, _))
        .Times(0);
    EXPECT_CALL(mock_sh_call_wrapper, QueryServiceStatusExWrapper(
        mock_service_handle,
        SC_STATUS_PROCESS_INFO,
        _,
        sizeof(SERVICE_STATUS_PROCESS),
        _
    ))
        .WillOnce(DoAll(SetArgPointee<2>(stopped_status), Return(TRUE)));
    EXPECT_CALL(mock_sh_call_wrapper, SleepWrapper(_))
        .Times(0);
    EXPECT_CALL(mock_sh_call_wrapper, CloseServiceHandleWrapper(_))
        .Times(0);
    EXPECT_CALL(mock_sh_call_wrapper, CloseServiceHandleWrapper(mock_sc_handle))
        .Times(1);
    EXPECT_CALL(mock_sh_call_wrapper, CloseServiceHandleWrapper(mock_service_handle))
        .Times(1);

    EXPECT_EQ(service_handler::StartLoaderService(&mock_sh_call_wrapper), FAIL_START_SERVICE);
}

TEST_F(ServiceHandlerTest, StartLoaderServiceFailSecondQueryStatus) {
    MockSvcHandlerCallWrapper mock_sh_call_wrapper;

    EXPECT_CALL(mock_sh_call_wrapper, OpenSCManagerWrapper(NULL, NULL, SC_MANAGER_ALL_ACCESS))
        .WillOnce(Return(mock_sc_handle));
    EXPECT_CALL(mock_sh_call_wrapper, OpenServiceWrapper(mock_sc_handle, service_handler::kLoaderSvcName, SERVICE_ALL_ACCESS))
        .WillOnce(Return(mock_service_handle));
    EXPECT_CALL(mock_sh_call_wrapper, StartServiceWrapper(mock_service_handle, 0, NULL))
        .WillOnce(Return(TRUE));
    EXPECT_CALL(mock_sh_call_wrapper, QueryServiceStatusExWrapper(_, _, _, _, _))
        .Times(0);
    EXPECT_CALL(mock_sh_call_wrapper, QueryServiceStatusExWrapper(
        mock_service_handle,
        SC_STATUS_PROCESS_INFO,
        _,
        sizeof(SERVICE_STATUS_PROCESS),
        _
    ))
        .WillOnce(DoAll(SetArgPointee<2>(stopped_status), Return(TRUE)))
        .WillOnce(Return(FALSE));
    EXPECT_CALL(mock_sh_call_wrapper, SleepWrapper(_))
        .Times(0);
    EXPECT_CALL(mock_sh_call_wrapper, CloseServiceHandleWrapper(_))
        .Times(0);
    EXPECT_CALL(mock_sh_call_wrapper, CloseServiceHandleWrapper(mock_sc_handle))
        .Times(1);
    EXPECT_CALL(mock_sh_call_wrapper, CloseServiceHandleWrapper(mock_service_handle))
        .Times(1);

    EXPECT_EQ(service_handler::StartLoaderService(&mock_sh_call_wrapper), FAIL_QUERY_SERVICE_STATUS);
}

TEST_F(ServiceHandlerTest, StartLoaderServiceFailQueryStatusAfterOneWait) {
    MockSvcHandlerCallWrapper mock_sh_call_wrapper;

    EXPECT_CALL(mock_sh_call_wrapper, OpenSCManagerWrapper(NULL, NULL, SC_MANAGER_ALL_ACCESS))
        .WillOnce(Return(mock_sc_handle));
    EXPECT_CALL(mock_sh_call_wrapper, OpenServiceWrapper(mock_sc_handle, service_handler::kLoaderSvcName, SERVICE_ALL_ACCESS))
        .WillOnce(Return(mock_service_handle));
    EXPECT_CALL(mock_sh_call_wrapper, StartServiceWrapper(mock_service_handle, 0, NULL))
        .WillOnce(Return(TRUE));
    EXPECT_CALL(mock_sh_call_wrapper, QueryServiceStatusExWrapper(_, _, _, _, _))
        .Times(0);
    EXPECT_CALL(mock_sh_call_wrapper, QueryServiceStatusExWrapper(
        mock_service_handle,
        SC_STATUS_PROCESS_INFO,
        _,
        sizeof(SERVICE_STATUS_PROCESS),
        _
    ))
        .WillOnce(DoAll(SetArgPointee<2>(stopped_status), Return(TRUE)))
        .WillOnce(DoAll(SetArgPointee<2>(start_pending_status), Return(TRUE)))
        .WillOnce(Return(FALSE));
    EXPECT_CALL(mock_sh_call_wrapper, SleepWrapper(2000))
        .Times(1);
    EXPECT_CALL(mock_sh_call_wrapper, CloseServiceHandleWrapper(_))
        .Times(0);
    EXPECT_CALL(mock_sh_call_wrapper, CloseServiceHandleWrapper(mock_sc_handle))
        .Times(1);
    EXPECT_CALL(mock_sh_call_wrapper, CloseServiceHandleWrapper(mock_service_handle))
        .Times(1);

    EXPECT_EQ(service_handler::StartLoaderService(&mock_sh_call_wrapper), FAIL_QUERY_SERVICE_STATUS);
}

// Fail after 3 tries still stopped
TEST_F(ServiceHandlerTest, StartLoaderServiceFailAfterThreeWaits) {
    MockSvcHandlerCallWrapper mock_sh_call_wrapper;

    EXPECT_CALL(mock_sh_call_wrapper, OpenSCManagerWrapper(NULL, NULL, SC_MANAGER_ALL_ACCESS))
        .WillOnce(Return(mock_sc_handle));
    EXPECT_CALL(mock_sh_call_wrapper, OpenServiceWrapper(mock_sc_handle, service_handler::kLoaderSvcName, SERVICE_ALL_ACCESS))
        .WillOnce(Return(mock_service_handle));
    EXPECT_CALL(mock_sh_call_wrapper, StartServiceWrapper(mock_service_handle, 0, NULL))
        .WillOnce(Return(TRUE));
    EXPECT_CALL(mock_sh_call_wrapper, QueryServiceStatusExWrapper(_, _, _, _, _))
        .Times(0);
    EXPECT_CALL(mock_sh_call_wrapper, QueryServiceStatusExWrapper(
        mock_service_handle,
        SC_STATUS_PROCESS_INFO,
        _,
        sizeof(SERVICE_STATUS_PROCESS),
        _
    ))
        .WillOnce(DoAll(SetArgPointee<2>(stopped_status), Return(TRUE)))
        .WillOnce(DoAll(SetArgPointee<2>(start_pending_status), Return(TRUE)))
        .WillOnce(DoAll(SetArgPointee<2>(start_pending_status), Return(TRUE)))
        .WillOnce(DoAll(SetArgPointee<2>(start_pending_status), Return(TRUE)))
        .WillOnce(DoAll(SetArgPointee<2>(stopped_status), Return(TRUE)));
    EXPECT_CALL(mock_sh_call_wrapper, SleepWrapper(2000))
        .Times(3);
    EXPECT_CALL(mock_sh_call_wrapper, CloseServiceHandleWrapper(_))
        .Times(0);
    EXPECT_CALL(mock_sh_call_wrapper, CloseServiceHandleWrapper(mock_sc_handle))
        .Times(1);
    EXPECT_CALL(mock_sh_call_wrapper, CloseServiceHandleWrapper(mock_service_handle))
        .Times(1);
		
    EXPECT_EQ(service_handler::StartLoaderService(&mock_sh_call_wrapper), FAIL_SERVICE_DID_NOT_START_IN_TIME);
}
