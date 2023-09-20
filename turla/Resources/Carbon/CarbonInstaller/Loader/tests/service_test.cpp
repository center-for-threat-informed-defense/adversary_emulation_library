#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <windows.h>
#include <synchapi.h>
#include <winsvc.h>
#include <string>
#include "service.h"

using ::testing::_;
using ::testing::Return;
using ::testing::StrEq;

// Mock the wrapper functions for unit tests
class MockLoaderSvcCallWrapper : public loader_service::LoaderSvcWrapperInterface {
public:
	virtual ~MockLoaderSvcCallWrapper(){}

    MOCK_METHOD3(RegisterServiceCtrlHandlerExWrapper, SERVICE_STATUS_HANDLE(LPCTSTR lpServiceName, LPHANDLER_FUNCTION_EX lpHandlerProc, LPVOID lpContext));
    MOCK_METHOD4(CreateEventWrapper, HANDLE(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCSTR lpName));
    MOCK_METHOD2(WaitForSingleObjectWrapper, DWORD(HANDLE hHandle, DWORD dwMilliseconds));
    MOCK_METHOD1(SetEventWrapper, BOOL(HANDLE hEvent));
    MOCK_METHOD2(SetServiceStatusWrapper, BOOL(SERVICE_STATUS_HANDLE hServiceStatus, LPSERVICE_STATUS lpServiceStatus));
    MOCK_METHOD2(RegisterEventSourceWrapper, HANDLE(LPCTSTR lpUNCServerName, LPCTSTR lpSourceName));
    MOCK_METHOD1(DeregisterEventSourceWrapper, BOOL(HANDLE hEventLog));
    MOCK_METHOD9(ReportEventWrapper, BOOL(
        HANDLE  hEventLog,
        WORD    wType,
        WORD    wCategory,
        DWORD   dwEventID,
        PSID    lpUserSid,
        WORD    wNumStrings,
        DWORD   dwDataSize,
        LPCTSTR *lpStrings,
        LPVOID  lpRawData
    ));
    MOCK_METHOD1(LoadLibraryWrapper, HMODULE(LPCTSTR lpLibFileName));
    MOCK_METHOD2(GetProcAddressWrapper, FARPROC(HMODULE hModule, LPCSTR lpProcName));
    MOCK_METHOD1(ModuleInitWrapper, void(fp_module_init fp_init_func));
};

// Text fixture for shared data
class LoaderSvcTest : public ::testing::Test {
protected:
    MockLoaderSvcCallWrapper mock_svc_call_wrapper;
    SERVICE_STATUS targetStatus;
    HANDLE hMockEventSource = HANDLE(1234);
    SERVICE_STATUS_HANDLE mockSvcStatusHandle = SERVICE_STATUS_HANDLE(1235);
    HANDLE hMockStopEvent = HANDLE(1236);
    HMODULE hMockModule = HMODULE(2345);
    FARPROC dummy_func = FARPROC(5678);
    LPCTSTR mock_module_path = TEXT("C:\\Path\\to\\dummy\\module");
    LPCSTR mock_init_func_name = "MockFuncInit";

    void SetUp() override {
        targetStatus.dwWin32ExitCode = NO_ERROR;
        targetStatus.dwWaitHint = 0;
        targetStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    }
};

// Define our own matching logic to compare SERVICE_STATUS structs.
MATCHER_P(ServiceStatusEq, pTargetStatus, "") { 
	return (pTargetStatus->dwCurrentState == arg->dwCurrentState) && 
        (pTargetStatus->dwWin32ExitCode == arg->dwWin32ExitCode) &&
        (pTargetStatus->dwWaitHint == arg->dwWaitHint) &&
        (pTargetStatus->dwControlsAccepted == arg->dwControlsAccepted);
}

// Define our own matching logic to compare lpszString array in event logging
MATCHER_P2(EventDataEq, lpszTargetStrings, length, "") { 
    for (int i = 0; i < length; i++) {
        if (strcmp(lpszTargetStrings[i], arg[i]) != 0) return false;
    }
    return true;
}

TEST_F(LoaderSvcTest, TestReportServiceStatus) {
    // SERVICE_START_PENDING
    targetStatus.dwCurrentState = SERVICE_START_PENDING;
    targetStatus.dwWaitHint = 3000;
    targetStatus.dwControlsAccepted = 0;
	EXPECT_CALL(mock_svc_call_wrapper, SetServiceStatusWrapper(loader_service::serviceStatusHandle, &loader_service::serviceStatus))
        .Times(5)
		.WillRepeatedly(Return(true));

    loader_service::ReportServiceStatus(&mock_svc_call_wrapper, SERVICE_START_PENDING, NO_ERROR, 3000);
    EXPECT_THAT(&loader_service::serviceStatus, ServiceStatusEq(&targetStatus));

    // SERVICE_STOP_PENDING
    targetStatus.dwCurrentState = SERVICE_STOP_PENDING;
    targetStatus.dwWaitHint = 0;
    targetStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    loader_service::ReportServiceStatus(&mock_svc_call_wrapper, SERVICE_STOP_PENDING, NO_ERROR, 0);
    EXPECT_THAT(&loader_service::serviceStatus, ServiceStatusEq(&targetStatus));

    // SERVICE_STOPPED
    targetStatus.dwCurrentState = SERVICE_STOPPED;
    loader_service::ReportServiceStatus(&mock_svc_call_wrapper, SERVICE_STOPPED, NO_ERROR, 0);
    EXPECT_THAT(&loader_service::serviceStatus, ServiceStatusEq(&targetStatus));

    // SERVICE_PAUSED
    targetStatus.dwCurrentState = SERVICE_PAUSED;
    loader_service::ReportServiceStatus(&mock_svc_call_wrapper, SERVICE_PAUSED, NO_ERROR, 0);
	EXPECT_THAT(&loader_service::serviceStatus, ServiceStatusEq(&targetStatus));

    // SERVICE_RUNNING
    targetStatus.dwCurrentState = SERVICE_RUNNING;
    loader_service::ReportServiceStatus(&mock_svc_call_wrapper, SERVICE_RUNNING, NO_ERROR, 0);
	EXPECT_THAT(&loader_service::serviceStatus, ServiceStatusEq(&targetStatus));
}

TEST_F(LoaderSvcTest, ServiceCtrlHandlerHandleStop) {
    targetStatus.dwCurrentState = SERVICE_STOP_PENDING;

    EXPECT_CALL(mock_svc_call_wrapper, SetServiceStatusWrapper(loader_service::serviceStatusHandle, ServiceStatusEq(&targetStatus)))
        .Times(2)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(mock_svc_call_wrapper, SetEventWrapper(loader_service::hServiceStopEvent))
        .WillOnce(Return(true));

    ASSERT_EQ(loader_service::ServiceCtrlHandler(SERVICE_CONTROL_STOP, 0, NULL, &mock_svc_call_wrapper), NO_ERROR);
    ASSERT_THAT(&loader_service::serviceStatus, ServiceStatusEq(&targetStatus));
}

TEST_F(LoaderSvcTest, ServiceCtrlHandlerHandleShutdown) {
    targetStatus.dwCurrentState = SERVICE_STOPPED;

    EXPECT_CALL(mock_svc_call_wrapper, SetServiceStatusWrapper(loader_service::serviceStatusHandle, ServiceStatusEq(&targetStatus)))
        .Times(1)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(mock_svc_call_wrapper, SetEventWrapper(loader_service::hServiceStopEvent))
        .WillOnce(Return(true));

    ASSERT_EQ(loader_service::ServiceCtrlHandler(SERVICE_CONTROL_SHUTDOWN, 0, NULL, &mock_svc_call_wrapper), NO_ERROR);
    ASSERT_THAT(&loader_service::serviceStatus, ServiceStatusEq(&targetStatus));
}

TEST_F(LoaderSvcTest, ServiceCtrlHandlerHandlePause) {
    targetStatus.dwCurrentState = SERVICE_PAUSED;

    EXPECT_CALL(mock_svc_call_wrapper, SetServiceStatusWrapper(loader_service::serviceStatusHandle, ServiceStatusEq(&targetStatus)))
        .Times(1)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(mock_svc_call_wrapper, SetEventWrapper(_))
        .Times(0);

    ASSERT_EQ(loader_service::ServiceCtrlHandler(SERVICE_CONTROL_PAUSE, 0, NULL, &mock_svc_call_wrapper), NO_ERROR);
    ASSERT_THAT(&loader_service::serviceStatus, ServiceStatusEq(&targetStatus));
}

TEST_F(LoaderSvcTest, ServiceCtrlHandlerHandleContinue) {
    targetStatus.dwCurrentState = SERVICE_RUNNING;

    EXPECT_CALL(mock_svc_call_wrapper, SetServiceStatusWrapper(loader_service::serviceStatusHandle, ServiceStatusEq(&targetStatus)))
        .Times(1)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(mock_svc_call_wrapper, SetEventWrapper(_))
        .Times(0);

    ASSERT_EQ(loader_service::ServiceCtrlHandler(SERVICE_CONTROL_CONTINUE, 0, NULL, &mock_svc_call_wrapper), NO_ERROR);
    ASSERT_THAT(&loader_service::serviceStatus, ServiceStatusEq(&targetStatus));
}

TEST_F(LoaderSvcTest, ServiceCtrlHandlerHandleInterrogate) {
    EXPECT_CALL(mock_svc_call_wrapper, SetServiceStatusWrapper(_, _))
        .Times(0);
    EXPECT_CALL(mock_svc_call_wrapper, SetEventWrapper(_))
        .Times(0);

    ASSERT_EQ(loader_service::ServiceCtrlHandler(SERVICE_CONTROL_INTERROGATE, 0, NULL, &mock_svc_call_wrapper), NO_ERROR);
}

TEST_F(LoaderSvcTest, ServiceCtrlHandlerHandleDefault) {
    // Other control codes shouldn't change service status
    SERVICE_STATUS targetStatus;
    targetStatus.dwCurrentState = loader_service::serviceStatus.dwCurrentState;
    targetStatus.dwWin32ExitCode = loader_service::serviceStatus.dwWin32ExitCode;
    targetStatus.dwWaitHint = loader_service::serviceStatus.dwWaitHint;
    targetStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;

    EXPECT_CALL(mock_svc_call_wrapper, SetServiceStatusWrapper(loader_service::serviceStatusHandle, ServiceStatusEq(&loader_service::serviceStatus)))
        .Times(1)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(mock_svc_call_wrapper, SetEventWrapper(_))
        .Times(0);

    ASSERT_EQ(loader_service::ServiceCtrlHandler(SERVICE_CONTROL_NETBINDADD, 0, NULL, &mock_svc_call_wrapper), NO_ERROR);
    ASSERT_THAT(&loader_service::serviceStatus, ServiceStatusEq(&targetStatus));
}

TEST_F(LoaderSvcTest, LogEventSuccess) {
    LPCTSTR lpszTargetStrings[2];
    lpszTargetStrings[0] = SERVICE_NAME;
    lpszTargetStrings[1] = TEXT("my mock event message");

    EXPECT_CALL(mock_svc_call_wrapper, RegisterEventSourceWrapper(NULL, StrEq(SERVICE_NAME)))
        .WillOnce(Return(hMockEventSource));
    EXPECT_CALL(mock_svc_call_wrapper, ReportEventWrapper(
        hMockEventSource, 
        EVENTLOG_INFORMATION_TYPE, 
        0, 
        SVC_INFO, 
        NULL, 
        2, 
        0, 
        EventDataEq(lpszTargetStrings, 2), 
        NULL
    )).WillOnce(Return(true));
    EXPECT_CALL(mock_svc_call_wrapper, DeregisterEventSourceWrapper(hMockEventSource))
        .WillOnce(Return(true));

    loader_service::LogEvent(&mock_svc_call_wrapper, TEXT("my mock event message"), EVENTLOG_INFORMATION_TYPE, SVC_INFO);
}

TEST_F(LoaderSvcTest, LogEventFailNullHandle) {
    EXPECT_CALL(mock_svc_call_wrapper, RegisterEventSourceWrapper(NULL, StrEq(SERVICE_NAME)))
        .WillOnce(Return(HANDLE(NULL)));
    EXPECT_CALL(mock_svc_call_wrapper, ReportEventWrapper(_, _, _, _, _, _, _, _, _)).Times(0);
    EXPECT_CALL(mock_svc_call_wrapper, DeregisterEventSourceWrapper(_)).Times(0);

    loader_service::LogEvent(&mock_svc_call_wrapper, TEXT("my mock event message"), EVENTLOG_INFORMATION_TYPE, SVC_INFO);
}

TEST_F(LoaderSvcTest, PrepServiceSuccess) {
    EXPECT_CALL(mock_svc_call_wrapper, RegisterServiceCtrlHandlerExWrapper(StrEq(SERVICE_NAME), (LPHANDLER_FUNCTION_EX)loader_service::ServiceCtrlHandler, &mock_svc_call_wrapper))
        .WillOnce(Return(mockSvcStatusHandle));
    EXPECT_CALL(mock_svc_call_wrapper, SetServiceStatusWrapper(mockSvcStatusHandle, &loader_service::serviceStatus))
        .WillOnce(Return(true));

    ASSERT_EQ(loader_service::PrepService(&mock_svc_call_wrapper), ERROR_SUCCESS);
    ASSERT_EQ(loader_service::serviceStatusHandle, mockSvcStatusHandle);
    ASSERT_EQ(loader_service::serviceStatus.dwServiceType, SERVICE_WIN32_SHARE_PROCESS);
    ASSERT_EQ(loader_service::serviceStatus.dwServiceSpecificExitCode, 0);
    ASSERT_EQ(loader_service::serviceStatus.dwCurrentState, SERVICE_START_PENDING);
    ASSERT_EQ(loader_service::serviceStatus.dwWin32ExitCode, NO_ERROR);
    ASSERT_EQ(loader_service::serviceStatus.dwWaitHint, 3000);
    ASSERT_EQ(loader_service::serviceStatus.dwControlsAccepted, 0);
}

TEST_F(LoaderSvcTest, PrepServiceFailRegisterCtrlHandler) {
    LPCTSTR lpszTargetStrings[2];
    lpszTargetStrings[0] = SERVICE_NAME;
    lpszTargetStrings[1] = TEXT("Failed to set up service. Error code: 512");
    
    EXPECT_CALL(mock_svc_call_wrapper, RegisterServiceCtrlHandlerExWrapper(StrEq(SERVICE_NAME), (LPHANDLER_FUNCTION_EX)loader_service::ServiceCtrlHandler, &mock_svc_call_wrapper))
        .WillOnce(Return(SERVICE_STATUS_HANDLE(NULL)));
    EXPECT_CALL(mock_svc_call_wrapper, SetServiceStatusWrapper(_, _))
        .Times(0);
    EXPECT_CALL(mock_svc_call_wrapper, RegisterEventSourceWrapper(NULL, StrEq(SERVICE_NAME)))
        .WillOnce(Return(hMockEventSource));
    EXPECT_CALL(mock_svc_call_wrapper, ReportEventWrapper(
        hMockEventSource, 
        EVENTLOG_ERROR_TYPE, 
        0, 
        SVC_ERROR, 
        NULL, 
        2, 
        0, 
        EventDataEq(lpszTargetStrings, 2), 
        NULL
    )).WillOnce(Return(true));
    EXPECT_CALL(mock_svc_call_wrapper, DeregisterEventSourceWrapper(hMockEventSource))
        .WillOnce(Return(true));

    ASSERT_EQ(loader_service::PrepService(&mock_svc_call_wrapper), FAILURE_REGISTER_SVC_CTRL_HANDLER);
    ASSERT_EQ(loader_service::serviceStatusHandle, SERVICE_STATUS_HANDLE(NULL));
    ASSERT_EQ(loader_service::serviceStatus.dwServiceType, 0);
    ASSERT_EQ(loader_service::serviceStatus.dwServiceSpecificExitCode, 0);
    ASSERT_EQ(loader_service::serviceStatus.dwCurrentState, 0);
    ASSERT_EQ(loader_service::serviceStatus.dwWin32ExitCode, 0);
    ASSERT_EQ(loader_service::serviceStatus.dwWaitHint, 0);
    ASSERT_EQ(loader_service::serviceStatus.dwControlsAccepted, 0);
}

TEST_F(LoaderSvcTest, BeginServiceFailCreateEvent) {
    LPCTSTR lpszTargetStrings[2];
    lpszTargetStrings[0] = SERVICE_NAME;
    lpszTargetStrings[1] = TEXT("Failed to create service event.");

    EXPECT_CALL(mock_svc_call_wrapper, CreateEventWrapper(NULL, TRUE, FALSE, NULL))
        .WillOnce(Return(HANDLE(NULL)));
    EXPECT_CALL(mock_svc_call_wrapper, RegisterEventSourceWrapper(NULL, StrEq(SERVICE_NAME)))
        .WillOnce(Return(hMockEventSource));
    EXPECT_CALL(mock_svc_call_wrapper, ReportEventWrapper(
        hMockEventSource, 
        EVENTLOG_ERROR_TYPE, 
        0, 
        SVC_ERROR, 
        NULL, 
        2, 
        0, 
        EventDataEq(lpszTargetStrings, 2), 
        NULL
    )).WillOnce(Return(true));
    EXPECT_CALL(mock_svc_call_wrapper, DeregisterEventSourceWrapper(hMockEventSource))
        .WillOnce(Return(true));
    EXPECT_CALL(mock_svc_call_wrapper, SetServiceStatusWrapper(loader_service::serviceStatusHandle, &loader_service::serviceStatus))
        .WillOnce(Return(true));
    EXPECT_CALL(mock_svc_call_wrapper, WaitForSingleObjectWrapper(_, _))
        .Times(0);

    loader_service::BeginService(&mock_svc_call_wrapper, 1, NULL);
    ASSERT_EQ(loader_service::serviceStatus.dwCurrentState, SERVICE_STOPPED);
    ASSERT_EQ(loader_service::serviceStatus.dwWin32ExitCode, NO_ERROR);
    ASSERT_EQ(loader_service::serviceStatus.dwWaitHint, 0);
    ASSERT_EQ(loader_service::serviceStatus.dwControlsAccepted, SERVICE_ACCEPT_STOP);
}

TEST_F(LoaderSvcTest, BeginServiceSuccess) {
    SERVICE_STATUS runningStatus;
    runningStatus.dwCurrentState = SERVICE_RUNNING;
    runningStatus.dwWin32ExitCode = NO_ERROR;
    runningStatus.dwWaitHint = 0;
    runningStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    SERVICE_STATUS stoppedStatus;
    stoppedStatus.dwCurrentState = SERVICE_STOPPED;
    stoppedStatus.dwWin32ExitCode = NO_ERROR;
    stoppedStatus.dwWaitHint = 0;
    stoppedStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;

    EXPECT_CALL(mock_svc_call_wrapper, CreateEventWrapper(NULL, TRUE, FALSE, NULL))
        .WillOnce(Return(hMockStopEvent));

    // Service reports that it's running
    EXPECT_CALL(mock_svc_call_wrapper, SetServiceStatusWrapper(loader_service::serviceStatusHandle, ServiceStatusEq(&runningStatus)))
        .WillOnce(Return(true));

    // Run module
    EXPECT_CALL(mock_svc_call_wrapper, LoadLibraryWrapper(StrEq(ORCHESTRATOR_PATH)))
        .WillOnce(Return(hMockModule));
    EXPECT_CALL(mock_svc_call_wrapper, GetProcAddressWrapper(hMockModule, StrEq(ORCHESTRATOR_INIT_FUNC_NAME)))
        .WillOnce(Return(dummy_func));
    EXPECT_CALL(mock_svc_call_wrapper, ModuleInitWrapper((fp_module_init)dummy_func))
        .Times(1);
    
    // Pretend to tell service to stop
    // Reference: https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject
    EXPECT_CALL(mock_svc_call_wrapper, WaitForSingleObjectWrapper(hMockStopEvent, INFINITE))
        .WillOnce(Return(WAIT_OBJECT_0));

    // Service reports that it has stopped
    EXPECT_CALL(mock_svc_call_wrapper, SetServiceStatusWrapper(loader_service::serviceStatusHandle, ServiceStatusEq(&stoppedStatus)))
        .WillOnce(Return(true));

    loader_service::BeginService(&mock_svc_call_wrapper, 1, NULL);
    ASSERT_EQ(loader_service::serviceStatus.dwCurrentState, SERVICE_STOPPED);
    ASSERT_EQ(loader_service::serviceStatus.dwWin32ExitCode, NO_ERROR);
    ASSERT_EQ(loader_service::serviceStatus.dwWaitHint, 0);
    ASSERT_EQ(loader_service::serviceStatus.dwControlsAccepted, SERVICE_ACCEPT_STOP);
}

TEST_F(LoaderSvcTest, RunModuleFailLoadModule) {
    LPCTSTR lpszTargetStrings[2];
    lpszTargetStrings[0] = SERVICE_NAME;
    lpszTargetStrings[1] = TEXT("Could not load required module.");

    EXPECT_CALL(mock_svc_call_wrapper, LoadLibraryWrapper(StrEq(mock_module_path)))
        .WillOnce(Return(HMODULE(NULL)));
    EXPECT_CALL(mock_svc_call_wrapper, RegisterEventSourceWrapper(NULL, StrEq(SERVICE_NAME)))
        .WillOnce(Return(hMockEventSource));
    EXPECT_CALL(mock_svc_call_wrapper, ReportEventWrapper(
        hMockEventSource, 
        EVENTLOG_ERROR_TYPE, 
        0, 
        SVC_ERROR, 
        NULL, 
        2, 
        0, 
        EventDataEq(lpszTargetStrings, 2), 
        NULL
    )).WillOnce(Return(true));
    EXPECT_CALL(mock_svc_call_wrapper, DeregisterEventSourceWrapper(hMockEventSource))
        .WillOnce(Return(true));
    EXPECT_CALL(mock_svc_call_wrapper, GetProcAddressWrapper(_, _))
        .Times(0);
    EXPECT_CALL(mock_svc_call_wrapper, ModuleInitWrapper(_))
        .Times(0);

    loader_service::RunModule(&mock_svc_call_wrapper, mock_module_path, mock_init_func_name);
}

TEST_F(LoaderSvcTest, RunModuleFailGetProcAddress) {
    LPCTSTR lpszTargetStrings[2];
    lpszTargetStrings[0] = SERVICE_NAME;
    lpszTargetStrings[1] = TEXT("Could not find required module function.");

    EXPECT_CALL(mock_svc_call_wrapper, LoadLibraryWrapper(StrEq(mock_module_path)))
        .WillOnce(Return(hMockModule));
    EXPECT_CALL(mock_svc_call_wrapper, GetProcAddressWrapper(hMockModule, StrEq(mock_init_func_name)))
        .WillOnce(Return(FARPROC(NULL)));
    EXPECT_CALL(mock_svc_call_wrapper, RegisterEventSourceWrapper(NULL, StrEq(SERVICE_NAME)))
        .WillOnce(Return(hMockEventSource));
    EXPECT_CALL(mock_svc_call_wrapper, ReportEventWrapper(
        hMockEventSource, 
        EVENTLOG_ERROR_TYPE, 
        0, 
        SVC_ERROR, 
        NULL, 
        2, 
        0, 
        EventDataEq(lpszTargetStrings, 2), 
        NULL
    )).WillOnce(Return(true));
    EXPECT_CALL(mock_svc_call_wrapper, DeregisterEventSourceWrapper(hMockEventSource))
        .WillOnce(Return(true));
    EXPECT_CALL(mock_svc_call_wrapper, ModuleInitWrapper(_))
        .Times(0);

    loader_service::RunModule(&mock_svc_call_wrapper, mock_module_path, mock_init_func_name);
}