#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <windows.h>
#include "execute.h"
#include "test_util.h"
#include <string>
#include <cstring>
#include <iostream>

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;
using ::testing::StrEq;
using ::testing::WithArg;
using ::testing::SaveArg;
using ::testing::SetArgPointee;
using ::testing::InSequence;
using ::testing::Each;

// Text fixture for shared data
class ExecuteTest : public ::testing::Test {
protected:
    MockApiWrapper mock_api_wrapper;
    std::string mock_timestamp = "2000-12-01 12:34:56";
    LPCWSTR mock_command = L"dummy commandline args";
    LPCWSTR expected_command_line = L"C:\\Windows\\System32\\cmd.exe /c dummy commandline args";
    LPCWSTR mock_psh_command = L"ZwBlAHQALQBjAGgAaQBsAGQAaQB0AGUAbQAgAHQAZQBzAHQAaQBuAGcA";
    LPCWSTR expected_psh_command_line = L"powershell.exe -nol -noni -nop -enc ZwBlAHQALQBjAGgAaQBsAGQAaQB0AGUAbQAgAHQAZQBzAHQAaQBuAGcA";
    LPCWSTR mock_proc_binary = L"C:\\path to\\my\\executable.exe";
    LPCWSTR mock_proc_args = L"arg1 arg2 argwith|special&characters#@";
    LPCWSTR expected_proc_command_line_no_args = L"\"C:\\path to\\my\\executable.exe\"";
    LPCWSTR expected_proc_command_line = L"\"C:\\path to\\my\\executable.exe\" arg1 arg2 argwith|special&characters#@";
    DWORD mock_timeout_seconds = 60;
    SECURITY_ATTRIBUTES mock_file_sa; 
    STARTUPINFOW mock_startup_info;
    STARTUPINFOW mock_startup_info_token;
    PROCESS_INFORMATION mock_proc_info;
    DWORD mock_proc_id = 678;
    DWORD mock_thread_id = 789;
    HANDLE mock_h_proc = HANDLE(2345);
    HANDLE mock_h_thread = HANDLE(3456);
    HANDLE mock_pipe_rd = HANDLE(1111);
    HANDLE mock_pipe_wr = HANDLE(2222);
    DWORD mock_exit_code = ERROR_SUCCESS;
    DWORD mock_error = 9876;
    HANDLE h_dummy_mutex = HANDLE(8888);
    std::wstring dummy_runas_user = L"dummydomain\\dummyuser";
    HANDLE mock_h_snapshot = HANDLE(23456);
    PROCESSENTRY32 dummy_pe;
    PROCESSENTRY32 dummy_pe_target_nonelev;
    PROCESSENTRY32 dummy_pe_target_elev;
    DWORD dummy_pid = 123;
    DWORD dummy_pid_nonelev = 234;
    DWORD dummy_pid_elev = 345;
    DWORD dummy_thread_id = 88889;
    HDESK dummy_h_desktop = HDESK(3001);
    HANDLE dummy_h_proc = HANDLE(123);
    HANDLE dummy_h_proc_nonelev = HANDLE(234);
    HANDLE dummy_h_proc_elev = HANDLE(345);
    HANDLE dummy_h_proc_token = HANDLE(1123);
    HANDLE dummy_h_proc_token_nonelev = HANDLE(1234);
    HANDLE dummy_h_proc_token_elev = HANDLE(1345);
    DWORD mock_info_size = 100;
    static constexpr LPCWSTR dummy_proc_owner = L"someuser";
    static constexpr LPCWSTR dummy_target_owner = L"dummyuser";
    static constexpr LPCWSTR dummy_domain = L"dummydomain";
    HANDLE dummy_h_to_dup_nonelev = HANDLE(1010);
    HANDLE dummy_h_to_dup_elev = HANDLE(1011);
    HANDLE dummy_h_duped_nonelev = HANDLE(21010);
    HANDLE dummy_h_duped_elev = HANDLE(21011);
    HWINSTA dummy_h_win_station = HWINSTA(3000);
    EXPLICIT_ACCESSW mock_access_to_grant;

    void SetUp() override {
        mock_file_sa.nLength = sizeof(mock_file_sa);
        mock_file_sa.lpSecurityDescriptor = NULL;
        mock_file_sa.bInheritHandle = TRUE;

        ZeroMemory(&mock_startup_info, sizeof(mock_startup_info));
        mock_startup_info.cb = sizeof(mock_startup_info);
        mock_startup_info.dwFlags = STARTF_USESTDHANDLES;
        mock_startup_info.hStdOutput = mock_pipe_wr;
        mock_startup_info.hStdError = mock_pipe_wr;

        ZeroMemory(&mock_startup_info_token, sizeof(mock_startup_info_token));
        mock_startup_info_token.cb = sizeof(mock_startup_info_token);
        mock_startup_info_token.dwFlags = STARTF_USESTDHANDLES;
        mock_startup_info_token.hStdOutput = mock_pipe_wr;
        mock_startup_info_token.hStdError = mock_pipe_wr;

        mock_proc_info.dwProcessId = mock_proc_id;
        mock_proc_info.dwThreadId = mock_thread_id;
        mock_proc_info.hProcess = mock_h_proc;
        mock_proc_info.hThread = mock_h_thread;

        logging::h_execution_log_mutex = h_dummy_mutex;

        memset(&dummy_pe, 0, sizeof(PROCESSENTRY32));
        memset(&dummy_pe_target_elev, 0, sizeof(PROCESSENTRY32));
        memset(&dummy_pe_target_nonelev, 0, sizeof(PROCESSENTRY32));
        dummy_pe.dwSize = sizeof(PROCESSENTRY32);
        dummy_pe_target_elev.dwSize = sizeof(PROCESSENTRY32);
        dummy_pe_target_nonelev.dwSize = sizeof(PROCESSENTRY32);

        dummy_pe.th32ProcessID = dummy_pid;
        dummy_pe_target_elev.th32ProcessID = dummy_pid_elev;
        dummy_pe_target_nonelev.th32ProcessID = dummy_pid_nonelev;

        mock_access_to_grant.grfAccessPermissions = WINSTA_ALL_ACCESS | READ_CONTROL;
        mock_access_to_grant.grfAccessMode = SET_ACCESS;
        mock_access_to_grant.grfInheritance = NO_INHERITANCE;
        mock_access_to_grant.Trustee.pMultipleTrustee = NULL;
        mock_access_to_grant.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
        mock_access_to_grant.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        mock_access_to_grant.Trustee.TrusteeType = TRUSTEE_IS_USER;
    }
};

// Define our own matching logic to compare SECURITY_ATTRIBUTE structs
MATCHER_P(SecurityAttrStructEq, pTarget, "") {
    return (pTarget->nLength == arg->nLength) &&
        (pTarget->bInheritHandle == arg->bInheritHandle);
}

MATCHER_P(ExplicitAccessStructEq, pTarget, "") {
    return (pTarget->grfAccessPermissions == arg->grfAccessPermissions) &&
        (pTarget->grfAccessMode == arg->grfAccessMode) &&
        (pTarget->grfInheritance == arg->grfInheritance) &&
        (pTarget->Trustee.pMultipleTrustee == arg->Trustee.pMultipleTrustee) &&
        (pTarget->Trustee.MultipleTrusteeOperation == arg->Trustee.MultipleTrusteeOperation) &&
        (pTarget->Trustee.TrusteeForm == arg->Trustee.TrusteeForm) &&
        (pTarget->Trustee.TrusteeType == arg->Trustee.TrusteeType);
}

// Define our own matching logic to compare STARTUPINFOW structs
MATCHER_P(StartupInfoStructEq, pTarget, "") {
    return (pTarget->cb == arg->cb) && 
        (pTarget->dwFlags == arg->dwFlags) && 
        (pTarget->hStdInput == arg->hStdInput) && 
        (pTarget->hStdOutput == arg->hStdOutput) &&
        (pTarget->hStdError == arg->hStdError);
}

// Define our own matching logic to compare PROCESS_INFORMATION structs
MATCHER_P(ProcInfoStructEq, pTarget, "") {
    if (pTarget->hProcess != arg->hProcess) {
        std::cout << "Different hProcess values: " << pTarget->hProcess << ", " << arg->hProcess << std::endl;
        return FALSE;
    }
    if (pTarget->hThread != arg->hThread) {
        std::cout << "Different hThread values: " << pTarget->hThread << ", " << arg->hThread << std::endl;
        return FALSE;
    }
    if (pTarget->dwProcessId != arg->dwProcessId) {
        std::cout << "Different dwProcessId values: " << pTarget->dwProcessId << ", " << arg->dwProcessId << std::endl;
        return FALSE;
    }
    if (pTarget->dwThreadId != arg->dwThreadId) {
        std::cout << "Different dwThreadId values: " << pTarget->dwThreadId << ", " << arg->dwThreadId << std::endl;
        return FALSE;
    }
    return TRUE;
}

// Custom action to set our process info struct output for CreateProcessWrapper
ACTION_P(SetProcessInfoStruct, param) {
    arg0->dwProcessId = param->dwProcessId;
    arg0->dwThreadId = param->dwThreadId;
    arg0->hProcess = param->hProcess;
    arg0->hThread = param->hThread;
}

// Custom action to set our process entry 32 struct output
ACTION_P(SetProcessEntryStruct, param) {
    arg0->dwSize = param->dwSize;
    arg0->th32ProcessID = param->th32ProcessID;
}

// Custom action to assign a handle
ACTION_P(SetHandleOutput, param) {
    std::memcpy(arg0, &param, sizeof(param));
}

TEST_F(ExecuteTest, TestExecuteCmdCommandSuccess) {
    InSequence s;
    LPVOID mock_buf;
    DWORD result;

    EXPECT_CALL(mock_api_wrapper, ConvertStringSecurityDescriptorToSecurityDescriptorWrapper(
        StrEq(L"D:(D;OICI;GA;;;BG)(D;OICI;GA;;;AN)(A;OICI;GRGWGX;;;AU)(A;OICI;GA;;;BA)"),
        SDDL_REVISION_1,
        _,
        NULL
    )).Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, CreatePipeWrapper(
        _,
        _,
        SecurityAttrStructEq(&mock_file_sa),
        0
    )).Times(1).WillOnce(DoAll(
        SetArgPointee<0>(mock_pipe_rd),
        SetArgPointee<1>(mock_pipe_wr),
        Return(TRUE)
    ));

    EXPECT_CALL(mock_api_wrapper, LocalFreeWrapper(_)).Times(1).WillOnce(Return(HLOCAL(NULL)));

    EXPECT_CALL(mock_api_wrapper, SetHandleInformationWrapper(mock_pipe_rd, HANDLE_FLAG_INHERIT, 0))
        .Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, CreateProcessWrapper(
        NULL,
        StrEq(expected_command_line),
        NULL, 
        NULL,
        TRUE,
        CREATE_NO_WINDOW,
        NULL,
        NULL,
        StartupInfoStructEq(&mock_startup_info),
        _
    )).Times(1).WillOnce(DoAll(
        WithArg<9>(SetProcessInfoStruct(&mock_proc_info)), 
        Return(TRUE)
    ));

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_mutex, MUTEX_WAIT_MS)).Times(1).WillOnce(Return(WAIT_OBJECT_0));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kExecutionLogFile), _)).Times(1);
    EXPECT_CALL(mock_api_wrapper, ReleaseMutexWrapper(h_dummy_mutex)).Times(1).WillOnce(Return(TRUE));
    
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(
        mock_proc_info.hProcess,
        WAIT_CHUNK_MS
    )).Times(1).WillOnce(Return(WAIT_OBJECT_0));

    EXPECT_CALL(mock_api_wrapper, GetExitCodeProcessWrapper(
        mock_proc_info.hProcess,
        _
    )).Times(1).WillOnce(DoAll(SetArgPointee<1>(mock_exit_code), Return(TRUE)));

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_mutex, MUTEX_WAIT_MS)).Times(1).WillOnce(Return(WAIT_OBJECT_0));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kExecutionLogFile), _)).Times(1);
    EXPECT_CALL(mock_api_wrapper, ReleaseMutexWrapper(h_dummy_mutex)).Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, PeekNamedPipeWrapper(mock_pipe_rd, NULL, 0, NULL, _, NULL))
        .Times(1).WillOnce(DoAll(
            SetArgPointee<4>(100),
            Return(TRUE)
        ));

    EXPECT_CALL(mock_api_wrapper, ReadFileWrapper(
        mock_pipe_rd, 
        _,
        PIPE_READ_BUFFER_SIZE,
        _, 
        NULL
    )).Times(1).WillOnce(DoAll(
        SaveArg<1>(&mock_buf),
        [&mock_buf]() { std::memset(mock_buf, 65, 100); }, // fill with "A"
        SetArgPointee<3>(100),
        Return(TRUE)
    ));

    EXPECT_CALL(mock_api_wrapper, PeekNamedPipeWrapper(mock_pipe_rd, NULL, 0, NULL, _, NULL))
        .Times(1).WillOnce(Return(FALSE));

    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(mock_proc_info.hProcess)).Times(1);
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(mock_proc_info.hThread)).Times(1);

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_mutex, MUTEX_WAIT_MS)).Times(1).WillOnce(Return(WAIT_OBJECT_0));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kExecutionLogFile), _)).Times(1);
    EXPECT_CALL(mock_api_wrapper, ReleaseMutexWrapper(h_dummy_mutex)).Times(1).WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(mock_pipe_wr)).Times(1);
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(mock_pipe_rd)).Times(1);
    
    std::vector<char> output = execute::ExecuteCmdCommand(&mock_api_wrapper, mock_command, L"", mock_timeout_seconds, &result);
    ASSERT_EQ(result, ERROR_SUCCESS);
    ASSERT_EQ(output.size(), 100);
    ASSERT_THAT(output, Each(65));
}

TEST_F(ExecuteTest, TestExecuteCmdCommandFailTimeout) {
    InSequence s;
    DWORD result;

    EXPECT_CALL(mock_api_wrapper, ConvertStringSecurityDescriptorToSecurityDescriptorWrapper(
        StrEq(L"D:(D;OICI;GA;;;BG)(D;OICI;GA;;;AN)(A;OICI;GRGWGX;;;AU)(A;OICI;GA;;;BA)"),
        SDDL_REVISION_1,
        _,
        NULL
    )).Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, CreatePipeWrapper(
        _,
        _,
        SecurityAttrStructEq(&mock_file_sa),
        0
    )).Times(1).WillOnce(DoAll(
        SetArgPointee<0>(mock_pipe_rd),
        SetArgPointee<1>(mock_pipe_wr),
        Return(TRUE)
    ));

    EXPECT_CALL(mock_api_wrapper, LocalFreeWrapper(_)).Times(1).WillOnce(Return(HLOCAL(NULL)));

    EXPECT_CALL(mock_api_wrapper, SetHandleInformationWrapper(mock_pipe_rd, HANDLE_FLAG_INHERIT, 0))
        .Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, CreateProcessWrapper(
        NULL,
        StrEq(expected_command_line),
        NULL, 
        NULL,
        TRUE,
        CREATE_NO_WINDOW,
        NULL,
        NULL,
        StartupInfoStructEq(&mock_startup_info),
        _
    )).Times(1).WillOnce(DoAll(
        WithArg<9>(SetProcessInfoStruct(&mock_proc_info)), 
        Return(TRUE)
    ));
    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_mutex, MUTEX_WAIT_MS)).Times(1).WillOnce(Return(WAIT_OBJECT_0));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kExecutionLogFile), _)).Times(1);
    EXPECT_CALL(mock_api_wrapper, ReleaseMutexWrapper(h_dummy_mutex)).Times(1).WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(
        mock_proc_info.hProcess,
        WAIT_CHUNK_MS
    )).Times(1).WillOnce(Return(WAIT_TIMEOUT));
    EXPECT_CALL(mock_api_wrapper, PeekNamedPipeWrapper(mock_pipe_rd, NULL, 0, NULL, _, NULL))
        .Times(1).WillOnce(Return(FALSE));

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_mutex, MUTEX_WAIT_MS)).Times(1).WillOnce(Return(WAIT_OBJECT_0));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kExecutionLogFile), _)).Times(1);
    EXPECT_CALL(mock_api_wrapper, ReleaseMutexWrapper(h_dummy_mutex)).Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(mock_proc_info.hProcess)).Times(1);
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(mock_proc_info.hThread)).Times(1);

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_mutex, MUTEX_WAIT_MS)).Times(1).WillOnce(Return(WAIT_OBJECT_0));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kExecutionLogFile), _)).Times(1);
    EXPECT_CALL(mock_api_wrapper, ReleaseMutexWrapper(h_dummy_mutex)).Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(mock_pipe_wr)).Times(1);
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(mock_pipe_rd)).Times(1);
    
    std::vector<char> output = execute::ExecuteCmdCommand(&mock_api_wrapper, mock_command, L"", 0, &result);
    ASSERT_EQ(result, FAIL_TIMEOUT_REACHED);
    ASSERT_EQ(output.size(), 0);
}


TEST_F(ExecuteTest, TestExecuteCmdCommandFailWait) {
    InSequence s;
    DWORD result;

    EXPECT_CALL(mock_api_wrapper, ConvertStringSecurityDescriptorToSecurityDescriptorWrapper(
        StrEq(L"D:(D;OICI;GA;;;BG)(D;OICI;GA;;;AN)(A;OICI;GRGWGX;;;AU)(A;OICI;GA;;;BA)"),
        SDDL_REVISION_1,
        _,
        NULL
    )).Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, CreatePipeWrapper(
        _,
        _,
        SecurityAttrStructEq(&mock_file_sa),
        0
    )).Times(1).WillOnce(DoAll(
        SetArgPointee<0>(mock_pipe_rd),
        SetArgPointee<1>(mock_pipe_wr),
        Return(TRUE)
    ));

    EXPECT_CALL(mock_api_wrapper, LocalFreeWrapper(_)).Times(1).WillOnce(Return(HLOCAL(NULL)));

    EXPECT_CALL(mock_api_wrapper, SetHandleInformationWrapper(mock_pipe_rd, HANDLE_FLAG_INHERIT, 0))
        .Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, CreateProcessWrapper(
        NULL,
        StrEq(expected_command_line),
        NULL, 
        NULL,
        TRUE,
        CREATE_NO_WINDOW,
        NULL,
        NULL,
        StartupInfoStructEq(&mock_startup_info),
        _
    )).Times(1).WillOnce(DoAll(
        WithArg<9>(SetProcessInfoStruct(&mock_proc_info)), 
        Return(TRUE)
    ));

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_mutex, MUTEX_WAIT_MS)).Times(1).WillOnce(Return(WAIT_OBJECT_0));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kExecutionLogFile), _)).Times(1);
    EXPECT_CALL(mock_api_wrapper, ReleaseMutexWrapper(h_dummy_mutex)).Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(
        mock_proc_info.hProcess,
        WAIT_CHUNK_MS
    )).Times(1).WillOnce(Return(WAIT_FAILED));

    EXPECT_CALL(mock_api_wrapper, GetLastErrorWrapper()).Times(1).WillOnce(Return(mock_error));
    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_mutex, MUTEX_WAIT_MS)).Times(1).WillOnce(Return(WAIT_OBJECT_0));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kExecutionLogFile), _)).Times(1);
    EXPECT_CALL(mock_api_wrapper, ReleaseMutexWrapper(h_dummy_mutex)).Times(1).WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, GetExitCodeProcessWrapper(_, _)).Times(0);
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(mock_proc_info.hProcess)).Times(1);
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(mock_proc_info.hThread)).Times(1);
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(mock_pipe_wr)).Times(1);
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(mock_pipe_rd)).Times(1);
    
    std::vector<char> output = execute::ExecuteCmdCommand(&mock_api_wrapper, mock_command, L"", mock_timeout_seconds, &result);
    ASSERT_EQ(result, mock_error);
    ASSERT_EQ(output.size(), 0);
}

TEST_F(ExecuteTest, TestExecutePshCommandSuccess) {
    InSequence s;
    LPVOID mock_buf;
    DWORD result;

    EXPECT_CALL(mock_api_wrapper, ConvertStringSecurityDescriptorToSecurityDescriptorWrapper(
        StrEq(L"D:(D;OICI;GA;;;BG)(D;OICI;GA;;;AN)(A;OICI;GRGWGX;;;AU)(A;OICI;GA;;;BA)"),
        SDDL_REVISION_1,
        _,
        NULL
    )).Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, CreatePipeWrapper(
        _,
        _,
        SecurityAttrStructEq(&mock_file_sa),
        0
    )).Times(1).WillOnce(DoAll(
        SetArgPointee<0>(mock_pipe_rd),
        SetArgPointee<1>(mock_pipe_wr),
        Return(TRUE)
    ));

    EXPECT_CALL(mock_api_wrapper, LocalFreeWrapper(_)).Times(1).WillOnce(Return(HLOCAL(NULL)));

    EXPECT_CALL(mock_api_wrapper, SetHandleInformationWrapper(mock_pipe_rd, HANDLE_FLAG_INHERIT, 0))
        .Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, CreateProcessWrapper(
        NULL,
        StrEq(expected_psh_command_line),
        NULL, 
        NULL,
        TRUE,
        CREATE_NO_WINDOW,
        NULL,
        NULL,
        StartupInfoStructEq(&mock_startup_info),
        _
    )).Times(1).WillOnce(DoAll(
        WithArg<9>(SetProcessInfoStruct(&mock_proc_info)), 
        Return(TRUE)
    ));

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_mutex, MUTEX_WAIT_MS)).Times(1).WillOnce(Return(WAIT_OBJECT_0));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kExecutionLogFile), _)).Times(1);
    EXPECT_CALL(mock_api_wrapper, ReleaseMutexWrapper(h_dummy_mutex)).Times(1).WillOnce(Return(TRUE));
    
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(
        mock_proc_info.hProcess,
        WAIT_CHUNK_MS
    )).Times(1).WillOnce(Return(WAIT_OBJECT_0));

    EXPECT_CALL(mock_api_wrapper, GetExitCodeProcessWrapper(
        mock_proc_info.hProcess,
        _
    )).Times(1).WillOnce(DoAll(SetArgPointee<1>(mock_exit_code), Return(TRUE)));

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_mutex, MUTEX_WAIT_MS)).Times(1).WillOnce(Return(WAIT_OBJECT_0));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kExecutionLogFile), _)).Times(1);
    EXPECT_CALL(mock_api_wrapper, ReleaseMutexWrapper(h_dummy_mutex)).Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, PeekNamedPipeWrapper(mock_pipe_rd, NULL, 0, NULL, _, NULL))
        .Times(1).WillOnce(DoAll(
            SetArgPointee<4>(100),
            Return(TRUE)
        ));

    EXPECT_CALL(mock_api_wrapper, ReadFileWrapper(
        mock_pipe_rd, 
        _,
        PIPE_READ_BUFFER_SIZE,
        _, 
        NULL
    )).Times(1).WillOnce(DoAll(
        SaveArg<1>(&mock_buf),
        [&mock_buf]() { std::memset(mock_buf, 65, 100); }, // fill with "A"
        SetArgPointee<3>(100),
        Return(TRUE)
    ));

    EXPECT_CALL(mock_api_wrapper, PeekNamedPipeWrapper(mock_pipe_rd, NULL, 0, NULL, _, NULL))
        .Times(1).WillOnce(Return(FALSE));
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(mock_proc_info.hProcess)).Times(1);
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(mock_proc_info.hThread)).Times(1);

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_mutex, MUTEX_WAIT_MS)).Times(1).WillOnce(Return(WAIT_OBJECT_0));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kExecutionLogFile), _)).Times(1);
    EXPECT_CALL(mock_api_wrapper, ReleaseMutexWrapper(h_dummy_mutex)).Times(1).WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(mock_pipe_wr)).Times(1);
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(mock_pipe_rd)).Times(1);
    
    std::vector<char> output = execute::ExecutePshCommand(&mock_api_wrapper, mock_psh_command, L"", mock_timeout_seconds, &result);
    ASSERT_EQ(result, ERROR_SUCCESS);
    ASSERT_EQ(output.size(), 100);
    ASSERT_THAT(output, Each(65));
}

TEST_F(ExecuteTest, TestExecuteProcCommandNoArgsSuccess) {
    InSequence s;
    LPVOID mock_buf;
    DWORD result;

    EXPECT_CALL(mock_api_wrapper, ConvertStringSecurityDescriptorToSecurityDescriptorWrapper(
        StrEq(L"D:(D;OICI;GA;;;BG)(D;OICI;GA;;;AN)(A;OICI;GRGWGX;;;AU)(A;OICI;GA;;;BA)"),
        SDDL_REVISION_1,
        _,
        NULL
    )).Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, CreatePipeWrapper(
        _,
        _,
        SecurityAttrStructEq(&mock_file_sa),
        0
    )).Times(1).WillOnce(DoAll(
        SetArgPointee<0>(mock_pipe_rd),
        SetArgPointee<1>(mock_pipe_wr),
        Return(TRUE)
    ));

    EXPECT_CALL(mock_api_wrapper, LocalFreeWrapper(_)).Times(1).WillOnce(Return(HLOCAL(NULL)));

    EXPECT_CALL(mock_api_wrapper, SetHandleInformationWrapper(mock_pipe_rd, HANDLE_FLAG_INHERIT, 0))
        .Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, CreateProcessWrapper(
        NULL,
        StrEq(expected_proc_command_line_no_args),
        NULL, 
        NULL,
        TRUE,
        CREATE_NO_WINDOW,
        NULL,
        NULL,
        StartupInfoStructEq(&mock_startup_info),
        _
    )).Times(1).WillOnce(DoAll(
        WithArg<9>(SetProcessInfoStruct(&mock_proc_info)), 
        Return(TRUE)
    ));

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_mutex, MUTEX_WAIT_MS)).Times(1).WillOnce(Return(WAIT_OBJECT_0));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kExecutionLogFile), _)).Times(1);
    EXPECT_CALL(mock_api_wrapper, ReleaseMutexWrapper(h_dummy_mutex)).Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(
        mock_proc_info.hProcess,
        WAIT_CHUNK_MS
    )).Times(1).WillOnce(Return(WAIT_TIMEOUT));

    EXPECT_CALL(mock_api_wrapper, PeekNamedPipeWrapper(mock_pipe_rd, NULL, 0, NULL, _, NULL))
        .Times(1).WillOnce(DoAll(
            SetArgPointee<4>(50),
            Return(TRUE)
        ));

    EXPECT_CALL(mock_api_wrapper, ReadFileWrapper(
        mock_pipe_rd, 
        _,
        PIPE_READ_BUFFER_SIZE,
        _, 
        NULL
    )).Times(1).WillOnce(DoAll(
        SaveArg<1>(&mock_buf),
        [&mock_buf]() { std::memset(mock_buf, 65, 50); }, // fill with "A"
        SetArgPointee<3>(50),
        Return(TRUE)
    ));

    EXPECT_CALL(mock_api_wrapper, PeekNamedPipeWrapper(mock_pipe_rd, NULL, 0, NULL, _, NULL))
        .Times(1).WillOnce(Return(FALSE));

    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(
        mock_proc_info.hProcess,
        WAIT_CHUNK_MS
    )).Times(1).WillOnce(Return(WAIT_OBJECT_0));

    EXPECT_CALL(mock_api_wrapper, GetExitCodeProcessWrapper(
        mock_proc_info.hProcess,
        _
    )).Times(1).WillOnce(DoAll(SetArgPointee<1>(mock_exit_code), Return(TRUE)));

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_mutex, MUTEX_WAIT_MS)).Times(1).WillOnce(Return(WAIT_OBJECT_0));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kExecutionLogFile), _)).Times(1);
    EXPECT_CALL(mock_api_wrapper, ReleaseMutexWrapper(h_dummy_mutex)).Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, PeekNamedPipeWrapper(mock_pipe_rd, NULL, 0, NULL, _, NULL))
        .Times(1).WillOnce(DoAll(
            SetArgPointee<4>(50),
            Return(TRUE)
        ));

    EXPECT_CALL(mock_api_wrapper, ReadFileWrapper(
        mock_pipe_rd, 
        _,
        PIPE_READ_BUFFER_SIZE,
        _, 
        NULL
    )).Times(1).WillOnce(DoAll(
        SaveArg<1>(&mock_buf),
        [&mock_buf]() { std::memset(mock_buf, 65, 100); }, // fill with "A"
        SetArgPointee<3>(50),
        Return(TRUE)
    ));

    EXPECT_CALL(mock_api_wrapper, PeekNamedPipeWrapper(mock_pipe_rd, NULL, 0, NULL, _, NULL))
        .Times(1).WillOnce(Return(FALSE));

    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(mock_proc_info.hProcess)).Times(1);
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(mock_proc_info.hThread)).Times(1);

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_mutex, MUTEX_WAIT_MS)).Times(1).WillOnce(Return(WAIT_OBJECT_0));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kExecutionLogFile), _)).Times(1);
    EXPECT_CALL(mock_api_wrapper, ReleaseMutexWrapper(h_dummy_mutex)).Times(1).WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(mock_pipe_wr)).Times(1);
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(mock_pipe_rd)).Times(1);
    
    std::vector<char> output = execute::ExecuteProcCommand(&mock_api_wrapper, mock_proc_binary, L"", L"", mock_timeout_seconds, &result);
    ASSERT_EQ(result, ERROR_SUCCESS);
    ASSERT_EQ(output.size(), 100);
    ASSERT_THAT(output, Each(65));
}

TEST_F(ExecuteTest, TestExecuteProcCommandSuccess) {
    InSequence s;
    LPVOID mock_buf;
    DWORD result;

    EXPECT_CALL(mock_api_wrapper, ConvertStringSecurityDescriptorToSecurityDescriptorWrapper(
        StrEq(L"D:(D;OICI;GA;;;BG)(D;OICI;GA;;;AN)(A;OICI;GRGWGX;;;AU)(A;OICI;GA;;;BA)"),
        SDDL_REVISION_1,
        _,
        NULL
    )).Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, CreatePipeWrapper(
        _,
        _,
        SecurityAttrStructEq(&mock_file_sa),
        0
    )).Times(1).WillOnce(DoAll(
        SetArgPointee<0>(mock_pipe_rd),
        SetArgPointee<1>(mock_pipe_wr),
        Return(TRUE)
    ));

    EXPECT_CALL(mock_api_wrapper, LocalFreeWrapper(_)).Times(1).WillOnce(Return(HLOCAL(NULL)));

    EXPECT_CALL(mock_api_wrapper, SetHandleInformationWrapper(mock_pipe_rd, HANDLE_FLAG_INHERIT, 0))
        .Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, CreateProcessWrapper(
        NULL,
        StrEq(expected_proc_command_line),
        NULL, 
        NULL,
        TRUE,
        CREATE_NO_WINDOW,
        NULL,
        NULL,
        StartupInfoStructEq(&mock_startup_info),
        _
    )).Times(1).WillOnce(DoAll(
        WithArg<9>(SetProcessInfoStruct(&mock_proc_info)), 
        Return(TRUE)
    ));

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_mutex, MUTEX_WAIT_MS)).Times(1).WillOnce(Return(WAIT_OBJECT_0));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kExecutionLogFile), _)).Times(1);
    EXPECT_CALL(mock_api_wrapper, ReleaseMutexWrapper(h_dummy_mutex)).Times(1).WillOnce(Return(TRUE));
    
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(
        mock_proc_info.hProcess,
        WAIT_CHUNK_MS
    )).Times(1).WillOnce(Return(WAIT_OBJECT_0));

    EXPECT_CALL(mock_api_wrapper, GetExitCodeProcessWrapper(
        mock_proc_info.hProcess,
        _
    )).Times(1).WillOnce(DoAll(SetArgPointee<1>(mock_exit_code), Return(TRUE)));

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_mutex, MUTEX_WAIT_MS)).Times(1).WillOnce(Return(WAIT_OBJECT_0));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kExecutionLogFile), _)).Times(1);
    EXPECT_CALL(mock_api_wrapper, ReleaseMutexWrapper(h_dummy_mutex)).Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, PeekNamedPipeWrapper(mock_pipe_rd, NULL, 0, NULL, _, NULL))
        .Times(1).WillOnce(DoAll(
            SetArgPointee<4>(100),
            Return(TRUE)
        ));

    EXPECT_CALL(mock_api_wrapper, ReadFileWrapper(
        mock_pipe_rd, 
        _,
        PIPE_READ_BUFFER_SIZE,
        _, 
        NULL
    )).Times(1).WillOnce(DoAll(
        SaveArg<1>(&mock_buf),
        [&mock_buf]() { std::memset(mock_buf, 65, 100); }, // fill with "A"
        SetArgPointee<3>(100),
        Return(TRUE)
    ));
    
    EXPECT_CALL(mock_api_wrapper, PeekNamedPipeWrapper(mock_pipe_rd, NULL, 0, NULL, _, NULL)).Times(1).WillOnce(Return(FALSE));

    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(mock_proc_info.hProcess)).Times(1);
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(mock_proc_info.hThread)).Times(1);

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_mutex, MUTEX_WAIT_MS)).Times(1).WillOnce(Return(WAIT_OBJECT_0));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kExecutionLogFile), _)).Times(1);
    EXPECT_CALL(mock_api_wrapper, ReleaseMutexWrapper(h_dummy_mutex)).Times(1).WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(mock_pipe_wr)).Times(1);
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(mock_pipe_rd)).Times(1);
    
    std::vector<char> output = execute::ExecuteProcCommand(&mock_api_wrapper, mock_proc_binary, mock_proc_args, L"", mock_timeout_seconds, &result);
    ASSERT_EQ(result, ERROR_SUCCESS);
    ASSERT_EQ(output.size(), 100);
    ASSERT_THAT(output, Each(65));
}

TEST_F(ExecuteTest, TestExecuteCmdDiffUserSuccessElevated) {
    InSequence s;
    LPVOID mock_buf;
    wchar_t* mock_name_buf;
    wchar_t* mock_domain_buf;
    DWORD result;
    LPVOID token_info_buf;

    EXPECT_CALL(mock_api_wrapper, ConvertStringSecurityDescriptorToSecurityDescriptorWrapper(
        StrEq(L"D:(D;OICI;GA;;;BG)(D;OICI;GA;;;AN)(A;OICI;GRGWGX;;;AU)(A;OICI;GA;;;BA)"),
        SDDL_REVISION_1,
        _,
        NULL
    )).Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, CreatePipeWrapper(
        _,
        _,
        SecurityAttrStructEq(&mock_file_sa),
        0
    )).Times(1).WillOnce(DoAll(
        SetArgPointee<0>(mock_pipe_rd),
        SetArgPointee<1>(mock_pipe_wr),
        Return(TRUE)
    ));

    EXPECT_CALL(mock_api_wrapper, LocalFreeWrapper(_)).Times(1).WillOnce(Return(HLOCAL(NULL)));

    EXPECT_CALL(mock_api_wrapper, SetHandleInformationWrapper(mock_pipe_rd, HANDLE_FLAG_INHERIT, 0))
        .Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, CreateToolhelp32SnapshotWrapper(TH32CS_SNAPPROCESS, 0))
        .Times(1).WillOnce(Return(mock_h_snapshot));

    // First process - not belonging to user
    EXPECT_CALL(mock_api_wrapper, Process32FirstWrapper(mock_h_snapshot, _))
        .Times(1).WillOnce(DoAll(
            WithArg<1>(SetProcessEntryStruct(&dummy_pe)),
            Return(TRUE)
        ));

    EXPECT_CALL(mock_api_wrapper, OpenProcessWrapper(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dummy_pid))
        .Times(1).WillOnce(Return(dummy_h_proc));

    EXPECT_CALL(mock_api_wrapper, OpenProcessTokenWrapper(dummy_h_proc, TOKEN_QUERY, _))
        .Times(1).WillOnce(DoAll(
            SetArgPointee<2>(dummy_h_proc_token),
            Return(TRUE)
        ));

    // BelongsToTargetUser
    EXPECT_CALL(mock_api_wrapper, GetTokenInformationWrapper(dummy_h_proc_token, TokenUser, NULL, 0, _))
        .Times(1).WillOnce(DoAll(
            SetArgPointee<4>(mock_info_size),
            Return(TRUE)
        ));

    EXPECT_CALL(mock_api_wrapper, GetTokenInformationWrapper(dummy_h_proc_token, TokenUser, _, mock_info_size, _))
        .Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, LookupAccountSidWrapper(
        NULL,
        _,
        _,
        _,
        _,
        _,
        _
    )).Times(1).WillOnce(DoAll(
        SaveArg<2>(&mock_name_buf),
        [&mock_name_buf]() { std::memcpy(mock_name_buf, dummy_proc_owner, sizeof(wchar_t) * (wcslen(dummy_proc_owner) + 1)); },
        SetArgPointee<3>(wcslen(dummy_proc_owner) + 1),
        SaveArg<4>(&mock_domain_buf),
        [&mock_domain_buf]() { std::memcpy(mock_domain_buf, dummy_domain, sizeof(wchar_t) * (wcslen(dummy_domain) + 1)); },
        SetArgPointee<5>(wcslen(dummy_domain) + 1),
        Return(TRUE)
    ));

    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(dummy_h_proc)).Times(1);
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(dummy_h_proc_token)).Times(1);

    // Second process - belongs to user, but non elev
    EXPECT_CALL(mock_api_wrapper, Process32NextWrapper(mock_h_snapshot, _))
        .Times(1).WillOnce(DoAll(
            WithArg<1>(SetProcessEntryStruct(&dummy_pe_target_nonelev)),
            Return(TRUE)
        ));

    EXPECT_CALL(mock_api_wrapper, OpenProcessWrapper(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dummy_pid_nonelev))
        .Times(1).WillOnce(Return(dummy_h_proc_nonelev));

    EXPECT_CALL(mock_api_wrapper, OpenProcessTokenWrapper(dummy_h_proc_nonelev, TOKEN_QUERY, _))
        .Times(1).WillOnce(DoAll(
            SetArgPointee<2>(dummy_h_proc_token_nonelev),
            Return(TRUE)
        ));

    // BelongsToTargetUser
    EXPECT_CALL(mock_api_wrapper, GetTokenInformationWrapper(dummy_h_proc_token_nonelev, TokenUser, NULL, 0, _))
        .Times(1).WillOnce(DoAll(
            SetArgPointee<4>(mock_info_size),
            Return(TRUE)
        ));

    EXPECT_CALL(mock_api_wrapper, GetTokenInformationWrapper(dummy_h_proc_token_nonelev, TokenUser, _, mock_info_size, _))
        .Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, LookupAccountSidWrapper(
        NULL,
        _,
        _,
        _,
        _,
        _,
        _
    )).Times(1).WillOnce(DoAll(
        SaveArg<2>(&mock_name_buf),
        [&mock_name_buf]() { std::memcpy(mock_name_buf, dummy_target_owner, sizeof(wchar_t) * (wcslen(dummy_target_owner) + 1)); },
        SetArgPointee<3>(wcslen(dummy_target_owner) + 1),
        SaveArg<4>(&mock_domain_buf),
        [&mock_domain_buf]() { std::memcpy(mock_domain_buf, dummy_domain, sizeof(wchar_t) * (wcslen(dummy_domain) + 1)); },
        SetArgPointee<5>(wcslen(dummy_domain) + 1),
        Return(TRUE)
    ));

    EXPECT_CALL(mock_api_wrapper, GetTokenInformationWrapper(dummy_h_proc_token_nonelev, TokenElevationType, _, sizeof(TOKEN_ELEVATION_TYPE), _))
        .Times(1).WillOnce(DoAll(
            SaveArg<2>(&token_info_buf),
            [&token_info_buf]() {
                TOKEN_ELEVATION_TYPE limited = TokenElevationTypeLimited;
                std::memcpy(token_info_buf, &limited, sizeof(TOKEN_ELEVATION_TYPE));
            },
            Return(TRUE)
        ));

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_mutex, MUTEX_WAIT_MS)).Times(1).WillOnce(Return(WAIT_OBJECT_0));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kExecutionLogFile), _)).Times(1);
    EXPECT_CALL(mock_api_wrapper, ReleaseMutexWrapper(h_dummy_mutex)).Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, OpenProcessTokenWrapper(dummy_h_proc_nonelev, TOKEN_QUERY | TOKEN_DUPLICATE, _))
        .Times(1).WillOnce(DoAll(
            SetArgPointee<2>(dummy_h_to_dup_nonelev),
            Return(TRUE)
        ));

    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(dummy_h_proc_nonelev)).Times(1);
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(dummy_h_proc_token_nonelev)).Times(1);

    // Third process - belongs to user, elevated
    EXPECT_CALL(mock_api_wrapper, Process32NextWrapper(mock_h_snapshot, _))
        .Times(1).WillOnce(DoAll(
            WithArg<1>(SetProcessEntryStruct(&dummy_pe_target_elev)),
            Return(TRUE)
        ));

    EXPECT_CALL(mock_api_wrapper, OpenProcessWrapper(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dummy_pid_elev))
        .Times(1).WillOnce(Return(dummy_h_proc_elev));

    EXPECT_CALL(mock_api_wrapper, OpenProcessTokenWrapper(dummy_h_proc_elev, TOKEN_QUERY, _))
        .Times(1).WillOnce(DoAll(
            SetArgPointee<2>(dummy_h_proc_token_elev),
            Return(TRUE)
        ));

    EXPECT_CALL(mock_api_wrapper, GetTokenInformationWrapper(dummy_h_proc_token_elev, TokenUser, NULL, 0, _))
        .Times(1).WillOnce(DoAll(
            SetArgPointee<4>(mock_info_size),
            Return(TRUE)
        ));

    EXPECT_CALL(mock_api_wrapper, GetTokenInformationWrapper(dummy_h_proc_token_elev, TokenUser, _, mock_info_size, _))
        .Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, LookupAccountSidWrapper(
        NULL,
        _,
        _,
        _,
        _,
        _,
        _
    )).Times(1).WillOnce(DoAll(
        SaveArg<2>(&mock_name_buf),
        [&mock_name_buf]() { std::memcpy(mock_name_buf, dummy_target_owner, sizeof(wchar_t) * (wcslen(dummy_target_owner) + 1)); },
        SetArgPointee<5>(wcslen(dummy_target_owner) + 1),
        SaveArg<4>(&mock_domain_buf),
        [&mock_domain_buf]() { std::memcpy(mock_domain_buf, dummy_domain, sizeof(wchar_t) * (wcslen(dummy_domain) + 1)); },
        SetArgPointee<5>(wcslen(dummy_domain) + 1),
        Return(TRUE)
    ));

    EXPECT_CALL(mock_api_wrapper, GetTokenInformationWrapper(dummy_h_proc_token_elev, TokenElevationType, _, sizeof(TOKEN_ELEVATION_TYPE), _))
        .Times(1).WillOnce(DoAll(
            SaveArg<2>(&token_info_buf),
            [&token_info_buf]() {
                TOKEN_ELEVATION_TYPE elevated = TokenElevationTypeFull;
                std::memcpy(token_info_buf, &elevated, sizeof(TOKEN_ELEVATION_TYPE));
            },
            Return(TRUE)
        ));


    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_mutex, MUTEX_WAIT_MS)).Times(1).WillOnce(Return(WAIT_OBJECT_0));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kExecutionLogFile), _)).Times(1);
    EXPECT_CALL(mock_api_wrapper, ReleaseMutexWrapper(h_dummy_mutex)).Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, OpenProcessTokenWrapper(dummy_h_proc_elev, TOKEN_QUERY | TOKEN_DUPLICATE, _))
        .Times(1).WillOnce(DoAll(
            SetArgPointee<2>(dummy_h_to_dup_elev),
            Return(TRUE)
        ));

    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(dummy_h_proc_elev)).Times(1);
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(dummy_h_proc_token_elev)).Times(1);
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(dummy_h_to_dup_nonelev)).Times(1);

    // Post-loop
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(mock_h_snapshot)).Times(1);

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_mutex, MUTEX_WAIT_MS)).Times(1).WillOnce(Return(WAIT_OBJECT_0));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kExecutionLogFile), _)).Times(1);
    EXPECT_CALL(mock_api_wrapper, ReleaseMutexWrapper(h_dummy_mutex)).Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, DuplicateTokenExWrapper(
        dummy_h_to_dup_elev, 
        MAXIMUM_ALLOWED, 
        NULL, 
        SecurityDelegation, 
        TokenPrimary, 
        _
    )).Times(1).WillOnce(DoAll(
        SetArgPointee<5>(dummy_h_duped_elev),
        Return(TRUE)
    ));

    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(dummy_h_to_dup_elev)).Times(1);
    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_mutex, MUTEX_WAIT_MS)).Times(1).WillOnce(Return(WAIT_OBJECT_0));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kExecutionLogFile), _)).Times(1);
    EXPECT_CALL(mock_api_wrapper, ReleaseMutexWrapper(h_dummy_mutex)).Times(1).WillOnce(Return(TRUE));

    // grant window station and desktop access for token
    EXPECT_CALL(mock_api_wrapper, GetTokenInformationWrapper(dummy_h_duped_elev, TokenUser, NULL, 0, _))
        .Times(1).WillOnce(DoAll(
            SetArgPointee<4>(mock_info_size),
            Return(TRUE)
        ));

    EXPECT_CALL(mock_api_wrapper, GetTokenInformationWrapper(dummy_h_duped_elev, TokenUser, _, mock_info_size, _))
        .Times(1).WillOnce(Return(TRUE));
    
    EXPECT_CALL(mock_api_wrapper, GetProcessWindowStationWrapper())
        .Times(1).WillOnce(Return(dummy_h_win_station));

    // GrantObjPermToSid
    EXPECT_CALL(mock_api_wrapper, GetUserObjectSecurityWrapper(dummy_h_win_station, _, NULL, 0, _))
        .Times(1).WillOnce(DoAll(
            SetArgPointee<4>(mock_info_size),
            Return(TRUE)
        ));
    EXPECT_CALL(mock_api_wrapper, GetUserObjectSecurityWrapper(dummy_h_win_station, _, _, mock_info_size, _))
        .Times(1).WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, GetSecurityDescriptorDaclWrapper(_ ,_, _, _)).Times(1).WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, SetEntriesInAclWrapper(
        1, 
        _, 
        _,
        _
    )).Times(1).WillOnce(Return(ERROR_SUCCESS));
    EXPECT_CALL(mock_api_wrapper, InitializeSecurityDescriptorWrapper(_, SECURITY_DESCRIPTOR_REVISION)).Times(1).WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, SetSecurityDescriptorDaclWrapper(_, TRUE, _, FALSE)).Times(1).WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, SetUserObjectSecurityWrapper(dummy_h_win_station, _, _)).Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, GetCurrentThreadIdWrapper()).Times(1).WillOnce(Return(dummy_thread_id));
    EXPECT_CALL(mock_api_wrapper, GetThreadDesktopWrapper(dummy_thread_id)).Times(1).WillOnce(Return(dummy_h_desktop));

    // GrantObjPermToSid
    EXPECT_CALL(mock_api_wrapper, GetUserObjectSecurityWrapper(dummy_h_desktop, _, NULL, 0, _))
        .Times(1).WillOnce(DoAll(
            SetArgPointee<4>(mock_info_size),
            Return(TRUE)
        ));
    EXPECT_CALL(mock_api_wrapper, GetUserObjectSecurityWrapper(dummy_h_desktop, _, _, mock_info_size, _))
        .Times(1).WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, GetSecurityDescriptorDaclWrapper(_ ,_, _, _)).Times(1).WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, SetEntriesInAclWrapper(
        1, 
        _, 
        _,
        _
    )).Times(1).WillOnce(Return(ERROR_SUCCESS));
    EXPECT_CALL(mock_api_wrapper, InitializeSecurityDescriptorWrapper(_, SECURITY_DESCRIPTOR_REVISION)).Times(1).WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, SetSecurityDescriptorDaclWrapper(_, TRUE, _, FALSE)).Times(1).WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, SetUserObjectSecurityWrapper(dummy_h_desktop, _, _)).Times(1).WillOnce(Return(TRUE));

    // CloseDesktopWrapper
    EXPECT_CALL(mock_api_wrapper, CloseDesktopWrapper(dummy_h_desktop)).Times(1);

    // Back in ExecuteProcess method
    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_mutex, MUTEX_WAIT_MS)).Times(1).WillOnce(Return(WAIT_OBJECT_0));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kExecutionLogFile), _)).Times(1);
    EXPECT_CALL(mock_api_wrapper, ReleaseMutexWrapper(h_dummy_mutex)).Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, CreateProcessWithTokenWrapper(
            dummy_h_duped_elev,
            0, // nologon flags
            NULL, // module name included in command line
            StrEq(expected_command_line),
            CREATE_NO_WINDOW, // dwCreationFlags
            NULL, // use specified user's environment
            NULL, // use current dir of calling process
            StartupInfoStructEq(&mock_startup_info_token),
            _
        )).Times(1).WillOnce(DoAll(
            WithArg<8>(SetProcessInfoStruct(&mock_proc_info)), 
            Return(TRUE)
        ));

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_mutex, MUTEX_WAIT_MS)).Times(1).WillOnce(Return(WAIT_OBJECT_0));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kExecutionLogFile), _)).Times(1);
    EXPECT_CALL(mock_api_wrapper, ReleaseMutexWrapper(h_dummy_mutex)).Times(1).WillOnce(Return(TRUE));
    
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(
        mock_proc_info.hProcess,
        WAIT_CHUNK_MS
    )).Times(1).WillOnce(Return(WAIT_OBJECT_0));

    EXPECT_CALL(mock_api_wrapper, GetExitCodeProcessWrapper(
        mock_proc_info.hProcess,
        _
    )).Times(1).WillOnce(DoAll(SetArgPointee<1>(mock_exit_code), Return(TRUE)));

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_mutex, MUTEX_WAIT_MS)).Times(1).WillOnce(Return(WAIT_OBJECT_0));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kExecutionLogFile), _)).Times(1);
    EXPECT_CALL(mock_api_wrapper, ReleaseMutexWrapper(h_dummy_mutex)).Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, PeekNamedPipeWrapper(mock_pipe_rd, NULL, 0, NULL, _, NULL))
        .Times(1).WillOnce(DoAll(
            SetArgPointee<4>(100),
            Return(TRUE)
        ));

    EXPECT_CALL(mock_api_wrapper, ReadFileWrapper(
        mock_pipe_rd, 
        _,
        PIPE_READ_BUFFER_SIZE,
        _, 
        NULL
    )).Times(1).WillOnce(DoAll(
        SaveArg<1>(&mock_buf),
        [&mock_buf]() { std::memset(mock_buf, 65, 100); }, // fill with "A"
        SetArgPointee<3>(100),
        Return(TRUE)
    ));

    EXPECT_CALL(mock_api_wrapper, PeekNamedPipeWrapper(mock_pipe_rd, NULL, 0, NULL, _, NULL))
        .Times(1).WillOnce(Return(FALSE));

    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(mock_proc_info.hProcess)).Times(1);
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(mock_proc_info.hThread)).Times(1);

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_mutex, MUTEX_WAIT_MS)).Times(1).WillOnce(Return(WAIT_OBJECT_0));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kExecutionLogFile), _)).Times(1);
    EXPECT_CALL(mock_api_wrapper, ReleaseMutexWrapper(h_dummy_mutex)).Times(1).WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(mock_pipe_wr)).Times(1);
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(mock_pipe_rd)).Times(1);
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(dummy_h_duped_elev)).Times(1);
    
    std::vector<char> output = execute::ExecuteCmdCommand(&mock_api_wrapper, mock_command, dummy_runas_user, mock_timeout_seconds, &result);
    ASSERT_EQ(result, ERROR_SUCCESS);
    ASSERT_EQ(output.size(), 100);
    ASSERT_THAT(output, Each(65));
}

TEST_F(ExecuteTest, TestExecuteCmdDiffUserSuccessElevatedFirst) {
    InSequence s;
    LPVOID mock_buf;
    wchar_t* mock_name_buf;
    wchar_t* mock_domain_buf;
    DWORD result;
    LPVOID token_info_buf;

    EXPECT_CALL(mock_api_wrapper, ConvertStringSecurityDescriptorToSecurityDescriptorWrapper(
        StrEq(L"D:(D;OICI;GA;;;BG)(D;OICI;GA;;;AN)(A;OICI;GRGWGX;;;AU)(A;OICI;GA;;;BA)"),
        SDDL_REVISION_1,
        _,
        NULL
    )).Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, CreatePipeWrapper(
        _,
        _,
        SecurityAttrStructEq(&mock_file_sa),
        0
    )).Times(1).WillOnce(DoAll(
        SetArgPointee<0>(mock_pipe_rd),
        SetArgPointee<1>(mock_pipe_wr),
        Return(TRUE)
    ));

    EXPECT_CALL(mock_api_wrapper, LocalFreeWrapper(_)).Times(1).WillOnce(Return(HLOCAL(NULL)));

    EXPECT_CALL(mock_api_wrapper, SetHandleInformationWrapper(mock_pipe_rd, HANDLE_FLAG_INHERIT, 0))
        .Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, CreateToolhelp32SnapshotWrapper(TH32CS_SNAPPROCESS, 0))
        .Times(1).WillOnce(Return(mock_h_snapshot));

    // First process - belonging to user and elevated
    EXPECT_CALL(mock_api_wrapper, Process32FirstWrapper(mock_h_snapshot, _))
        .Times(1).WillOnce(DoAll(
            WithArg<1>(SetProcessEntryStruct(&dummy_pe_target_elev)),
            Return(TRUE)
        ));

    EXPECT_CALL(mock_api_wrapper, OpenProcessWrapper(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dummy_pid_elev))
        .Times(1).WillOnce(Return(dummy_h_proc_elev));

    EXPECT_CALL(mock_api_wrapper, OpenProcessTokenWrapper(dummy_h_proc_elev, TOKEN_QUERY, _))
        .Times(1).WillOnce(DoAll(
            SetArgPointee<2>(dummy_h_proc_token_elev),
            Return(TRUE)
        ));

    // BelongsToTargetUser
    EXPECT_CALL(mock_api_wrapper, GetTokenInformationWrapper(dummy_h_proc_token_elev, TokenUser, NULL, 0, _))
        .Times(1).WillOnce(DoAll(
            SetArgPointee<4>(mock_info_size),
            Return(TRUE)
        ));

    EXPECT_CALL(mock_api_wrapper, GetTokenInformationWrapper(dummy_h_proc_token_elev, TokenUser, _, mock_info_size, _))
        .Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, LookupAccountSidWrapper(
        NULL,
        _,
        _,
        _,
        _,
        _,
        _
    )).Times(1).WillOnce(DoAll(
        SaveArg<2>(&mock_name_buf),
        [&mock_name_buf]() { std::memcpy(mock_name_buf, dummy_target_owner, sizeof(wchar_t) * (wcslen(dummy_target_owner) + 1)); },
        SetArgPointee<3>(wcslen(dummy_target_owner) + 1),
        SaveArg<4>(&mock_domain_buf),
        [&mock_domain_buf]() { std::memcpy(mock_domain_buf, dummy_domain, sizeof(wchar_t) * (wcslen(dummy_domain) + 1)); },
        SetArgPointee<5>(wcslen(dummy_domain) + 1),
        Return(TRUE)
    ));

    EXPECT_CALL(mock_api_wrapper, GetTokenInformationWrapper(dummy_h_proc_token_elev, TokenElevationType, _, sizeof(TOKEN_ELEVATION_TYPE), _))
        .Times(1).WillOnce(DoAll(
            SaveArg<2>(&token_info_buf),
            [&token_info_buf]() {
                TOKEN_ELEVATION_TYPE elevated = TokenElevationTypeFull;
                std::memcpy(token_info_buf, &elevated, sizeof(TOKEN_ELEVATION_TYPE));
            },
            Return(TRUE)
        ));


    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_mutex, MUTEX_WAIT_MS)).Times(1).WillOnce(Return(WAIT_OBJECT_0));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kExecutionLogFile), _)).Times(1);
    EXPECT_CALL(mock_api_wrapper, ReleaseMutexWrapper(h_dummy_mutex)).Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, OpenProcessTokenWrapper(dummy_h_proc_elev, TOKEN_QUERY | TOKEN_DUPLICATE, _))
        .Times(1).WillOnce(DoAll(
            SetArgPointee<2>(dummy_h_to_dup_elev),
            Return(TRUE)
        ));

    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(dummy_h_proc_elev)).Times(1);
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(dummy_h_proc_token_elev)).Times(1);

    // Post-loop
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(mock_h_snapshot)).Times(1);

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_mutex, MUTEX_WAIT_MS)).Times(1).WillOnce(Return(WAIT_OBJECT_0));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kExecutionLogFile), _)).Times(1);
    EXPECT_CALL(mock_api_wrapper, ReleaseMutexWrapper(h_dummy_mutex)).Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, DuplicateTokenExWrapper(
        dummy_h_to_dup_elev, 
        MAXIMUM_ALLOWED, 
        NULL, 
        SecurityDelegation, 
        TokenPrimary, 
        _
    )).Times(1).WillOnce(DoAll(
        SetArgPointee<5>(dummy_h_duped_elev),
        Return(TRUE)
    ));

    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(dummy_h_to_dup_elev)).Times(1);
    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_mutex, MUTEX_WAIT_MS)).Times(1).WillOnce(Return(WAIT_OBJECT_0));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kExecutionLogFile), _)).Times(1);
    EXPECT_CALL(mock_api_wrapper, ReleaseMutexWrapper(h_dummy_mutex)).Times(1).WillOnce(Return(TRUE));

    // grant window station and desktop access for token
    EXPECT_CALL(mock_api_wrapper, GetTokenInformationWrapper(dummy_h_duped_elev, TokenUser, NULL, 0, _))
        .Times(1).WillOnce(DoAll(
            SetArgPointee<4>(mock_info_size),
            Return(TRUE)
        ));

    EXPECT_CALL(mock_api_wrapper, GetTokenInformationWrapper(dummy_h_duped_elev, TokenUser, _, mock_info_size, _))
        .Times(1).WillOnce(Return(TRUE));
    
    EXPECT_CALL(mock_api_wrapper, GetProcessWindowStationWrapper())
        .Times(1).WillOnce(Return(dummy_h_win_station));

    // GrantObjPermToSid
    EXPECT_CALL(mock_api_wrapper, GetUserObjectSecurityWrapper(dummy_h_win_station, _, NULL, 0, _))
        .Times(1).WillOnce(DoAll(
            SetArgPointee<4>(mock_info_size),
            Return(TRUE)
        ));
    EXPECT_CALL(mock_api_wrapper, GetUserObjectSecurityWrapper(dummy_h_win_station, _, _, mock_info_size, _))
        .Times(1).WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, GetSecurityDescriptorDaclWrapper(_ ,_, _, _)).Times(1).WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, SetEntriesInAclWrapper(
        1, 
        _, 
        _,
        _
    )).Times(1).WillOnce(Return(ERROR_SUCCESS));
    EXPECT_CALL(mock_api_wrapper, InitializeSecurityDescriptorWrapper(_, SECURITY_DESCRIPTOR_REVISION)).Times(1).WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, SetSecurityDescriptorDaclWrapper(_, TRUE, _, FALSE)).Times(1).WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, SetUserObjectSecurityWrapper(dummy_h_win_station, _, _)).Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, GetCurrentThreadIdWrapper()).Times(1).WillOnce(Return(dummy_thread_id));
    EXPECT_CALL(mock_api_wrapper, GetThreadDesktopWrapper(dummy_thread_id)).Times(1).WillOnce(Return(dummy_h_desktop));

    // GrantObjPermToSid
    EXPECT_CALL(mock_api_wrapper, GetUserObjectSecurityWrapper(dummy_h_desktop, _, NULL, 0, _))
        .Times(1).WillOnce(DoAll(
            SetArgPointee<4>(mock_info_size),
            Return(TRUE)
        ));
    EXPECT_CALL(mock_api_wrapper, GetUserObjectSecurityWrapper(dummy_h_desktop, _, _, mock_info_size, _))
        .Times(1).WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, GetSecurityDescriptorDaclWrapper(_ ,_, _, _)).Times(1).WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, SetEntriesInAclWrapper(
        1, 
        _, 
        _,
        _
    )).Times(1).WillOnce(Return(ERROR_SUCCESS));
    EXPECT_CALL(mock_api_wrapper, InitializeSecurityDescriptorWrapper(_, SECURITY_DESCRIPTOR_REVISION)).Times(1).WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, SetSecurityDescriptorDaclWrapper(_, TRUE, _, FALSE)).Times(1).WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, SetUserObjectSecurityWrapper(dummy_h_desktop, _, _)).Times(1).WillOnce(Return(TRUE));

    // CloseDesktopWrapper
    EXPECT_CALL(mock_api_wrapper, CloseDesktopWrapper(dummy_h_desktop)).Times(1);

    // Back in ExecuteProcess method
    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_mutex, MUTEX_WAIT_MS)).Times(1).WillOnce(Return(WAIT_OBJECT_0));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kExecutionLogFile), _)).Times(1);
    EXPECT_CALL(mock_api_wrapper, ReleaseMutexWrapper(h_dummy_mutex)).Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, CreateProcessWithTokenWrapper(
            dummy_h_duped_elev,
            0, // nologon flags
            NULL, // module name included in command line
            StrEq(expected_command_line),
            CREATE_NO_WINDOW, // dwCreationFlags
            NULL, // use specified user's environment
            NULL, // use current dir of calling process
            StartupInfoStructEq(&mock_startup_info_token),
            _
        )).Times(1).WillOnce(DoAll(
            WithArg<8>(SetProcessInfoStruct(&mock_proc_info)), 
            Return(TRUE)
        ));

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_mutex, MUTEX_WAIT_MS)).Times(1).WillOnce(Return(WAIT_OBJECT_0));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kExecutionLogFile), _)).Times(1);
    EXPECT_CALL(mock_api_wrapper, ReleaseMutexWrapper(h_dummy_mutex)).Times(1).WillOnce(Return(TRUE));
    
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(
        mock_proc_info.hProcess,
        WAIT_CHUNK_MS
    )).Times(1).WillOnce(Return(WAIT_OBJECT_0));

    EXPECT_CALL(mock_api_wrapper, GetExitCodeProcessWrapper(
        mock_proc_info.hProcess,
        _
    )).Times(1).WillOnce(DoAll(SetArgPointee<1>(mock_exit_code), Return(TRUE)));

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_mutex, MUTEX_WAIT_MS)).Times(1).WillOnce(Return(WAIT_OBJECT_0));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kExecutionLogFile), _)).Times(1);
    EXPECT_CALL(mock_api_wrapper, ReleaseMutexWrapper(h_dummy_mutex)).Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, PeekNamedPipeWrapper(mock_pipe_rd, NULL, 0, NULL, _, NULL))
        .Times(1).WillOnce(DoAll(
            SetArgPointee<4>(100),
            Return(TRUE)
        ));

    EXPECT_CALL(mock_api_wrapper, ReadFileWrapper(
        mock_pipe_rd, 
        _,
        PIPE_READ_BUFFER_SIZE,
        _, 
        NULL
    )).Times(1).WillOnce(DoAll(
        SaveArg<1>(&mock_buf),
        [&mock_buf]() { std::memset(mock_buf, 65, 100); }, // fill with "A"
        SetArgPointee<3>(100),
        Return(TRUE)
    ));

    EXPECT_CALL(mock_api_wrapper, PeekNamedPipeWrapper(mock_pipe_rd, NULL, 0, NULL, _, NULL))
        .Times(1).WillOnce(Return(FALSE));

    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(mock_proc_info.hProcess)).Times(1);
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(mock_proc_info.hThread)).Times(1);

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_mutex, MUTEX_WAIT_MS)).Times(1).WillOnce(Return(WAIT_OBJECT_0));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kExecutionLogFile), _)).Times(1);
    EXPECT_CALL(mock_api_wrapper, ReleaseMutexWrapper(h_dummy_mutex)).Times(1).WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(mock_pipe_wr)).Times(1);
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(mock_pipe_rd)).Times(1);
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(dummy_h_duped_elev)).Times(1);
    
    std::vector<char> output = execute::ExecuteCmdCommand(&mock_api_wrapper, mock_command, dummy_runas_user, mock_timeout_seconds, &result);
    ASSERT_EQ(result, ERROR_SUCCESS);
    ASSERT_EQ(output.size(), 100);
    ASSERT_THAT(output, Each(65));
}

TEST_F(ExecuteTest, TestExecuteCmdDiffUserSuccessNonElev) {
    InSequence s;
    LPVOID mock_buf;
    wchar_t* mock_name_buf;
    wchar_t* mock_domain_buf;
    DWORD result;
    LPVOID token_info_buf;

    EXPECT_CALL(mock_api_wrapper, ConvertStringSecurityDescriptorToSecurityDescriptorWrapper(
        StrEq(L"D:(D;OICI;GA;;;BG)(D;OICI;GA;;;AN)(A;OICI;GRGWGX;;;AU)(A;OICI;GA;;;BA)"),
        SDDL_REVISION_1,
        _,
        NULL
    )).Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, CreatePipeWrapper(
        _,
        _,
        SecurityAttrStructEq(&mock_file_sa),
        0
    )).Times(1).WillOnce(DoAll(
        SetArgPointee<0>(mock_pipe_rd),
        SetArgPointee<1>(mock_pipe_wr),
        Return(TRUE)
    ));

    EXPECT_CALL(mock_api_wrapper, LocalFreeWrapper(_)).Times(1).WillOnce(Return(HLOCAL(NULL)));

    EXPECT_CALL(mock_api_wrapper, SetHandleInformationWrapper(mock_pipe_rd, HANDLE_FLAG_INHERIT, 0))
        .Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, CreateToolhelp32SnapshotWrapper(TH32CS_SNAPPROCESS, 0))
        .Times(1).WillOnce(Return(mock_h_snapshot));

    // First process - belongs to user, but non elev
    EXPECT_CALL(mock_api_wrapper, Process32FirstWrapper(mock_h_snapshot, _))
        .Times(1).WillOnce(DoAll(
            WithArg<1>(SetProcessEntryStruct(&dummy_pe_target_nonelev)),
            Return(TRUE)
        ));

    EXPECT_CALL(mock_api_wrapper, OpenProcessWrapper(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dummy_pid_nonelev))
        .Times(1).WillOnce(Return(dummy_h_proc_nonelev));

    EXPECT_CALL(mock_api_wrapper, OpenProcessTokenWrapper(dummy_h_proc_nonelev, TOKEN_QUERY, _))
        .Times(1).WillOnce(DoAll(
            SetArgPointee<2>(dummy_h_proc_token_nonelev),
            Return(TRUE)
        ));

    // BelongsToTargetUser
    EXPECT_CALL(mock_api_wrapper, GetTokenInformationWrapper(dummy_h_proc_token_nonelev, TokenUser, NULL, 0, _))
        .Times(1).WillOnce(DoAll(
            SetArgPointee<4>(mock_info_size),
            Return(TRUE)
        ));

    EXPECT_CALL(mock_api_wrapper, GetTokenInformationWrapper(dummy_h_proc_token_nonelev, TokenUser, _, mock_info_size, _))
        .Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, LookupAccountSidWrapper(
        NULL,
        _,
        _,
        _,
        _,
        _,
        _
    )).Times(1).WillOnce(DoAll(
        SaveArg<2>(&mock_name_buf),
        [&mock_name_buf]() { std::memcpy(mock_name_buf, dummy_target_owner, sizeof(wchar_t) * (wcslen(dummy_target_owner) + 1)); },
        SetArgPointee<3>(wcslen(dummy_target_owner) + 1),
        SaveArg<4>(&mock_domain_buf),
        [&mock_domain_buf]() { std::memcpy(mock_domain_buf, dummy_domain, sizeof(wchar_t) * (wcslen(dummy_domain) + 1)); },
        SetArgPointee<5>(wcslen(dummy_domain) + 1),
        Return(TRUE)
    ));

    EXPECT_CALL(mock_api_wrapper, GetTokenInformationWrapper(dummy_h_proc_token_nonelev, TokenElevationType, _, sizeof(TOKEN_ELEVATION_TYPE), _))
        .Times(1).WillOnce(DoAll(
            SaveArg<2>(&token_info_buf),
            [&token_info_buf]() {
                TOKEN_ELEVATION_TYPE limited = TokenElevationTypeLimited;
                std::memcpy(token_info_buf, &limited, sizeof(TOKEN_ELEVATION_TYPE));
            },
            Return(TRUE)
        ));

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_mutex, MUTEX_WAIT_MS)).Times(1).WillOnce(Return(WAIT_OBJECT_0));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kExecutionLogFile), _)).Times(1);
    EXPECT_CALL(mock_api_wrapper, ReleaseMutexWrapper(h_dummy_mutex)).Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, OpenProcessTokenWrapper(dummy_h_proc_nonelev, TOKEN_QUERY | TOKEN_DUPLICATE, _))
        .Times(1).WillOnce(DoAll(
            SetArgPointee<2>(dummy_h_to_dup_nonelev),
            Return(TRUE)
        ));

    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(dummy_h_proc_nonelev)).Times(1);
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(dummy_h_proc_token_nonelev)).Times(1);

    // Second process - not belonging to user
    EXPECT_CALL(mock_api_wrapper, Process32NextWrapper(mock_h_snapshot, _))
        .Times(1).WillOnce(DoAll(
            WithArg<1>(SetProcessEntryStruct(&dummy_pe)),
            Return(TRUE)
        ));

    EXPECT_CALL(mock_api_wrapper, OpenProcessWrapper(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dummy_pid))
        .Times(1).WillOnce(Return(dummy_h_proc));

    EXPECT_CALL(mock_api_wrapper, OpenProcessTokenWrapper(dummy_h_proc, TOKEN_QUERY, _))
        .Times(1).WillOnce(DoAll(
            SetArgPointee<2>(dummy_h_proc_token),
            Return(TRUE)
        ));

    // BelongsToTargetUser
    EXPECT_CALL(mock_api_wrapper, GetTokenInformationWrapper(dummy_h_proc_token, TokenUser, NULL, 0, _))
        .Times(1).WillOnce(DoAll(
            SetArgPointee<4>(mock_info_size),
            Return(TRUE)
        ));

    EXPECT_CALL(mock_api_wrapper, GetTokenInformationWrapper(dummy_h_proc_token, TokenUser, _, mock_info_size, _))
        .Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, LookupAccountSidWrapper(
        NULL,
        _,
        _,
        _,
        _,
        _,
        _
    )).Times(1).WillOnce(DoAll(
        SaveArg<2>(&mock_name_buf),
        [&mock_name_buf]() { std::memcpy(mock_name_buf, dummy_proc_owner, sizeof(wchar_t) * (wcslen(dummy_proc_owner) + 1)); },
        SetArgPointee<3>(wcslen(dummy_proc_owner) + 1),
        SaveArg<4>(&mock_domain_buf),
        [&mock_domain_buf]() { std::memcpy(mock_domain_buf, dummy_domain, sizeof(wchar_t) * (wcslen(dummy_domain) + 1)); },
        SetArgPointee<5>(wcslen(dummy_domain) + 1),
        Return(TRUE)
    ));

    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(dummy_h_proc)).Times(1);
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(dummy_h_proc_token)).Times(1);

    // End loop
    EXPECT_CALL(mock_api_wrapper, Process32NextWrapper(mock_h_snapshot, _))
        .Times(1).WillOnce(Return(FALSE));
    EXPECT_CALL(mock_api_wrapper, GetLastErrorWrapper()).Times(1).WillOnce(Return(ERROR_NO_MORE_FILES));

    // Post-loop
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(mock_h_snapshot)).Times(1);

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_mutex, MUTEX_WAIT_MS)).Times(1).WillOnce(Return(WAIT_OBJECT_0));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kExecutionLogFile), _)).Times(1);
    EXPECT_CALL(mock_api_wrapper, ReleaseMutexWrapper(h_dummy_mutex)).Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, DuplicateTokenExWrapper(
        dummy_h_to_dup_nonelev, 
        MAXIMUM_ALLOWED, 
        NULL, 
        SecurityDelegation, 
        TokenPrimary, 
        _
    )).Times(1).WillOnce(DoAll(
        SetArgPointee<5>(dummy_h_duped_nonelev),
        Return(TRUE)
    ));

    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(dummy_h_to_dup_nonelev)).Times(1);
    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_mutex, MUTEX_WAIT_MS)).Times(1).WillOnce(Return(WAIT_OBJECT_0));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kExecutionLogFile), _)).Times(1);
    EXPECT_CALL(mock_api_wrapper, ReleaseMutexWrapper(h_dummy_mutex)).Times(1).WillOnce(Return(TRUE));

    // grant window station and desktop access for token
    EXPECT_CALL(mock_api_wrapper, GetTokenInformationWrapper(dummy_h_duped_nonelev, TokenUser, NULL, 0, _))
        .Times(1).WillOnce(DoAll(
            SetArgPointee<4>(mock_info_size),
            Return(TRUE)
        ));

    EXPECT_CALL(mock_api_wrapper, GetTokenInformationWrapper(dummy_h_duped_nonelev, TokenUser, _, mock_info_size, _))
        .Times(1).WillOnce(Return(TRUE));
    
    EXPECT_CALL(mock_api_wrapper, GetProcessWindowStationWrapper())
        .Times(1).WillOnce(Return(dummy_h_win_station));

    // GrantObjPermToSid
    EXPECT_CALL(mock_api_wrapper, GetUserObjectSecurityWrapper(dummy_h_win_station, _, NULL, 0, _))
        .Times(1).WillOnce(DoAll(
            SetArgPointee<4>(mock_info_size),
            Return(TRUE)
        ));
    EXPECT_CALL(mock_api_wrapper, GetUserObjectSecurityWrapper(dummy_h_win_station, _, _, mock_info_size, _))
        .Times(1).WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, GetSecurityDescriptorDaclWrapper(_ ,_, _, _)).Times(1).WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, SetEntriesInAclWrapper(
        1, 
        _, 
        _,
        _
    )).Times(1).WillOnce(Return(ERROR_SUCCESS));
    EXPECT_CALL(mock_api_wrapper, InitializeSecurityDescriptorWrapper(_, SECURITY_DESCRIPTOR_REVISION)).Times(1).WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, SetSecurityDescriptorDaclWrapper(_, TRUE, _, FALSE)).Times(1).WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, SetUserObjectSecurityWrapper(dummy_h_win_station, _, _)).Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, GetCurrentThreadIdWrapper()).Times(1).WillOnce(Return(dummy_thread_id));
    EXPECT_CALL(mock_api_wrapper, GetThreadDesktopWrapper(dummy_thread_id)).Times(1).WillOnce(Return(dummy_h_desktop));

    // GrantObjPermToSid
    EXPECT_CALL(mock_api_wrapper, GetUserObjectSecurityWrapper(dummy_h_desktop, _, NULL, 0, _))
        .Times(1).WillOnce(DoAll(
            SetArgPointee<4>(mock_info_size),
            Return(TRUE)
        ));
    EXPECT_CALL(mock_api_wrapper, GetUserObjectSecurityWrapper(dummy_h_desktop, _, _, mock_info_size, _))
        .Times(1).WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, GetSecurityDescriptorDaclWrapper(_ ,_, _, _)).Times(1).WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, SetEntriesInAclWrapper(
        1, 
        _, 
        _,
        _
    )).Times(1).WillOnce(Return(ERROR_SUCCESS));
    EXPECT_CALL(mock_api_wrapper, InitializeSecurityDescriptorWrapper(_, SECURITY_DESCRIPTOR_REVISION)).Times(1).WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, SetSecurityDescriptorDaclWrapper(_, TRUE, _, FALSE)).Times(1).WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, SetUserObjectSecurityWrapper(dummy_h_desktop, _, _)).Times(1).WillOnce(Return(TRUE));

    // CloseDesktopWrapper
    EXPECT_CALL(mock_api_wrapper, CloseDesktopWrapper(dummy_h_desktop)).Times(1);

    // Back in ExecuteProcess method
    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_mutex, MUTEX_WAIT_MS)).Times(1).WillOnce(Return(WAIT_OBJECT_0));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kExecutionLogFile), _)).Times(1);
    EXPECT_CALL(mock_api_wrapper, ReleaseMutexWrapper(h_dummy_mutex)).Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, CreateProcessWithTokenWrapper(
            dummy_h_duped_nonelev,
            0, // nologon flags
            NULL, // module name included in command line
            StrEq(expected_command_line),
            CREATE_NO_WINDOW, // dwCreationFlags
            NULL, // use specified user's environment
            NULL, // use current dir of calling process
            StartupInfoStructEq(&mock_startup_info_token),
            _
        )).Times(1).WillOnce(DoAll(
            WithArg<8>(SetProcessInfoStruct(&mock_proc_info)), 
            Return(TRUE)
        ));

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_mutex, MUTEX_WAIT_MS)).Times(1).WillOnce(Return(WAIT_OBJECT_0));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kExecutionLogFile), _)).Times(1);
    EXPECT_CALL(mock_api_wrapper, ReleaseMutexWrapper(h_dummy_mutex)).Times(1).WillOnce(Return(TRUE));
    
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(
        mock_proc_info.hProcess,
        WAIT_CHUNK_MS
    )).Times(1).WillOnce(Return(WAIT_OBJECT_0));

    EXPECT_CALL(mock_api_wrapper, GetExitCodeProcessWrapper(
        mock_proc_info.hProcess,
        _
    )).Times(1).WillOnce(DoAll(SetArgPointee<1>(mock_exit_code), Return(TRUE)));

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_mutex, MUTEX_WAIT_MS)).Times(1).WillOnce(Return(WAIT_OBJECT_0));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kExecutionLogFile), _)).Times(1);
    EXPECT_CALL(mock_api_wrapper, ReleaseMutexWrapper(h_dummy_mutex)).Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, PeekNamedPipeWrapper(mock_pipe_rd, NULL, 0, NULL, _, NULL))
        .Times(1).WillOnce(DoAll(
            SetArgPointee<4>(100),
            Return(TRUE)
        ));

    EXPECT_CALL(mock_api_wrapper, ReadFileWrapper(
        mock_pipe_rd, 
        _,
        PIPE_READ_BUFFER_SIZE,
        _, 
        NULL
    )).Times(1).WillOnce(DoAll(
        SaveArg<1>(&mock_buf),
        [&mock_buf]() { std::memset(mock_buf, 65, 100); }, // fill with "A"
        SetArgPointee<3>(100),
        Return(TRUE)
    ));

    EXPECT_CALL(mock_api_wrapper, PeekNamedPipeWrapper(mock_pipe_rd, NULL, 0, NULL, _, NULL))
        .Times(1).WillOnce(Return(FALSE));

    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(mock_proc_info.hProcess)).Times(1);
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(mock_proc_info.hThread)).Times(1);

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_mutex, MUTEX_WAIT_MS)).Times(1).WillOnce(Return(WAIT_OBJECT_0));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kExecutionLogFile), _)).Times(1);
    EXPECT_CALL(mock_api_wrapper, ReleaseMutexWrapper(h_dummy_mutex)).Times(1).WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(mock_pipe_wr)).Times(1);
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(mock_pipe_rd)).Times(1);
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(dummy_h_duped_nonelev)).Times(1);
    
    std::vector<char> output = execute::ExecuteCmdCommand(&mock_api_wrapper, mock_command, dummy_runas_user, mock_timeout_seconds, &result);
    ASSERT_EQ(result, ERROR_SUCCESS);
    ASSERT_EQ(output.size(), 100);
    ASSERT_THAT(output, Each(65));
}

TEST_F(ExecuteTest, TestExecuteCmdDiffUserSuccessUserNotFound) {
    InSequence s;
    LPVOID mock_buf;
    wchar_t* mock_name_buf;
    wchar_t* mock_domain_buf;
    DWORD result;

    EXPECT_CALL(mock_api_wrapper, ConvertStringSecurityDescriptorToSecurityDescriptorWrapper(
        StrEq(L"D:(D;OICI;GA;;;BG)(D;OICI;GA;;;AN)(A;OICI;GRGWGX;;;AU)(A;OICI;GA;;;BA)"),
        SDDL_REVISION_1,
        _,
        NULL
    )).Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, CreatePipeWrapper(
        _,
        _,
        SecurityAttrStructEq(&mock_file_sa),
        0
    )).Times(1).WillOnce(DoAll(
        SetArgPointee<0>(mock_pipe_rd),
        SetArgPointee<1>(mock_pipe_wr),
        Return(TRUE)
    ));

    EXPECT_CALL(mock_api_wrapper, LocalFreeWrapper(_)).Times(1).WillOnce(Return(HLOCAL(NULL)));

    EXPECT_CALL(mock_api_wrapper, SetHandleInformationWrapper(mock_pipe_rd, HANDLE_FLAG_INHERIT, 0))
        .Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, CreateToolhelp32SnapshotWrapper(TH32CS_SNAPPROCESS, 0))
        .Times(1).WillOnce(Return(mock_h_snapshot));

    // First process - not belonging to user
    EXPECT_CALL(mock_api_wrapper, Process32FirstWrapper(mock_h_snapshot, _))
        .Times(1).WillOnce(DoAll(
            WithArg<1>(SetProcessEntryStruct(&dummy_pe)),
            Return(TRUE)
        ));

    EXPECT_CALL(mock_api_wrapper, OpenProcessWrapper(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dummy_pid))
        .Times(1).WillOnce(Return(dummy_h_proc));

    EXPECT_CALL(mock_api_wrapper, OpenProcessTokenWrapper(dummy_h_proc, TOKEN_QUERY, _))
        .Times(1).WillOnce(DoAll(
            SetArgPointee<2>(dummy_h_proc_token),
            Return(TRUE)
        ));

    // BelongsToTargetUser
    EXPECT_CALL(mock_api_wrapper, GetTokenInformationWrapper(dummy_h_proc_token, TokenUser, NULL, 0, _))
        .Times(1).WillOnce(DoAll(
            SetArgPointee<4>(mock_info_size),
            Return(TRUE)
        ));

    EXPECT_CALL(mock_api_wrapper, GetTokenInformationWrapper(dummy_h_proc_token, TokenUser, _, mock_info_size, _))
        .Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, LookupAccountSidWrapper(
        NULL,
        _,
        _,
        _,
        _,
        _,
        _
    )).Times(1).WillOnce(DoAll(
        SaveArg<2>(&mock_name_buf),
        [&mock_name_buf]() { std::memcpy(mock_name_buf, dummy_proc_owner, sizeof(wchar_t) * (wcslen(dummy_proc_owner) + 1)); },
        SetArgPointee<3>(wcslen(dummy_proc_owner) + 1),
        SaveArg<4>(&mock_domain_buf),
        [&mock_domain_buf]() { std::memcpy(mock_domain_buf, dummy_domain, sizeof(wchar_t) * (wcslen(dummy_domain) + 1)); },
        SetArgPointee<5>(wcslen(dummy_domain) + 1),
        Return(TRUE)
    ));

    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(dummy_h_proc)).Times(1);
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(dummy_h_proc_token)).Times(1);

    // End loop
    EXPECT_CALL(mock_api_wrapper, Process32NextWrapper(mock_h_snapshot, _))
        .Times(1).WillOnce(Return(FALSE));
    EXPECT_CALL(mock_api_wrapper, GetLastErrorWrapper()).Times(1).WillOnce(Return(ERROR_NO_MORE_FILES));

    // Post-loop
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(mock_h_snapshot)).Times(1);

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_mutex, MUTEX_WAIT_MS)).Times(1).WillOnce(Return(WAIT_OBJECT_0));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kExecutionLogFile), _)).Times(1);
    EXPECT_CALL(mock_api_wrapper, ReleaseMutexWrapper(h_dummy_mutex)).Times(1).WillOnce(Return(TRUE));

    // Back in ExecuteProcess method
    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_mutex, MUTEX_WAIT_MS)).Times(1).WillOnce(Return(WAIT_OBJECT_0));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kExecutionLogFile), _)).Times(1);
    EXPECT_CALL(mock_api_wrapper, ReleaseMutexWrapper(h_dummy_mutex)).Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, CreateProcessWrapper(
        NULL,
        StrEq(expected_command_line),
        NULL, 
        NULL,
        TRUE,
        CREATE_NO_WINDOW,
        NULL,
        NULL,
        StartupInfoStructEq(&mock_startup_info),
        _
    )).Times(1).WillOnce(DoAll(
        WithArg<9>(SetProcessInfoStruct(&mock_proc_info)), 
        Return(TRUE)
    ));

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_mutex, MUTEX_WAIT_MS)).Times(1).WillOnce(Return(WAIT_OBJECT_0));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kExecutionLogFile), _)).Times(1);
    EXPECT_CALL(mock_api_wrapper, ReleaseMutexWrapper(h_dummy_mutex)).Times(1).WillOnce(Return(TRUE));
    
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(
        mock_proc_info.hProcess,
        WAIT_CHUNK_MS
    )).Times(1).WillOnce(Return(WAIT_OBJECT_0));

    EXPECT_CALL(mock_api_wrapper, GetExitCodeProcessWrapper(
        mock_proc_info.hProcess,
        _
    )).Times(1).WillOnce(DoAll(SetArgPointee<1>(mock_exit_code), Return(TRUE)));

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_mutex, MUTEX_WAIT_MS)).Times(1).WillOnce(Return(WAIT_OBJECT_0));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kExecutionLogFile), _)).Times(1);
    EXPECT_CALL(mock_api_wrapper, ReleaseMutexWrapper(h_dummy_mutex)).Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, PeekNamedPipeWrapper(mock_pipe_rd, NULL, 0, NULL, _, NULL))
        .Times(1).WillOnce(DoAll(
            SetArgPointee<4>(100),
            Return(TRUE)
        ));

    EXPECT_CALL(mock_api_wrapper, ReadFileWrapper(
        mock_pipe_rd, 
        _,
        PIPE_READ_BUFFER_SIZE,
        _, 
        NULL
    )).Times(1).WillOnce(DoAll(
        SaveArg<1>(&mock_buf),
        [&mock_buf]() { std::memset(mock_buf, 65, 100); }, // fill with "A"
        SetArgPointee<3>(100),
        Return(TRUE)
    ));

    EXPECT_CALL(mock_api_wrapper, PeekNamedPipeWrapper(mock_pipe_rd, NULL, 0, NULL, _, NULL))
        .Times(1).WillOnce(Return(FALSE));

    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(mock_proc_info.hProcess)).Times(1);
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(mock_proc_info.hThread)).Times(1);

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_mutex, MUTEX_WAIT_MS)).Times(1).WillOnce(Return(WAIT_OBJECT_0));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kExecutionLogFile), _)).Times(1);
    EXPECT_CALL(mock_api_wrapper, ReleaseMutexWrapper(h_dummy_mutex)).Times(1).WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(mock_pipe_wr)).Times(1);
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(mock_pipe_rd)).Times(1);
    
    std::vector<char> output = execute::ExecuteCmdCommand(&mock_api_wrapper, mock_command, dummy_runas_user, mock_timeout_seconds, &result);
    ASSERT_EQ(result, ERROR_SUCCESS);
    ASSERT_EQ(output.size(), 100);
    ASSERT_THAT(output, Each(65));
}