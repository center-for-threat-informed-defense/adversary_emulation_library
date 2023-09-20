#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <windows.h>
#include <cstring>
#include "core.h"
#include "util.h"
#include "test_util.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::SetArgPointee;
using ::testing::StrEq;


// Text fixture for shared data
class CoreTest : public ::testing::Test {
protected:
    MockApiWrapper mock_api_wrapper;

    std::string mock_timestamp = "2000-12-01 12:34:56";
    static constexpr const wchar_t* mock_chrome_path = L"C:\\dummy path\\chrome.exe";
    static constexpr const wchar_t* mock_firefox_path = L"firefox.exe";
    static constexpr const wchar_t* mock_edge_path = L"C:\\dummy\\path\\MSEDGE.exe";
    static constexpr const wchar_t* mock_iexplorer_path = L"C:\\dummy\\path\\iexplore.exe";
    static constexpr const wchar_t* mock_nonbrowser_path = L"C:\\dummy\\path\\notabrowser.exe";
    static constexpr const wchar_t* mock_computer_name = L"MYWORKSTATION";
    static constexpr const wchar_t* mock_computer_name_short = L"WS10";

    std::wstring dummy_payload_dest_path_no_dir = L"thiswillgotosnakehomedir";
    std::wstring dummy_payload_dest_path = L"C:\\some\\dummy\\payload\\path";

    HANDLE h_mock_output_file = HANDLE(10121);
};

MATCHER_P2(BufferContentEq, target, length, "") {
    return (memcmp(arg, target, length) == 0);
}

TEST_F(CoreTest, TestGetModuleModeAndSetUserAgentChrome) {
    DWORD mode;
    LPVOID mock_buf;

    EXPECT_CALL(mock_api_wrapper, GetModuleFileNameWrapper(NULL, _, MAX_PATH))
        .Times(1)
        .WillOnce(DoAll(
            SaveArg<1>(&mock_buf),
            Invoke([&mock_buf]() { std::memcpy(mock_buf, mock_chrome_path, sizeof(wchar_t) * (wcslen(mock_chrome_path) + 1)); }),
            Return(wcslen(mock_chrome_path))
        ));

    ASSERT_EQ(module_core::GetModuleModeAndSetUserAgent(&mock_api_wrapper, &mode), ERROR_SUCCESS);
    EXPECT_EQ(mode, COMMS_MODE);
    EXPECT_THAT(comms_http::user_agent, StrEq(CHROME_WIN10_USER_AGENT));
}

TEST_F(CoreTest, TestGetModuleModeAndSetUserAgentFirefox) {
    DWORD mode;
    LPVOID mock_buf;

    EXPECT_CALL(mock_api_wrapper, GetModuleFileNameWrapper(NULL, _, MAX_PATH))
        .Times(1)
        .WillOnce(DoAll(
            SaveArg<1>(&mock_buf),
            Invoke([&mock_buf]() { std::memcpy(mock_buf, mock_firefox_path, sizeof(wchar_t) * (wcslen(mock_firefox_path) + 1)); }),
            Return(wcslen(mock_firefox_path))
        ));

    ASSERT_EQ(module_core::GetModuleModeAndSetUserAgent(&mock_api_wrapper, &mode), ERROR_SUCCESS);
    EXPECT_EQ(mode, COMMS_MODE);
    EXPECT_THAT(comms_http::user_agent, StrEq(FIREFOX_WIN10_USER_AGENT));
}

TEST_F(CoreTest, TestGetModuleModeAndSetUserAgentEdge) {
    DWORD mode;
    LPVOID mock_buf;

    EXPECT_CALL(mock_api_wrapper, GetModuleFileNameWrapper(NULL, _, MAX_PATH))
        .Times(1)
        .WillOnce(DoAll(
            SaveArg<1>(&mock_buf),
            Invoke([&mock_buf]() { std::memcpy(mock_buf, mock_edge_path, sizeof(wchar_t) * (wcslen(mock_edge_path) + 1)); }),
            Return(wcslen(mock_edge_path))
        ));

    ASSERT_EQ(module_core::GetModuleModeAndSetUserAgent(&mock_api_wrapper, &mode), ERROR_SUCCESS);
    EXPECT_EQ(mode, COMMS_MODE);
    EXPECT_THAT(comms_http::user_agent, StrEq(EDGE_WIN10_USER_AGENT));
}

TEST_F(CoreTest, TestGetModuleModeAndSetUserAgentIexplorer) {
    DWORD mode;
    LPVOID mock_buf;

    EXPECT_CALL(mock_api_wrapper, GetModuleFileNameWrapper(NULL, _, MAX_PATH))
        .Times(1)
        .WillOnce(DoAll(
            SaveArg<1>(&mock_buf),
            Invoke([&mock_buf]() { std::memcpy(mock_buf, mock_iexplorer_path, sizeof(wchar_t) * (wcslen(mock_iexplorer_path) + 1)); }),
            Return(wcslen(mock_iexplorer_path))
        ));

    ASSERT_EQ(module_core::GetModuleModeAndSetUserAgent(&mock_api_wrapper, &mode), ERROR_SUCCESS);
    EXPECT_EQ(mode, COMMS_MODE);
    EXPECT_THAT(comms_http::user_agent, StrEq(IE_WIN10_USER_AGENT));
}

TEST_F(CoreTest, TestGetModuleModeAndSetUserAgentExecution) {
    DWORD mode;
    LPVOID mock_buf;

    EXPECT_CALL(mock_api_wrapper, GetModuleFileNameWrapper(NULL, _, MAX_PATH))
        .Times(1)
        .WillOnce(DoAll(
            SaveArg<1>(&mock_buf),
            Invoke([&mock_buf]() { std::memcpy(mock_buf, mock_nonbrowser_path, sizeof(wchar_t) * (wcslen(mock_nonbrowser_path) + 1)); }),
            Return(wcslen(mock_nonbrowser_path))
        ));

    ASSERT_EQ(module_core::GetModuleModeAndSetUserAgent(&mock_api_wrapper, &mode), ERROR_SUCCESS);
    EXPECT_EQ(mode, EXECUTION_MODE);
    EXPECT_THAT(comms_http::user_agent, StrEq(DEFAULT_USER_AGENT));
}

TEST_F(CoreTest, TestSetImplantIdSuccess) {
    LPVOID mock_buf;

    EXPECT_CALL(mock_api_wrapper, GetComputerNameWrapper(_, _))
        .Times(1)
        .WillOnce(DoAll(
            SaveArg<0>(&mock_buf),
            Invoke([&mock_buf]() { std::memcpy(mock_buf, mock_computer_name, sizeof(wchar_t) * (wcslen(mock_computer_name) + 1)); }),
            SetArgPointee<1>(wcslen(mock_computer_name)),
            Return(TRUE)
        ));

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(2).WillRepeatedly(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kC2LogFile), _)).Times(2);

    module_core::SetImplantId(&mock_api_wrapper);
    EXPECT_THAT(module_core::module_implant_id, StrEq(L"7f686278637b6b607365"));
}

TEST_F(CoreTest, TestSetImplantIdSuccessShort) {
    LPVOID mock_buf;

    EXPECT_CALL(mock_api_wrapper, GetComputerNameWrapper(_, _))
        .Times(1)
        .WillOnce(DoAll(
            SaveArg<0>(&mock_buf),
            Invoke([&mock_buf]() { std::memcpy(mock_buf, mock_computer_name_short, sizeof(wchar_t) * (wcslen(mock_computer_name_short) + 1)); }),
            SetArgPointee<1>(wcslen(mock_computer_name_short)),
            Return(TRUE)
        ));

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(2).WillRepeatedly(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kC2LogFile), _)).Times(2);

    module_core::SetImplantId(&mock_api_wrapper);
    EXPECT_THAT(module_core::module_implant_id, StrEq(L"65620407666309046562"));
}

TEST_F(CoreTest, TestSetImplantIdFail) {
    LPVOID mock_buf;

    EXPECT_CALL(mock_api_wrapper, GetComputerNameWrapper(_, _))
        .Times(1)
        .WillOnce(Return(FALSE));

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kC2LogFile), _)).Times(1);

    module_core::SetImplantId(&mock_api_wrapper);
    EXPECT_THAT(module_core::module_implant_id, StrEq(util::ConvertStringToWstring(module_core::kImplantIdBase)));
}

TEST_F(CoreTest, TestSavePayloadFromPipeMsgSnakeHomeDir) {
    const char mock_pipe_payload_resp_data[56] = {
        0x28,0x00,0x00,0x00,
        0x43,0x3a,0x5c,0x55,0x73,0x65,0x72,0x73,0x5c,0x50,0x75,0x62,0x6c,0x69,0x63,0x5c,0x74,0x68,0x69,0x73,0x77,0x69,0x6c,0x6c,0x67,0x6f,0x74,0x6f,0x73,0x6e,0x61,0x6b,0x65,0x68,0x6f,0x6d,0x65,0x64,0x69,0x72, // C:\Users\Public\thiswillgotosnakehomedir
        0x65,0x65,0x65,0x65,0x65,0x65,0x65,0x65,0x65,0x65,0x65,0x65
    };
    const char payload_data[12] = {
        0x65,0x65,0x65,0x65,0x65,0x65,0x65,0x65,0x65,0x65,0x65,0x65
    };

    EXPECT_CALL(mock_api_wrapper, CreateFileWrapper(
        StrEq(std::wstring(HOME_DIRECTORY) + L"\\" + dummy_payload_dest_path_no_dir),
        GENERIC_WRITE,
        FILE_SHARE_WRITE,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    )).Times(1).WillOnce(Return(h_mock_output_file));

    EXPECT_CALL(mock_api_wrapper, WriteFileWrapper(
        h_mock_output_file, 
        BufferContentEq(payload_data, sizeof(payload_data)),
        sizeof(payload_data),
        _, 
        NULL
    )).Times(1).WillOnce(DoAll(
        SetArgPointee<3>(sizeof(payload_data)),
        Return(TRUE)
    ));
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(h_mock_output_file)).Times(1);

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillRepeatedly(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kExecutionLogFile), _)).Times(1);

    module_core::SavePayloadFromPipeMsg(&mock_api_wrapper, std::vector<char>(mock_pipe_payload_resp_data, mock_pipe_payload_resp_data + sizeof(mock_pipe_payload_resp_data)));
}