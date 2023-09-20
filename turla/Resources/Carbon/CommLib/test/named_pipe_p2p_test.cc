#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "NamedPipeP2p.hpp"
#include "testing.h"
#include <string>
#include <cstring>
#include <vector>

using ::testing::_;
using ::testing::AtLeast;
using ::testing::DoAll;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::SetArgPointee;


// Test fixture for shared data
class CommsPipeTest : public ::testing::Test {
protected:
    MockWinApiWrapper mock_api_wrapper;

    HANDLE mock_h_pipe = HANDLE(1234);
    std::string mock_client_id = "P2PCLIENT";
    std::string mock_response_pipe = "\\\\hostname\\pipe\\dummypipename";
    LPCWSTR mock_pipe = L"\\\\hostname\\pipe\\dummypipename";
    static constexpr const size_t mock_pipe_beacon_request_bytes_len = 50;
    static constexpr const char mock_pipe_beacon_request_bytes[50] = {
        0x01,0x00,0x00,0x00, // beacon request, little endian
        0x09,0x00,0x00,0x00, // client ID length
        0x50,0x32,0x50,0x43,0x4c,0x49,0x45,0x4e,0x54, // client ID
        0x1D,0x00,0x00,0x00, // response pipe length
        0x5c,0x5c,0x68,0x6f,0x73,0x74,0x6e,0x61,0x6d,0x65,0x5c,0x70,0x69,0x70,0x65,0x5c,0x64,0x75,0x6d,0x6d,0x79,0x70,0x69,0x70,0x65,0x6e,0x61,0x6d,0x65
    };

    std::string dummy_beacon_resp_data_str = "eeeeeeeeeee";
    static constexpr const size_t mock_pipe_beacon_resp_bytes_len = 23;
    static constexpr const char mock_pipe_beacon_resp_bytes[23] = {
        0x02,0x00,0x00,0x00, // beacon response, little endian
        0x00,0x00,0x00,0x00, // client ID length
        0x00,0x00,0x00,0x00, // response pipe length
        0x65,0x65,0x65,0x65,0x65,0x65,0x65,0x65,0x65,0x65,0x65
    };

    std::string dummy_beacon_task_output_str = "abcdefghij";
    static constexpr const size_t mock_pipe_task_output_bytes_len = 60;
    static constexpr const char mock_pipe_task_output_bytes[60] = {
        0x03,0x00,0x00,0x00, // task output, little endian
        0x09,0x00,0x00,0x00, // client ID length
        0x50,0x32,0x50,0x43,0x4c,0x49,0x45,0x4e,0x54, // client ID
        0x1D,0x00,0x00,0x00, // response pipe length
        0x5c,0x5c,0x68,0x6f,0x73,0x74,0x6e,0x61,0x6d,0x65,0x5c,0x70,0x69,0x70,0x65,0x5c,0x64,0x75,0x6d,0x6d,0x79,0x70,0x69,0x70,0x65,0x6e,0x61,0x6d,0x65,
        0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6a
    };

    static constexpr const size_t mock_pipe_task_output_resp_bytes_len = 23;
    static constexpr const char mock_pipe_task_output_resp_bytes[23] = {
        0x04,0x00,0x00,0x00, // task output response, little endian
        0x00,0x00,0x00,0x00, // client ID length
        0x00,0x00,0x00,0x00, // response pipe length
        0x65,0x65,0x65,0x65,0x65,0x65,0x65,0x65,0x65,0x65,0x65
    };

    comms_pipe::PipeMessage dummy_beacon_req_msg = comms_pipe::PipeMessage();
    comms_pipe::PipeMessage dummy_beacon_resp_msg = comms_pipe::PipeMessage();
    comms_pipe::PipeMessage dummy_task_output_msg = comms_pipe::PipeMessage();
    comms_pipe::PipeMessage dummy_task_output_resp_msg = comms_pipe::PipeMessage();

    void SetUp() override {
        dummy_beacon_req_msg.message_type = PIPE_MSG_BEACON;
        dummy_beacon_req_msg.client_id_len = (int32_t)mock_client_id.length();
        dummy_beacon_req_msg.client_id = mock_client_id;
        dummy_beacon_req_msg.response_pipe_path_len = (int32_t)mock_response_pipe.length();
        dummy_beacon_req_msg.response_pipe_path = mock_response_pipe;
        dummy_beacon_req_msg.data = std::vector<char>();

        dummy_beacon_resp_msg.message_type = PIPE_MSG_BEACON_RESP;
        dummy_beacon_resp_msg.client_id_len = 0;
        dummy_beacon_resp_msg.client_id = "";
        dummy_beacon_resp_msg.response_pipe_path_len = 0;
        dummy_beacon_resp_msg.response_pipe_path = "";
        dummy_beacon_resp_msg.data = std::vector<char>(dummy_beacon_resp_data_str.begin(), dummy_beacon_resp_data_str.end());

        dummy_task_output_msg.message_type = PIPE_MSG_TASK_OUTPUT;
        dummy_task_output_msg.client_id_len = (int32_t)mock_client_id.length();
        dummy_task_output_msg.client_id = mock_client_id;
        dummy_task_output_msg.response_pipe_path_len = (int32_t)mock_response_pipe.length();
        dummy_task_output_msg.response_pipe_path = mock_response_pipe;
        dummy_task_output_msg.data = std::vector<char>(dummy_beacon_task_output_str.begin(), dummy_beacon_task_output_str.end());

        dummy_task_output_resp_msg.message_type = PIPE_MSG_TASK_OUTPUT_RESP;
        dummy_task_output_resp_msg.client_id_len = 0;
        dummy_task_output_resp_msg.client_id = "";
        dummy_task_output_resp_msg.response_pipe_path_len = 0;
        dummy_task_output_resp_msg.response_pipe_path = "";
        dummy_task_output_resp_msg.data = std::vector<char>(dummy_beacon_resp_data_str.begin(), dummy_beacon_resp_data_str.end());
    }
};

// Define our own matching logic to compare PipeMessage structs
MATCHER_P(PipeMsgEq, pTarget, "") {
    return (pTarget->message_type == arg->message_type) &&
        (pTarget->data == arg->data) &&
        (pTarget->client_id_len == arg->client_id_len) &&
        (pTarget->client_id.compare(arg->client_id) == 0) && 
        (pTarget->response_pipe_path_len == arg->response_pipe_path_len) &&
        (pTarget->response_pipe_path.compare(arg->response_pipe_path) == 0);
}

MATCHER_P2(BufferContentEq, target, length, "") {
    return (memcmp(arg, target, length) == 0);
}

TEST_F(CommsPipeTest, TestGetPipeMsgSuccessBeaconReq) {
    LPVOID mock_buf;

    // Catch all logging messages
    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).WillRepeatedly(Return(""));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(_, _)).Times(AtLeast(0));

    EXPECT_CALL(mock_api_wrapper, ReadFileWrapper(
        mock_h_pipe,
        _,
        PIPE_OUT_BUFFER,
        _,
        NULL
    )).Times(2)
        .WillOnce(DoAll(
            SaveArg<1>(&mock_buf),
            Invoke([&mock_buf]() { std::memcpy(mock_buf, mock_pipe_beacon_request_bytes, mock_pipe_beacon_request_bytes_len); }),
            SetArgPointee<3>(mock_pipe_beacon_request_bytes_len),
            Return(TRUE)))
        .WillOnce(DoAll(
            SetArgPointee<3>(0),
            Return(FALSE)));

    EXPECT_CALL(mock_api_wrapper, GetLastErrorWrapper())
        .Times(1)
        .WillOnce(Return(ERROR_BROKEN_PIPE));

    comms_pipe::PipeMessage pipe_msg = comms_pipe::PipeMessage();
    ASSERT_EQ(comms_pipe::GetPipeMsg(&mock_api_wrapper, mock_h_pipe, &pipe_msg, FALSE), ERROR_SUCCESS);
    EXPECT_THAT(&pipe_msg, PipeMsgEq(&dummy_beacon_req_msg));
}

TEST_F(CommsPipeTest, TestGetPipeMsgSuccessBeaconResp) {
    LPVOID mock_buf;

    // Catch all logging messages
    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).WillRepeatedly(Return(""));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(_, _)).Times(AtLeast(0));

    EXPECT_CALL(mock_api_wrapper, ReadFileWrapper(
        mock_h_pipe,
        _,
        PIPE_OUT_BUFFER,
        _,
        NULL
    )).Times(2)
        .WillOnce(DoAll(
            SaveArg<1>(&mock_buf),
            Invoke([&mock_buf]() { std::memcpy(mock_buf, mock_pipe_beacon_resp_bytes, mock_pipe_beacon_resp_bytes_len); }),
            SetArgPointee<3>(mock_pipe_beacon_resp_bytes_len),
            Return(TRUE)))
        .WillOnce(DoAll(
            SetArgPointee<3>(0),
            Return(FALSE)));

    EXPECT_CALL(mock_api_wrapper, GetLastErrorWrapper())
        .Times(1)
        .WillOnce(Return(ERROR_BROKEN_PIPE));

    comms_pipe::PipeMessage pipe_msg = comms_pipe::PipeMessage();
    ASSERT_EQ(comms_pipe::GetPipeMsg(&mock_api_wrapper, mock_h_pipe, &pipe_msg, FALSE), ERROR_SUCCESS);
    EXPECT_THAT(&pipe_msg, PipeMsgEq(&dummy_beacon_resp_msg));
}

TEST_F(CommsPipeTest, TestGetPipeMsgSuccessTaskOutput) {
    LPVOID mock_buf;

    // Catch all logging messages
    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).WillRepeatedly(Return(""));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(_, _)).Times(AtLeast(0));

    EXPECT_CALL(mock_api_wrapper, ReadFileWrapper(
        mock_h_pipe,
        _,
        PIPE_OUT_BUFFER,
        _,
        NULL
    )).Times(2)
        .WillOnce(DoAll(
            SaveArg<1>(&mock_buf),
            Invoke([&mock_buf]() { std::memcpy(mock_buf, mock_pipe_task_output_bytes, mock_pipe_task_output_bytes_len); }),
            SetArgPointee<3>(mock_pipe_task_output_bytes_len),
            Return(TRUE)))
        .WillOnce(DoAll(
            SetArgPointee<3>(0),
            Return(FALSE)));

    EXPECT_CALL(mock_api_wrapper, GetLastErrorWrapper())
        .Times(1)
        .WillOnce(Return(ERROR_BROKEN_PIPE));

    comms_pipe::PipeMessage pipe_msg = comms_pipe::PipeMessage();
    ASSERT_EQ(comms_pipe::GetPipeMsg(&mock_api_wrapper, mock_h_pipe, &pipe_msg, FALSE), ERROR_SUCCESS);
    EXPECT_THAT(&pipe_msg, PipeMsgEq(&dummy_task_output_msg));
}

TEST_F(CommsPipeTest, TestSendBeaconReq) {
    // Catch all logging messages
    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).WillRepeatedly(Return(""));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(_, _)).Times(AtLeast(0));

    EXPECT_CALL(mock_api_wrapper, CreateFileWrapper(
        mock_pipe,
        GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    )).Times(1).WillOnce(Return(mock_h_pipe));
    EXPECT_CALL(mock_api_wrapper, WriteFileWrapper(
        mock_h_pipe,
        BufferContentEq(mock_pipe_beacon_request_bytes, mock_pipe_beacon_request_bytes_len),
        mock_pipe_beacon_request_bytes_len,
        _,
        NULL
    )).Times(1)
        .WillOnce(DoAll(
            SetArgPointee<3>(mock_pipe_beacon_request_bytes_len),
            Return(TRUE)));

    EXPECT_CALL(mock_api_wrapper, FlushFileBuffersWrapper(mock_h_pipe))
        .Times(1)
        .WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(mock_h_pipe)).Times(1);

    ASSERT_EQ(comms_pipe::SendBeaconRequest(&mock_api_wrapper, mock_pipe, mock_client_id, mock_response_pipe, FALSE), ERROR_SUCCESS);
}

TEST_F(CommsPipeTest, TestSendBeaconResp) {
    // Catch all logging messages
    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).WillRepeatedly(Return(""));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(_, _)).Times(AtLeast(0));

    EXPECT_CALL(mock_api_wrapper, CreateFileWrapper(
        mock_pipe,
        GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    )).Times(1).WillOnce(Return(mock_h_pipe));
    EXPECT_CALL(mock_api_wrapper, WriteFileWrapper(
        mock_h_pipe,
        BufferContentEq(mock_pipe_beacon_resp_bytes, mock_pipe_beacon_resp_bytes_len),
        mock_pipe_beacon_resp_bytes_len,
        _,
        NULL
    )).Times(1)
        .WillOnce(DoAll(
            SetArgPointee<3>(mock_pipe_beacon_resp_bytes_len),
            Return(TRUE)));

    EXPECT_CALL(mock_api_wrapper, FlushFileBuffersWrapper(mock_h_pipe))
        .Times(1)
        .WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(mock_h_pipe)).Times(1);

    ASSERT_EQ(comms_pipe::SendBeaconResp(&mock_api_wrapper, mock_pipe, dummy_beacon_resp_msg.data, FALSE), ERROR_SUCCESS);
}

TEST_F(CommsPipeTest, TestSendTaskOutput) {
    // Catch all logging messages
    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).WillRepeatedly(Return(""));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(_, _)).Times(AtLeast(0));

    EXPECT_CALL(mock_api_wrapper, CreateFileWrapper(
        mock_pipe,
        GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    )).Times(1).WillOnce(Return(mock_h_pipe));
    EXPECT_CALL(mock_api_wrapper, WriteFileWrapper(
        mock_h_pipe,
        BufferContentEq(mock_pipe_task_output_bytes, mock_pipe_task_output_bytes_len),
        mock_pipe_task_output_bytes_len,
        _,
        NULL
    )).Times(1)
        .WillOnce(DoAll(
            SetArgPointee<3>(mock_pipe_task_output_bytes_len),
            Return(TRUE)));

    EXPECT_CALL(mock_api_wrapper, FlushFileBuffersWrapper(mock_h_pipe))
        .Times(1)
        .WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(mock_h_pipe)).Times(1);

    ASSERT_EQ(comms_pipe::SendTaskOutput(&mock_api_wrapper, mock_pipe, mock_client_id, mock_response_pipe, dummy_task_output_msg.data, FALSE), ERROR_SUCCESS);
}

TEST_F(CommsPipeTest, TestSendTaskOutputResp) {
    // Catch all logging messages
    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).WillRepeatedly(Return(""));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(_, _)).Times(AtLeast(0));
    
    EXPECT_CALL(mock_api_wrapper, CreateFileWrapper(
        mock_pipe,
        GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    )).Times(1).WillOnce(Return(mock_h_pipe));
    EXPECT_CALL(mock_api_wrapper, WriteFileWrapper(
        mock_h_pipe,
        BufferContentEq(mock_pipe_task_output_resp_bytes, mock_pipe_task_output_resp_bytes_len),
        mock_pipe_task_output_resp_bytes_len,
        _,
        NULL
    )).Times(1)
        .WillOnce(DoAll(
            SetArgPointee<3>(mock_pipe_task_output_resp_bytes_len),
            Return(TRUE)));

    EXPECT_CALL(mock_api_wrapper, FlushFileBuffersWrapper(mock_h_pipe))
        .Times(1)
        .WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(mock_h_pipe)).Times(1);

    ASSERT_EQ(comms_pipe::SendTaskOutputResp(&mock_api_wrapper, mock_pipe, dummy_task_output_resp_msg.data, FALSE), ERROR_SUCCESS);
}