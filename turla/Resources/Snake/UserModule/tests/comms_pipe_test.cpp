#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "comms_pipe.h"
#include "test_util.h"
#include <string>
#include <cstring>
#include <vector>

using ::testing::_;
using ::testing::DoAll;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::SetArgPointee;

// Test fixture for shared data
class CommsPipeTest : public ::testing::Test {
protected:
    MockApiWrapper mock_api_wrapper;

    HANDLE mock_h_pipe = HANDLE(1234);
    std::string mock_id = "123456789012345678";
    std::string blank_id = "000000000000000000";
    std::string dummy_cmd = "ID123456789012345678#01 &d2hvYW1pIC9hbGw=#5&&&";
    static constexpr const size_t mock_pipe_beacon_request_data_len = 22;
    static constexpr const char mock_pipe_beacon_request_data[22] = {
        0x01,0x00,0x00,0x00, // beacon request, little endian
        0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30
    };
    static constexpr const size_t mock_pipe_cmd_resp_data_len = 68;
    static constexpr const char mock_pipe_cmd_resp_data[68] = {
        0x02,0x00,0x00,0x00,
        0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,

        // ID123456789012345678#01 &d2hvYW1pIC9hbGw=#5&&&
        0x49,0x44,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x23,0x30,0x31,0x20,0x26,0x64,0x32,0x68,0x76,0x59,0x57,0x31,0x70,0x49,0x43,0x39,0x68,0x62,0x47,0x77,0x3d,0x23,0x35,0x26,0x26,0x26
    };
    std::string dummy_output_str = "eeeeeeeeeeee";
    std::vector<char> dummy_output = std::vector<char>(dummy_output_str.begin(), dummy_output_str.end());
    static constexpr const size_t mock_pipe_task_output_data_len = 34;
    static constexpr const char mock_pipe_task_output_data[34] = {
        0x04,0x00,0x00,0x00,
        0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,

        0x65,0x65,0x65,0x65,0x65,0x65,0x65,0x65,0x65,0x65,0x65,0x65
    };

    std::string mock_payload_path = "C:\\test\\path";
    static constexpr const size_t mock_pipe_payload_resp_data_len = 50;
    static constexpr const char mock_pipe_payload_resp_data[50] = {
        0x03,0x00,0x00,0x00,
        0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,
        0x0c,0x00,0x00,0x00,
        0x43,0x3a,0x5c,0x74,0x65,0x73,0x74,0x5c,0x70,0x61,0x74,0x68, // C:\test\path
        0x65,0x65,0x65,0x65,0x65,0x65,0x65,0x65,0x65,0x65,0x65,0x65
    };

    comms_pipe::PipeMessage dummy_beacon_req_msg = comms_pipe::PipeMessage();
    comms_pipe::PipeMessage dummy_cmd_resp_msg = comms_pipe::PipeMessage();
    comms_pipe::PipeMessage dummy_payload_resp_msg = comms_pipe::PipeMessage();
    comms_pipe::PipeMessage dummy_task_output_msg = comms_pipe::PipeMessage();

    void SetUp() override {
        dummy_beacon_req_msg.data = std::vector<char>();
        dummy_beacon_req_msg.instruction_id = blank_id;
        dummy_beacon_req_msg.message_type = PIPE_MSG_BEACON;

        dummy_cmd_resp_msg.data = std::vector<char>(dummy_cmd.begin(), dummy_cmd.end());
        dummy_cmd_resp_msg.instruction_id = blank_id;
        dummy_cmd_resp_msg.message_type = PIPE_MSG_CMD_RESP;

        dummy_payload_resp_msg.data = dummy_output;
        dummy_payload_resp_msg.instruction_id = blank_id;
        dummy_payload_resp_msg.message_type = PIPE_MSG_PAYLOAD_RESP;

        dummy_task_output_msg.data = dummy_output;
        dummy_task_output_msg.instruction_id = mock_id;
        dummy_task_output_msg.message_type = PIPE_MSG_TASK_OUTPUT;
    }
};

// Define our own matching logic to compare PipeMessage structs
MATCHER_P(PipeMsgEq, pTarget, "") {
    return (pTarget->message_type == arg->message_type) &&
        (pTarget->data == arg->data) &&
        (pTarget->instruction_id.compare(arg->instruction_id) == 0);
}

MATCHER_P2(BufferContentEq, target, length, "") {
    return (memcmp(arg, target, length) == 0);
}

TEST_F(CommsPipeTest, TestGetPipeMsgSuccessBeaconReq) {
    LPVOID mock_buf;

    EXPECT_CALL(mock_api_wrapper, ReadFileWrapper(
        mock_h_pipe,
        _,
        PIPE_OUT_BUFFER,
        _,
        NULL
    )).Times(2)
        .WillOnce(DoAll(
            SaveArg<1>(&mock_buf),
            Invoke([&mock_buf]() { std::memcpy(mock_buf, mock_pipe_beacon_request_data, mock_pipe_beacon_request_data_len); }),
            SetArgPointee<3>(mock_pipe_beacon_request_data_len),
            Return(TRUE)))
        .WillOnce(DoAll(
            SetArgPointee<3>(0),
            Return(FALSE)));

    EXPECT_CALL(mock_api_wrapper, GetLastErrorWrapper())
        .Times(1)
        .WillOnce(Return(ERROR_BROKEN_PIPE));

    comms_pipe::PipeMessage pipe_msg = comms_pipe::PipeMessage();
    ASSERT_EQ(comms_pipe::GetPipeMsg(&mock_api_wrapper, mock_h_pipe, &pipe_msg), ERROR_SUCCESS);
    EXPECT_THAT(&pipe_msg, PipeMsgEq(&dummy_beacon_req_msg));
}

TEST_F(CommsPipeTest, TestGetPipeMsgSuccessBeaconResp) {
    LPVOID mock_buf;

    EXPECT_CALL(mock_api_wrapper, ReadFileWrapper(
        mock_h_pipe,
        _,
        PIPE_OUT_BUFFER,
        _,
        NULL
    )).Times(2)
        .WillOnce(DoAll(
            SaveArg<1>(&mock_buf),
            Invoke([&mock_buf]() { std::memcpy(mock_buf, mock_pipe_cmd_resp_data, mock_pipe_cmd_resp_data_len); }),
            SetArgPointee<3>(mock_pipe_cmd_resp_data_len),
            Return(TRUE)))
        .WillOnce(DoAll(
            SetArgPointee<3>(0),
            Return(FALSE)));

    EXPECT_CALL(mock_api_wrapper, GetLastErrorWrapper())
        .Times(1)
        .WillOnce(Return(ERROR_BROKEN_PIPE));

    comms_pipe::PipeMessage pipe_msg = comms_pipe::PipeMessage();
    ASSERT_EQ(comms_pipe::GetPipeMsg(&mock_api_wrapper, mock_h_pipe, &pipe_msg), ERROR_SUCCESS);
    EXPECT_THAT(&pipe_msg, PipeMsgEq(&dummy_cmd_resp_msg));
}

TEST_F(CommsPipeTest, TestSendBeaconReq) {
    EXPECT_CALL(mock_api_wrapper, WriteFileWrapper(
        mock_h_pipe,
        BufferContentEq(mock_pipe_beacon_request_data, mock_pipe_beacon_request_data_len),
        mock_pipe_beacon_request_data_len,
        _,
        NULL
    )).Times(1)
        .WillOnce(DoAll(
            SetArgPointee<3>(mock_pipe_beacon_request_data_len),
            Return(TRUE)));

    EXPECT_CALL(mock_api_wrapper, FlushFileBuffersWrapper(mock_h_pipe))
        .Times(1)
        .WillOnce(Return(TRUE));

    ASSERT_EQ(comms_pipe::SendBeaconRequest(&mock_api_wrapper, mock_h_pipe), ERROR_SUCCESS);
}

TEST_F(CommsPipeTest, TestSendCmdResp) {
    EXPECT_CALL(mock_api_wrapper, WriteFileWrapper(
        mock_h_pipe,
        BufferContentEq(mock_pipe_cmd_resp_data, mock_pipe_cmd_resp_data_len),
        mock_pipe_cmd_resp_data_len,
        _,
        NULL
    )).Times(1)
        .WillOnce(DoAll(
            SetArgPointee<3>(mock_pipe_cmd_resp_data_len),
            Return(TRUE)));

    EXPECT_CALL(mock_api_wrapper, FlushFileBuffersWrapper(mock_h_pipe))
        .Times(1)
        .WillOnce(Return(TRUE));

    ASSERT_EQ(comms_pipe::SendCmdResp(&mock_api_wrapper, mock_h_pipe, dummy_cmd), ERROR_SUCCESS);
}

TEST_F(CommsPipeTest, TestSendPayloadResp) {
    EXPECT_CALL(mock_api_wrapper, WriteFileWrapper(
        mock_h_pipe,
        BufferContentEq(mock_pipe_payload_resp_data, mock_pipe_payload_resp_data_len),
        mock_pipe_payload_resp_data_len,
        _,
        NULL
    )).Times(1)
        .WillOnce(DoAll(
            SetArgPointee<3>(mock_pipe_payload_resp_data_len),
            Return(TRUE)));

    EXPECT_CALL(mock_api_wrapper, FlushFileBuffersWrapper(mock_h_pipe))
        .Times(1)
        .WillOnce(Return(TRUE));

    ASSERT_EQ(comms_pipe::SendPayloadResp(&mock_api_wrapper, mock_h_pipe, mock_payload_path, dummy_output), ERROR_SUCCESS);
}

TEST_F(CommsPipeTest, TestSendTaskOutput) {
    EXPECT_CALL(mock_api_wrapper, WriteFileWrapper(
        mock_h_pipe,
        BufferContentEq(mock_pipe_task_output_data, mock_pipe_task_output_data_len),
        mock_pipe_task_output_data_len,
        _,
        NULL
    )).Times(1)
        .WillOnce(DoAll(
            SetArgPointee<3>(mock_pipe_task_output_data_len),
            Return(TRUE)));

    EXPECT_CALL(mock_api_wrapper, FlushFileBuffersWrapper(mock_h_pipe))
        .Times(1)
        .WillOnce(Return(TRUE));

    ASSERT_EQ(comms_pipe::SendTaskOutput(&mock_api_wrapper, mock_h_pipe, mock_id, dummy_output), ERROR_SUCCESS);
}
