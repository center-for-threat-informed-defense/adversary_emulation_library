#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <windows.h>
#include "logging.h"
#include "test_util.h"
#include <string>

using ::testing::_;
using ::testing::Return;
using ::testing::StrEq;
using ::testing::InSequence;

// Text fixture for shared data
class LoggingTest : public ::testing::Test {
protected:
    MockApiWrapper mock_api_wrapper;

    HANDLE h_dummy_execution_mutex = HANDLE(8888);
    HANDLE h_dummy_pipe_client_mutex = HANDLE(9999);
    std::string test_log_data = "this is dummy logging data";
    std::string base64_debug_data = "aiJ8cmZ3aBMxXlZRWl5aXkcDCBAACwoCB09BBmQYEV9eC0gFEkoPGRwdFloZCQgAAQdRFFZRTVk="; // [DEBUG] [2000-12-01 12:34:56] this is dummy logging data
    std::string base64_info_data = "ai93dnxtFRMxXlZRWl5aXkcDCBAACwoCB09BBmQYEV9eC0gFEkoPGRwdFloZCQgAAQdRFFZRTVk="; // [INFO]  [2000-12-01 12:34:56] this is dummy logging data
    std::string base64_error_data = "aiNrYnxiaBMxXlZRWl5aXkcDCBAACwoCB09BBmQYEV9eC0gFEkoPGRwdFloZCQgAAQdRFFZRTVk="; // [ERROR] [2000-12-01 12:34:56] this is dummy logging data
    unsigned char test_binary_log_data[16] = { 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00 };
    std::string base64_binary_data = "zojk/IiarLsdCjMlWVF6bA==";
    std::string mock_timestamp = "2000-12-01 12:34:56";
    DWORD dummy_error = 123;

    void SetUp() override {
        logging::h_execution_log_mutex = h_dummy_execution_mutex;
        logging::h_pipe_client_log_mutex = h_dummy_pipe_client_mutex;
    }

};

TEST_F(LoggingTest, TestLoggingDataSuccess) {
    InSequence s;
    
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kC2LogFile), StrEq(base64_binary_data))).Times(1);
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kPipeServerLogFile), StrEq(base64_binary_data))).Times(1);

    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_pipe_client_mutex, MUTEX_WAIT_MS)).Times(1).WillOnce(Return(WAIT_OBJECT_0));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kPipeClientLogFile), StrEq(base64_binary_data))).Times(1);
    EXPECT_CALL(mock_api_wrapper, ReleaseMutexWrapper(h_dummy_pipe_client_mutex)).Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_execution_mutex, MUTEX_WAIT_MS)).Times(1).WillOnce(Return(WAIT_OBJECT_0));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kExecutionLogFile), StrEq(base64_binary_data))).Times(1);
    EXPECT_CALL(mock_api_wrapper, ReleaseMutexWrapper(h_dummy_execution_mutex)).Times(1).WillOnce(Return(TRUE));

    EXPECT_EQ(logging::LogData(&mock_api_wrapper, LOG_C2, test_binary_log_data, sizeof(test_binary_log_data)), ERROR_SUCCESS);
    EXPECT_EQ(logging::LogData(&mock_api_wrapper, LOG_PIPE_SERVER, test_binary_log_data, sizeof(test_binary_log_data)), ERROR_SUCCESS);
    EXPECT_EQ(logging::LogData(&mock_api_wrapper, LOG_PIPE_CLIENT, test_binary_log_data, sizeof(test_binary_log_data)), ERROR_SUCCESS);
    EXPECT_EQ(logging::LogData(&mock_api_wrapper, LOG_EXECUTION, test_binary_log_data, sizeof(test_binary_log_data)), ERROR_SUCCESS);
}

TEST_F(LoggingTest, TestLoggingMessageSuccess) {
    InSequence s;

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kC2LogFile), StrEq(base64_debug_data))).Times(1);

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kPipeServerLogFile), StrEq(base64_info_data))).Times(1);

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_pipe_client_mutex, MUTEX_WAIT_MS)).Times(1).WillOnce(Return(WAIT_OBJECT_0));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kPipeClientLogFile), StrEq(base64_error_data))).Times(1);
    EXPECT_CALL(mock_api_wrapper, ReleaseMutexWrapper(h_dummy_pipe_client_mutex)).Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_execution_mutex, MUTEX_WAIT_MS)).Times(1).WillOnce(Return(WAIT_OBJECT_0));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kExecutionLogFile), StrEq(base64_debug_data))).Times(1);
    EXPECT_CALL(mock_api_wrapper, ReleaseMutexWrapper(h_dummy_execution_mutex)).Times(1).WillOnce(Return(TRUE));

    EXPECT_EQ(logging::LogMessage(&mock_api_wrapper, LOG_C2, LOG_LEVEL_DEBUG, test_log_data), ERROR_SUCCESS);
    EXPECT_EQ(logging::LogMessage(&mock_api_wrapper, LOG_PIPE_SERVER, LOG_LEVEL_INFO, test_log_data), ERROR_SUCCESS);
    EXPECT_EQ(logging::LogMessage(&mock_api_wrapper, LOG_PIPE_CLIENT, LOG_LEVEL_ERROR, test_log_data), ERROR_SUCCESS);
    EXPECT_EQ(logging::LogMessage(&mock_api_wrapper, LOG_EXECUTION, LOG_LEVEL_DEBUG, test_log_data), ERROR_SUCCESS);
}

TEST_F(LoggingTest, TestLoggingMutexFailMutexWait) {
    InSequence s;

    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_execution_mutex, MUTEX_WAIT_MS))
        .Times(1).WillOnce(Return(WAIT_FAILED));
    
    EXPECT_CALL(mock_api_wrapper, GetLastErrorWrapper())
        .Times(1).WillOnce(Return(dummy_error));

    EXPECT_EQ(logging::LogMessage(&mock_api_wrapper, LOG_EXECUTION, LOG_LEVEL_DEBUG, test_log_data), dummy_error);
}

TEST_F(LoggingTest, TestLoggingMutexFailMutexTimeout) {
    InSequence s;

    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_execution_mutex, MUTEX_WAIT_MS))
        .Times(1).WillOnce(Return(WAIT_TIMEOUT));

    EXPECT_EQ(logging::LogMessage(&mock_api_wrapper, LOG_EXECUTION, LOG_LEVEL_DEBUG, test_log_data), FAIL_MUTEX_TIMEOUT);
}

TEST_F(LoggingTest, TestLoggingMutexFailMutexAbandoned) {
    InSequence s;

    EXPECT_CALL(mock_api_wrapper, WaitForSingleObjectWrapper(h_dummy_pipe_client_mutex, MUTEX_WAIT_MS))
        .Times(1).WillOnce(Return(WAIT_ABANDONED));

    EXPECT_EQ(logging::LogMessage(&mock_api_wrapper, LOG_PIPE_CLIENT, LOG_LEVEL_DEBUG, test_log_data), FAIL_MUTEX_ABANDONED);
}