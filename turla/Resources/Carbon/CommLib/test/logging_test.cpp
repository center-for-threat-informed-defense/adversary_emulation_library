#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "Logging.hpp"
#include "Config.hpp"
#include "EncUtils.hpp"
#include "testing.h"
#include <string>

using ::testing::_;
using ::testing::Return;
using ::testing::StrEq;
using ::testing::InSequence;

// Text fixture for shared data
class LoggingTest : public ::testing::Test {
protected:
    MockWinApiWrapper mock_api_wrapper;

    std::string test_log_data = "this is dummy logging data";
    std::string mock_timestamp = "2000-12-01 12:34:56";
};

MATCHER_P(EncryptedEncodedStr, target, "") {
    std::string decoded = decodeToString(arg);
    std::vector<char> ciphertext(decoded.begin(), decoded.end());
    std::vector<char> plaintext = cast128_enc::Cast128Decrypt(ciphertext, cast128_enc::kCast128Key);
    return memcmp(&plaintext[0], target, plaintext.size()) == 0 && strlen(target) == plaintext.size();
}

TEST_F(LoggingTest, TestLoggingMessageWithEnc) {
    InSequence s;

    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(
        StrEq(kCommsModuleLogPath), 
        EncryptedEncodedStr("[DEBUG] [2000-12-01 12:34:56]  [MODULE CORE]: this is dummy logging data")
    )).Times(1);
    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(
        StrEq(kCommsModuleLogPath), 
        EncryptedEncodedStr("[INFO]  [2000-12-01 12:34:56]  [P2P HANDLER]: this is dummy logging data")
    )).Times(1);
    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(
        StrEq(kCommsModuleLogPath), 
        EncryptedEncodedStr("[ERROR] [2000-12-01 12:34:56]  [ENC HANDLER]: this is dummy logging data")
    )).Times(1);
    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(
        StrEq(kCommsModuleLogPath), 
        EncryptedEncodedStr("[DEBUG] [2000-12-01 12:34:56]  [HTTP CLIENT]: this is dummy logging data")
    )).Times(1);
    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(
        StrEq(kCommsModuleLogPath), 
        EncryptedEncodedStr("[INFO]  [2000-12-01 12:34:56] [PIPE HANDLER]: this is dummy logging data")
    )).Times(1);
    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(1).WillOnce(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(
        StrEq(kCommsModuleLogPath), 
        EncryptedEncodedStr("[ERROR] [2000-12-01 12:34:56] [TASK HANDLER]: this is dummy logging data")
    )).Times(1);

    EXPECT_EQ(logging::LogMessage(&mock_api_wrapper, LOG_CORE, LOG_LEVEL_DEBUG, test_log_data), ERROR_SUCCESS);
    EXPECT_EQ(logging::LogMessage(&mock_api_wrapper, LOG_P2P_HANDLER, LOG_LEVEL_INFO, test_log_data), ERROR_SUCCESS);
    EXPECT_EQ(logging::LogMessage(&mock_api_wrapper, LOG_ENCRYPTION, LOG_LEVEL_ERROR, test_log_data), ERROR_SUCCESS);
    EXPECT_EQ(logging::LogMessage(&mock_api_wrapper, LOG_HTTP_CLIENT, LOG_LEVEL_DEBUG, test_log_data), ERROR_SUCCESS);
    EXPECT_EQ(logging::LogMessage(&mock_api_wrapper, LOG_NAMED_PIPE, LOG_LEVEL_INFO, test_log_data), ERROR_SUCCESS);
    EXPECT_EQ(logging::LogMessage(&mock_api_wrapper, LOG_TASKING, LOG_LEVEL_ERROR, test_log_data), ERROR_SUCCESS);
}
