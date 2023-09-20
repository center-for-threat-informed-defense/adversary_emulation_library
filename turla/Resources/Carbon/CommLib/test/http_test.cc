#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <testing.h>
#include <HttpClient.hpp>
#include <vector>

using ::testing::AtLeast;
using ::testing::StrEq;
using ::testing::StrNe;
using ::testing::_;
using ::testing::Return;

// Test fixture for shared data
class TestHttp : public ::testing::Test {
protected:
    MockWinApiWrapper mock_api_wrapper;
    HINTERNET h_mock_internet = HINTERNET(1234);
    HINTERNET h_mock_connect = HINTERNET(1235);
};

TEST_F(TestHttp, TestCreateConnection){
    auto test_conn = std::make_shared<MockHttpConnection>(kTestingServer, kTestingPort, "", testingUserAgent, kTestingResource);

    // Catch all logging messages
    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).WillRepeatedly(Return(""));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(_, _)).Times(AtLeast(0));

    EXPECT_CALL(*(test_conn.get()), InternetOpenWrapper(
        StrEq(testingUserAgent),
        INTERNET_OPEN_TYPE_DIRECT,
        NULL,
        NULL,
        0  
    )).Times(2).WillOnce(Return(nullptr)).WillOnce(Return(h_mock_internet));
    EXPECT_CALL(*(test_conn.get()), InternetConnectWrapper(
        h_mock_internet,
        StrEq(kTestingServer),
        kTestingPort,
        NULL,
        NULL,
        INTERNET_SERVICE_HTTP,
        0,
        0
    )).Times(1).WillOnce(Return(h_mock_connect));

    EXPECT_FALSE(test_conn->IsValid(&mock_api_wrapper)); // Fails after InternetOpenWrapper fails once. Does not call InternetConnectWrapper
    EXPECT_TRUE(test_conn->IsValid(&mock_api_wrapper)); // Runs InternetOpenWrapper and InternetConnectWrapper each once.
    ASSERT_TRUE(test_conn->hasInternet());
    ASSERT_TRUE(test_conn->hasConnection());
}

TEST_F(TestHttp, TestCreateSimpleSession){
    auto test_conn = std::make_shared<HttpConnection>(kTestingServer, kTestingPort, "", "");

    // Catch all logging messages
    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).WillRepeatedly(Return(""));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(_, _)).Times(AtLeast(0));

    ASSERT_TRUE(test_conn->IsValid(&mock_api_wrapper));
    EXPECT_TRUE(test_conn->MakeSimpleConnection(&mock_api_wrapper, "/"));
}

TEST_F(TestHttp, testCreateSimpleSessionWithData){
    auto testConnection = std::make_shared<HttpConnection>(kTestingServer, kTestingPort, "", "TESTING");

    // Catch all logging messages
    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).WillRepeatedly(Return(""));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(_, _)).Times(AtLeast(0));

    ASSERT_TRUE(testConnection->IsValid(&mock_api_wrapper));
    ASSERT_TRUE(testConnection->SetTimeout(&mock_api_wrapper, 5)) << "Could not set timeout";
    ASSERT_TRUE(testConnection->setCookie(PHPSESSID, testingUuid, false)) << "Could not set cookie, error " << std::to_string(GetLastError());
    auto session = testConnection->StartSession(&mock_api_wrapper, kTestingResource);

    ASSERT_TRUE(session->ValidSession(&mock_api_wrapper)) << "Could not start session.";

    ASSERT_GT(session->NumberBytesAvailable(&mock_api_wrapper), 0) << "Could not retrieve available bytes for session.";
    auto returned = session->GetData(&mock_api_wrapper);
    ASSERT_THAT(returned, StrNe(""));
    std::cout << returned << std::endl;
}

TEST_F(TestHttp, testTimeoutSetCorrectly){
    auto testConnection = std::make_shared<HttpConnection>(kTestingServer, kTestingPort, "", "TESTING");

    // Catch all logging messages
    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).WillRepeatedly(Return(""));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(_, _)).Times(AtLeast(0));

    ASSERT_TRUE(testConnection->IsValid(&mock_api_wrapper));
    testConnection->SetTimeout(&mock_api_wrapper, 5);
    // TODO get the internet option, check if the timeout was correct.
}

TEST_F(TestHttp, testMultipleSession){
    auto testConnection = std::make_shared<HttpConnection>(kTestingServer, kTestingPort, "", "TESTING");

    // Catch all logging messages
    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).WillRepeatedly(Return(""));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(_, _)).Times(AtLeast(0));
    
    EXPECT_TRUE(testConnection->MakeSimpleConnection(&mock_api_wrapper, "/"));
    auto session = testConnection->StartSession(&mock_api_wrapper, kTestingResource);
    EXPECT_TRUE(session->ValidSession(&mock_api_wrapper));
}

TEST_F(TestHttp, TestGetValueTagValue){
    std::vector <std::vector<std::string>> input_and_want_collection {
        std::vector<std::string>{"<input name=\"hello\" value=\"something\">", "something"},
        std::vector<std::string>{" <input name=\"hello\" value=\"something\"> ", "something"},
        std::vector<std::string>{"<input name=\"hello\" value=\"something12345\">", "something12345"},
        std::vector<std::string>{"<input name=\"hello\" value=\"\">", ""},
        std::vector<std::string>{"HTML 1.0/s jlksjdflsjd jdjdjdf=d <hfd> </djd> <input name=\"hello\" value=\"something09u3250325 y8t t ogj lgsjkghps  \"> ghghgh ", "something09u3250325 y8t t ogj lgsjkghps  "},
    };

    for (auto input_and_want : input_and_want_collection) {
        std::string value = GetValueTagValue(input_and_want[0]);
        EXPECT_EQ(value.compare(input_and_want[1]), 0);
    }
}
