#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <testing.h>
#include <Tasks.hpp>
#include <tchar.h>
#include "EncUtils.hpp"

using ::testing::AtLeast;
using ::testing::Return;
using ::testing::StrEq;
using ::testing::_;
using ::testing::Eq;
using ::testing::StartsWith;
using ::testing::SetArgPointee;
using ::testing::SetArgReferee;
using ::testing::DoAll;
using ::testing::Args;

// Test fixture for shared data
class TestTasks : public ::testing::Test {
protected:
    MockWinApiWrapper mock_api_wrapper;
    DWORD dummy_file_attr = 3;
    LPCWSTR mock_task_list_file_path = L"C:\\Users\\Public\\0511\\workdict.xml";
    std::string mock_task_list_file_path_str = "C:\\Users\\Public\\0511\\workdict.xml";
    LPCWSTR mock_carbon_dir = L"C:\\Users\\Public";
    std::string mock_carbon_working_dir = "C:\\Users\\Public";
    HANDLE h_mock_task_list_file = HANDLE(12345);
    HANDLE h_mock_task_config_file = HANDLE(12346);
    HANDLE h_mock_task_payload_file = HANDLE(2345);
};

MATCHER_P2(BufferContentEq, target, length, "") {
    return (memcmp(arg, target, length) == 0);
}

MATCHER_P2(EncryptedBufferContentEq, target, ciphertext_len, "") {
    std::vector<char> ciphertext((char*)arg, (char*)arg + ciphertext_len);
    std::vector<char> plaintext = cast128_enc::Cast128Decrypt(ciphertext, cast128_enc::kCast128Key);
    return memcmp(&plaintext[0], target, plaintext.size()) == 0;
}

unsigned char letters[] = "abcdefghijklmnopqrstuvwxyz";

struct dataBlockInfo{
    byte* data;
    size_t dataLen;
    const bool isString;
    dataBlockInfo(): data(nullptr), dataLen(0), isString(false) {};
    dataBlockInfo(dataBlockInfo &oldObj): dataLen(oldObj.dataLen), isString(oldObj.isString){
        if (oldObj.dataLen > 0) {
            data = (byte*) malloc(dataLen+1);
            memcpy(data, oldObj.data, dataLen);
            if (isString) data[dataLen] = '\0';
        }
        else data = nullptr;
    }
    dataBlockInfo(dataBlockInfo &&oldObj) = delete; // I don't want to deal with move
    dataBlockInfo(int size, bool toBeString):dataLen(size), isString(toBeString){ 
        if (size > 0){
            data = (byte*) malloc(dataLen+1);
            for (int idx = 0; idx < size; idx++){
                if (isString) data[idx] =  letters[std::rand() % 26];
                else data[idx] = (byte) (std::rand() % 0x100);

            }
            if (isString) data[dataLen] = '\0' ;
        }
        else {
            data = nullptr;
        }
        
    };
    ~dataBlockInfo(){ if (dataLen > 0) free(data); };
    size_t writeLenAndData(byte* dest){
        std::memcpy(dest, &dataLen, sizeof(int));
        if (dataLen > 0) std::memcpy(dest + 4, data, dataLen);
        return dataLen + sizeof(int);
    };
    size_t totalSize(){
        return dataLen + sizeof(int);
    }
    bool equals(const char* incomingData, size_t incomingDataLen){
        for (size_t idx = 0; idx < incomingDataLen && idx < dataLen; idx++){
            if (*(incomingData + idx) != *(data + idx)) return false;
        }
        return incomingDataLen == dataLen;
    }
    bool equals(std::string someString){
        return equals(someString.c_str(), (int) someString.length());
    }
};

std::tuple<std::shared_ptr<byte[]>, size_t, dataBlockInfo, dataBlockInfo, dataBlockInfo> 
buildPayload(int taskId, int taskCode, int routingLen, int payloadLen, int configLen){
    dataBlockInfo routingBlock{routingLen, true};
    dataBlockInfo payloadBlock{payloadLen, false};
    dataBlockInfo configBlock{configLen, true};
    
    size_t fullPayloadLen = sizeof(int) + sizeof(int)   // TaskID and Task code
        + routingBlock.totalSize() // for block for len and len of block  
        + payloadBlock.totalSize()
        + configBlock.totalSize();
    std::shared_ptr<byte[]> fullPayload = std::make_shared<byte[]>(fullPayloadLen);

    size_t totalSize = 0;

    // Task ID
    memcpy(fullPayload.get() + totalSize, &taskId, sizeof(int));
    totalSize += sizeof(int);

    // Routing len and routing data
    totalSize += routingBlock.writeLenAndData(&fullPayload[totalSize]);

    // task code
    memcpy(fullPayload.get() + totalSize, &taskCode, sizeof(int));
    totalSize += sizeof(int);

    // Payload len and payload
    totalSize += payloadBlock.writeLenAndData(fullPayload.get() + totalSize);

    // Config len and block size
    totalSize += configBlock.writeLenAndData(fullPayload.get() + totalSize);

    return std::make_tuple(fullPayload, fullPayloadLen, routingBlock, payloadBlock, configBlock);
}
LPCTSTR ErrorMessage(DWORD error) 
{ 
    LPVOID lpMsgBuf;

    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER 
                   | FORMAT_MESSAGE_FROM_SYSTEM 
                   | FORMAT_MESSAGE_IGNORE_INSERTS,
                  NULL,
                  error,
                  MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                  (LPTSTR) &lpMsgBuf,
                  0,
                  NULL);

    return((LPCTSTR)lpMsgBuf);
};
void PrintError(LPCTSTR errDesc)
{
        LPCTSTR errMsg = ErrorMessage(GetLastError());
        _tprintf(TEXT("\n** ERROR ** %s: %s\n"), errDesc, errMsg);
        LocalFree((LPVOID)errMsg);
};
std::shared_ptr<TCHAR[]> makeTmpFile(std::string fileContent) {

    HANDLE hTempFile = INVALID_HANDLE_VALUE; 
    UINT uRetVal   = 0;
    DWORD dwRetVal = 0;
    TCHAR szTempFileName[MAX_PATH];  
    TCHAR lpTempPathBuffer[MAX_PATH];
    DWORD dwBytesWritten = 0; 
    BOOL fSuccess  = FALSE;

    //  Gets the temp path env string (no guarantee it's a valid path).
    dwRetVal = GetTempPath(MAX_PATH,          // length of the buffer
                           lpTempPathBuffer); // buffer for path 

    if (dwRetVal > MAX_PATH || (dwRetVal == 0))
    {
        PrintError(TEXT("GetTempPath failed"));
        return nullptr;
    }

    std::cout << "Temp Path: " << lpTempPathBuffer << std::endl;

    uRetVal = GetTempFileName(lpTempPathBuffer, // directory for tmp files
                              TEXT("DEMO"),     // temp file name prefix 
                              0,                // create unique name 
                              szTempFileName);  // buffer for name 
    if (uRetVal == 0)
    {
        PrintError(TEXT("GetTempFileName failed"));
        return nullptr;
    }

    std::cout << "Temp File: " << szTempFileName << std::endl;

    //  Creates the new file to write to for the upper-case version.
    hTempFile = CreateFile((LPTSTR) szTempFileName, // file name 
                           GENERIC_WRITE,        // open for write 
                           0,                    // do not share 
                           NULL,                 // default security 
                           CREATE_ALWAYS,        // overwrite existing
                           FILE_ATTRIBUTE_NORMAL,// normal file 
                           NULL);                // no template 
    if (hTempFile == INVALID_HANDLE_VALUE) 
    {
        PrintError(TEXT("CreateFile failed"));
        return nullptr;
    }

    if (fileContent.length() > 0){
        fSuccess = WriteFile(hTempFile, 
                                 fileContent.c_str(), 
                                 (DWORD)fileContent.length(),
                                 &dwBytesWritten, 
                                 NULL); 
        if (!fSuccess) 
        {
            PrintError(TEXT("WriteFile failed"));
            return nullptr;
        }
    }
    

    if (!CloseHandle(hTempFile)) 
    {
       PrintError(TEXT("CloseHandle(hTempFile) failed"));
       return nullptr;
    }

    auto returnableFileName = std::make_shared<TCHAR[]>(MAX_PATH);
    memcpy(returnableFileName.get(), szTempFileName, MAX_PATH);
    return returnableFileName;
}

TEST_F(TestTasks, TestExtractSimple){
    byte data[] = {
        0x05, 0x00, 0x00, 0x00, // Task ID
        0x04, 0x00, 0x00, 0x00, // routingBlobLen
        'a', 'b', 'c', 'd',     // routingBlob
        0x03, 0x00, 0x00, 0x00, // Task code
        0x08, 0x00, 0x00, 0x00, // payloadLen
        'e', 'f', 'g', 'h',     // payload
        'i', 'j', 'k', 'l',     
        0x0c, 0x00, 0x00, 0x00, // configLen
        'm', 'n', 'o', 'p',     // config
        'q', 'r', 's', 't',
        'u', 'v', 'w', 'x'
    };
    std::shared_ptr<byte[]> wholePacket = std::make_shared<byte[]>(sizeof(data));
    memcpy(wholePacket.get(), &data, sizeof(data));
    Task testTask{wholePacket, sizeof(data), CarbonLocation};

    EXPECT_EQ(5, testTask.getTaskId());
    EXPECT_EQ(3, testTask.getTaskCode()) ;
    
    ASSERT_NE(testTask.getRoute(), nullptr);
    auto parsedRoute = testTask.getRoute()->c_str();
    auto routeLen = testTask.getRoute()->length();
    EXPECT_EQ(4, routeLen);
    for(int idx = 0; idx < 4; idx++){
        EXPECT_EQ(parsedRoute[idx], data[8+idx]);
    }
    
    
    auto [taskPayloadData, taskPayloadLen] = testTask.getPayload();
    EXPECT_EQ(8, taskPayloadLen);
    ASSERT_NE(taskPayloadData, nullptr);
    for(int idx = 0; idx < 8; idx++){
        EXPECT_EQ(taskPayloadData[idx], data[20+idx]);
    }
    

    ASSERT_NE(testTask.getConfig(), nullptr);
    auto parsedConfig = testTask.getConfig()->c_str();
    auto configLen = testTask.getConfig()->length();
    EXPECT_EQ(12, configLen);
    for(int idx = 0; idx < 12; idx++){
        EXPECT_EQ(parsedConfig[idx], data[32+idx]);
    }
};

TEST_F(TestTasks, TestExtract){
    std::srand((unsigned int)std::time(nullptr));
    int taskId;
    int taskCode;

    // Test all zeros
    taskId = 0;
    taskCode = 0;
    
    auto [fullPayload, payloadLen, routingBlock, payloadBlock, configBlock] = buildPayload(taskId, taskCode, 0, 0, 0);
    
    Task testTask{fullPayload, payloadLen, "C:\\Users\\Public"};

    ASSERT_EQ(taskId, testTask.getTaskId());
    ASSERT_EQ(taskCode, testTask.getTaskCode()) ;
    
    auto parsedRoute = testTask.getRoute()->c_str();
    auto routeLen = testTask.getRoute()->length();
    ASSERT_TRUE(routingBlock.equals(parsedRoute, routeLen)) ;
    
    auto [taskPayloadData, taskPayloadLen] = testTask.getPayload();
    if (taskPayloadData != nullptr) ASSERT_TRUE(payloadBlock.equals((char*)taskPayloadData.get(), taskPayloadLen)) ;
    ASSERT_TRUE(configBlock.equals(testTask.getConfig()->c_str(), testTask.getConfig()->length())) ;
    
    // Test taskId and taskCode as some random number.
    for (int i = 0; i < 50; i++){
        taskId = std::rand();
        taskCode = std::rand();
        auto [fullPayload, payloadLen, routingBlock, payloadBlock, configBlock] = buildPayload(taskId, taskCode, 0, 0, 0);
    
        Task testTask{fullPayload, payloadLen, CarbonLocation};

        ASSERT_EQ(taskId, testTask.getTaskId());
        ASSERT_EQ(taskCode, testTask.getTaskCode()) ;
        
        auto parsedRoute = testTask.getRoute()->c_str();
        auto routeLen = testTask.getRoute()->length();
        EXPECT_TRUE(routingBlock.equals(parsedRoute, routeLen)) ;
        
        auto [taskPayloadData, taskPayloadLen] = testTask.getPayload();
        if (taskPayloadData != nullptr) ASSERT_TRUE(payloadBlock.equals((char*)taskPayloadData.get(), taskPayloadLen)) ;
        EXPECT_TRUE(configBlock.equals(testTask.getConfig()->c_str(), testTask.getConfig()->length())) ;

    }
    // Test taskId and taskCode as some random number.
    for (int i = 0; i < 50; i++){
        taskId = 0;
        taskCode = 0;
        int testRoutingBlobLen = std::rand();
        auto [fullPayload, payloadLen, routingBlock, payloadBlock, configBlock] = buildPayload(taskId, taskCode, testRoutingBlobLen, 0, 0);
    
        Task testTask{fullPayload, payloadLen, CarbonLocation};

        ASSERT_EQ(taskId, testTask.getTaskId());
        ASSERT_EQ(taskCode, testTask.getTaskCode()) ;
        
        auto parsedRoute = testTask.getRoute()->c_str();
        auto routeLen = testTask.getRoute()->length();
        ASSERT_EQ(routeLen, testRoutingBlobLen);
        ASSERT_TRUE(routingBlock.equals(parsedRoute, routeLen)) << "Routing blob was supposed to be \"" << (char*)routingBlock.data << "\", got \"" << parsedRoute << "\"";
        
        auto [taskPayloadData, taskPayloadLen] = testTask.getPayload();
        if (taskPayloadData != nullptr) ASSERT_TRUE(payloadBlock.equals((char*)taskPayloadData.get(), taskPayloadLen)) ;
        ASSERT_TRUE(configBlock.equals(testTask.getConfig()->c_str(), testTask.getConfig()->length())) ;
    }
}


TEST_F(TestTasks, TestSaveTaskWithPayload){
    std::vector<char> empty_contents = std::vector<char>(0);
    char config[] = "[CONFIG]\nname = C:\\mock\\payload\\sysh32.bat\nexe = cmd.exe /c \"C:\\mock\\payload\\sysh32.bat\"";
    std::string expected_task_line = "5 | C:\\mock\\payload\\sysh32.bat | C:\\Users\\Public\\Nlts\\a67s3ofc5.txt | C:\\Users\\Public\\2028\\5.yml | C:\\Users\\Public\\2028\\5.log\n";
    LPCSTR expected_task_line_cstr = expected_task_line.c_str();
    const int configSize = sizeof(config);
    byte dataBeforeConfig[] = {
        0x05, 0x00, 0x00, 0x00, // Task ID
        0x04, 0x00, 0x00, 0x00, // routingBlobLen
        'a', 'b', 'c', 'd',     // routingBlob
        0x03, 0x00, 0x00, 0x00, // Task code
        0x08, 0x00, 0x00, 0x00, // payloadLen
        'e', 'f', 'g', 'h',     // payload
        'i', 'j', 'k', 'l'
    };
    const int fullSizeOfData = sizeof(dataBeforeConfig) + configSize + sizeof(int);
    std::shared_ptr<byte[]> wholePacket = std::make_shared<byte[]>(fullSizeOfData);
    // Copy over data
    memcpy(wholePacket.get(), &dataBeforeConfig, sizeof(dataBeforeConfig));
    // Copy over size of config
    memcpy(wholePacket.get() + sizeof(dataBeforeConfig), &configSize, sizeof(int));
    // Copy over config
    memcpy(wholePacket.get() + sizeof(dataBeforeConfig) + sizeof(int), &config, configSize);    

    // Ciphertext of config and task line
    std::vector<char> encrypted_config = cast128_enc::Cast128Encrypt(std::vector<char>(config, config + configSize), cast128_enc::kCast128Key);
    std::vector<char> encrypted_task_line = cast128_enc::Cast128Encrypt(std::vector<char>(expected_task_line.begin(), expected_task_line.end()), cast128_enc::kCast128Key);
    
    Task testTask{wholePacket, fullSizeOfData, mock_carbon_working_dir};
    
    ASSERT_EQ(5, testTask.getTaskId());
    ASSERT_EQ(3, testTask.getTaskCode()) ;
    ASSERT_NE(testTask.getRoute(), nullptr);
    auto parsedRoute = testTask.getRoute()->c_str();
    auto routeLen = testTask.getRoute()->length();
    EXPECT_EQ(4, routeLen);
    for(int idx = 0; idx < 4; idx++){
        EXPECT_EQ(parsedRoute[idx], wholePacket[8+idx]);
    }
    
    auto [taskPayloadData, taskPayloadLen] = testTask.getPayload();
    ASSERT_EQ(8, taskPayloadLen);
    ASSERT_NE(taskPayloadData, nullptr);
    for(int idx = 0; idx < 8; idx++){
        EXPECT_EQ(taskPayloadData[idx], wholePacket[20+idx]);
    }

    ASSERT_NE(testTask.getConfig(), nullptr);
    auto parsedConfig = testTask.getConfig()->c_str();
    auto parsedConfigLen = testTask.getConfig()->length();
    EXPECT_EQ(configSize, parsedConfigLen);
    for(unsigned int idx = 0; idx < parsedConfigLen; idx++){
        EXPECT_EQ(parsedConfig[idx], config[idx]);
    }

    // Catch all logging messages
    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).WillRepeatedly(Return(""));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(_, _)).Times(AtLeast(0));

    EXPECT_CALL(mock_api_wrapper, GetFileAttributesWrapper(
        StrEq(mock_carbon_dir)
    )).Times(1).WillOnce(Return(dummy_file_attr));
    EXPECT_CALL(mock_api_wrapper, GetFileAttributesWrapper(
        StrEq(mock_task_list_file_path)
    )).Times(1).WillOnce(Return(INVALID_FILE_ATTRIBUTES));
    EXPECT_CALL(mock_api_wrapper, CreateFileWrapper(
        StrEq(mock_task_list_file_path),
        GENERIC_WRITE,          // open for writing
        0,                      // do not share
        NULL,                   // default security
        CREATE_NEW,             // create new file only
        FILE_ATTRIBUTE_NORMAL,  // normal file
        NULL
    )).Times(1).WillOnce(Return(h_mock_task_list_file));
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(
        h_mock_task_list_file
    )).Times(2);

    // Task config file
    EXPECT_CALL(mock_api_wrapper, CreateFileWrapper(
        StrEq(L"C:\\Users\\Public\\Nlts\\a67s3ofc5.txt"),
        GENERIC_WRITE,          // open for writing
        0,                      // do not share
        NULL,                   // default security
        CREATE_ALWAYS,             // create new file only
        FILE_ATTRIBUTE_NORMAL,  // normal file
        NULL
    )).Times(1).WillOnce(Return(h_mock_task_config_file));

    EXPECT_CALL(mock_api_wrapper, WriteFileWrapper( 
        h_mock_task_config_file,           // open file handle
        EncryptedBufferContentEq(config, encrypted_config.size()),      // start of data to write
        (DWORD)encrypted_config.size(),  // number of bytes to write
        _, // number of bytes that were written
        NULL
    )).Times(1).WillOnce(DoAll(
        SetArgPointee<3>((DWORD)encrypted_config.size()),
        Return(TRUE)
    ));
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(
        h_mock_task_config_file
    )).Times(1);
    
    // Payload
    EXPECT_CALL(mock_api_wrapper, CreateFileWrapper(
        StrEq(L"C:\\mock\\payload\\sysh32.bat"),
        GENERIC_WRITE,          // open for writing
        0,                      // do not share
        NULL,                   // default security
        CREATE_ALWAYS,             // create new file only
        FILE_ATTRIBUTE_NORMAL,  // normal file
        NULL
    )).Times(1).WillOnce(Return(h_mock_task_payload_file));

    EXPECT_CALL(mock_api_wrapper, WriteFileWrapper( 
        h_mock_task_payload_file,           // open file handle
        BufferContentEq("efghijkl", 8),      // start of data to write
        8,  // number of bytes to write
        _, // number of bytes that were written
        NULL
    )).Times(1).WillOnce(DoAll(
        SetArgPointee<3>(8),
        Return(TRUE)
    ));
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(
        h_mock_task_payload_file
    )).Times(1);

    // Appending to task list file
    EXPECT_CALL(mock_api_wrapper, FileExistsWrapper(
        StrEq(mock_task_list_file_path_str)
    )).Times(1).WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, ReadFileIntoVectorWrapper(
        StrEq(mock_task_list_file_path_str),
        _
    )).Times(1).WillOnce(DoAll(
        SetArgPointee<1>(TRUE),
        Return(empty_contents)
    ));
    EXPECT_CALL(mock_api_wrapper, CreateFileWrapper(
        StrEq(mock_task_list_file_path),
        GENERIC_WRITE,
        0,                      // do not share
        NULL,                   // default security
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,  // normal file
        NULL
    )).Times(1).WillOnce(Return(h_mock_task_list_file));

    EXPECT_CALL(mock_api_wrapper, WriteFileWrapper( 
        h_mock_task_list_file,           // open file handle
        EncryptedBufferContentEq(expected_task_line_cstr, encrypted_task_line.size()),      // start of data to write
        (DWORD)encrypted_task_line.size(),  // number of bytes to write
        _, // number of bytes that were written
        NULL
    )).Times(1).WillOnce(DoAll(
        SetArgPointee<3>(encrypted_task_line.size()),
        Return(TRUE)
    ));

    ASSERT_TRUE(testTask.SaveTask(&mock_api_wrapper));
}

TEST_F(TestTasks, TestSaveTaskNoPayload){
    std::vector<char> empty_contents = std::vector<char>(0);
    char config[] = "[CONFIG]\nexe = cmd.exe /c whoami /all";
    std::string expected_task_line = "16 |  | C:\\Users\\Public\\Nlts\\a67s3ofc16.txt | C:\\Users\\Public\\2028\\16.yml | C:\\Users\\Public\\2028\\16.log\n";
    LPCSTR expected_task_line_cstr = expected_task_line.c_str();
    const int configSize = sizeof(config);
    byte dataBeforeConfig[] = {
        0x10, 0x00, 0x00, 0x00, // Task ID
        0x04, 0x00, 0x00, 0x00, // routingBlobLen
        'a', 'b', 'c', 'd',     // routingBlob
        0x03, 0x00, 0x00, 0x00, // Task code
        0x00, 0x00, 0x00, 0x00  // payloadLen
    };
    const int fullSizeOfData = (const int)(sizeof(dataBeforeConfig) + configSize + sizeof(int));
    std::shared_ptr<byte[]> wholePacket = std::make_shared<byte[]>(fullSizeOfData);
    // Copy over data
    memcpy(wholePacket.get(), &dataBeforeConfig, sizeof(dataBeforeConfig));
    // Copy over size of config
    memcpy(wholePacket.get() + sizeof(dataBeforeConfig), &configSize, sizeof(int));
    // Copy over config
    memcpy(wholePacket.get() + sizeof(dataBeforeConfig) + sizeof(int), &config, configSize);    

    // Ciphertext of config and task line
    std::vector<char> encrypted_config = cast128_enc::Cast128Encrypt(std::vector<char>(config, config + configSize), cast128_enc::kCast128Key);
    std::vector<char> encrypted_task_line = cast128_enc::Cast128Encrypt(std::vector<char>(expected_task_line.begin(), expected_task_line.end()), cast128_enc::kCast128Key);
    
    Task testTask{wholePacket, fullSizeOfData, mock_carbon_working_dir};
    
    ASSERT_EQ(16, testTask.getTaskId());
    ASSERT_EQ(3, testTask.getTaskCode()) ;
    ASSERT_NE(testTask.getRoute(), nullptr);
    auto parsedRoute = testTask.getRoute()->c_str();
    auto routeLen = testTask.getRoute()->length();
    EXPECT_EQ(4, routeLen);
    for(int idx = 0; idx < 4; idx++){
        EXPECT_EQ(parsedRoute[idx], wholePacket[8+idx]);
    }
    
    auto [taskPayloadData, taskPayloadLen] = testTask.getPayload();
    ASSERT_EQ(0, taskPayloadLen);
    ASSERT_NE(taskPayloadData, nullptr);

    ASSERT_NE(testTask.getConfig(), nullptr);
    auto parsedConfig = testTask.getConfig()->c_str();
    auto parsedConfigLen = testTask.getConfig()->length();
    EXPECT_EQ(configSize, parsedConfigLen);
    for(unsigned int idx = 0; idx < parsedConfigLen; idx++){
        EXPECT_EQ(parsedConfig[idx], config[idx]);
    }

    // Catch all logging messages
    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).WillRepeatedly(Return(""));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(_, _)).Times(AtLeast(0));

    EXPECT_CALL(mock_api_wrapper, GetFileAttributesWrapper(
        StrEq(mock_carbon_dir)
    )).Times(1).WillOnce(Return(dummy_file_attr));
    EXPECT_CALL(mock_api_wrapper, GetFileAttributesWrapper(
        StrEq(mock_task_list_file_path)
    )).Times(1).WillOnce(Return(INVALID_FILE_ATTRIBUTES));
    EXPECT_CALL(mock_api_wrapper, CreateFileWrapper(
        StrEq(mock_task_list_file_path),
        GENERIC_WRITE,          // open for writing
        0,                      // do not share
        NULL,                   // default security
        CREATE_NEW,             // create new file only
        FILE_ATTRIBUTE_NORMAL,  // normal file
        NULL
    )).Times(1).WillOnce(Return(h_mock_task_list_file));
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(
        h_mock_task_list_file
    )).Times(2);

    // Task config file
    EXPECT_CALL(mock_api_wrapper, CreateFileWrapper(
        StrEq(L"C:\\Users\\Public\\Nlts\\a67s3ofc16.txt"),
        GENERIC_WRITE,          // open for writing
        0,                      // do not share
        NULL,                   // default security
        CREATE_ALWAYS,             // create new file only
        FILE_ATTRIBUTE_NORMAL,  // normal file
        NULL
    )).Times(1).WillOnce(Return(h_mock_task_config_file));

    EXPECT_CALL(mock_api_wrapper, WriteFileWrapper( 
        h_mock_task_config_file,           // open file handle
        EncryptedBufferContentEq(config, encrypted_config.size()),      // start of data to write
        (DWORD)encrypted_config.size(),  // number of bytes to write
        _, // number of bytes that were written
        NULL
    )).Times(1).WillOnce(DoAll(
        SetArgPointee<3>((DWORD)encrypted_config.size()),
        Return(TRUE)
    ));
    EXPECT_CALL(mock_api_wrapper, CloseHandleWrapper(
        h_mock_task_config_file
    )).Times(1);
    
    // Appending to task list file
    EXPECT_CALL(mock_api_wrapper, FileExistsWrapper(
        StrEq(mock_task_list_file_path_str)
    )).Times(1).WillOnce(Return(FALSE));
    EXPECT_CALL(mock_api_wrapper, CreateFileWrapper(
        StrEq(mock_task_list_file_path),
        GENERIC_WRITE,
        0,                      // do not share
        NULL,                   // default security
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,  // normal file
        NULL
    )).Times(1).WillOnce(Return(h_mock_task_list_file));

    EXPECT_CALL(mock_api_wrapper, WriteFileWrapper( 
        h_mock_task_list_file,           // open file handle
        EncryptedBufferContentEq(expected_task_line_cstr, encrypted_task_line.size()),      // start of data to write
        (DWORD)encrypted_task_line.size(),  // number of bytes to write
        _, // number of bytes that were written
        NULL
    )).Times(1).WillOnce(DoAll(
        SetArgPointee<3>((DWORD)encrypted_task_line.size()),
        Return(TRUE)
    ));

    ASSERT_TRUE(testTask.SaveTask(&mock_api_wrapper));
}

TEST_F(TestTasks, TestBuildingBlob) {
    // Catch all logging messages
    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).WillRepeatedly(Return(""));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(_, _)).Times(AtLeast(0));
    
    // Test empty array
    char* array0;
    int array0Size = 0;

    auto [data, size] = PackageBytes(&mock_api_wrapper, { std::make_tuple(array0, array0Size)});
    ASSERT_EQ(size, array0Size);
    for (int i = 0; i < size; i++){
        ASSERT_EQ(data[i], array0[i]);
    }

    // Test 1 array
    char array1[] = {'a', 'b'};
    int array1Size = sizeof(array1);

    auto [data1, size1] = PackageBytes(&mock_api_wrapper, { std::make_tuple(array1, array1Size)});
    ASSERT_EQ(size1, array1Size);
    for (int i = 0; i < size1; i++){
        ASSERT_EQ(data1[i], array1[i]);
    }

    // Test empty and 1 array
    auto [data01, size01] = PackageBytes(&mock_api_wrapper, { std::make_tuple(array0, array0Size), std::make_tuple(array1, array1Size)});
    ASSERT_EQ(size01, array0Size + array1Size);
    for (int i = 0; i < array1Size; i++){
        ASSERT_EQ(data1[i], array1[i]);
    }

    // Test multiple arrays
    char array2_0[] = {'a', 'b'};
    int array2_0Size = sizeof(array2_0);
    char array2_1[] = {'c'};
    int array2_1Size = sizeof(array2_1);
    char *array2_2;
    int array2_2Size = 0;

    auto [data2, size2] = PackageBytes(&mock_api_wrapper, { std::make_tuple(array2_0, array2_0Size),  std::make_tuple(array2_1, array2_1Size), std::make_tuple(array2_2, array2_2Size)});
    ASSERT_EQ(size2, array2_0Size + array2_1Size + array2_2Size);
    char array2[] = {'a', 'b', 'c'};
    for (int i = 0; i < size1; i++){
        ASSERT_EQ(data2[i], array2[i]);
    }
}

TEST_F(TestTasks, TestGettingTask) {
    // Log file content:
    std::string output = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
    int task_id = 5;
    std::string object_id = "objectIdString";
    std::vector<char> encrypted_output = cast128_enc::Cast128Encrypt(std::vector<char>(output.begin(), output.end()), cast128_enc::kCast128Key); 
    std::string output_file_path = "C:\\mock\\output\\file\\output.txt"; 

    // task_id | "1" | task_log_filepath | object_id
    std::string task_output_metadata = std::to_string(task_id) + taskInfoSeperator + "1" + taskInfoSeperator + output_file_path + taskInfoSeperator + object_id;
    std::vector<char> encrypted_task_output_metadata = cast128_enc::Cast128Encrypt(std::vector<char>(task_output_metadata.begin(), task_output_metadata.end()), cast128_enc::kCast128Key); 
    std::string task_output_metadata_file_path = "C:\\mock\\task\\output\\metadata.txt";

    // Catch all logging messages
    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).WillRepeatedly(Return(""));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(_, _)).Times(AtLeast(0));

    // getReportableTasks
    EXPECT_CALL(mock_api_wrapper, FileExistsWrapper(
        StrEq(task_output_metadata_file_path)
    )).Times(1).WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, ReadFileIntoVectorWrapper(
        StrEq(task_output_metadata_file_path),
        _
    )).Times(1).WillOnce(DoAll(
        SetArgPointee<1>(TRUE),
        Return(encrypted_task_output_metadata)
    ));
    EXPECT_CALL(mock_api_wrapper, ClearFileWrapper(
        StrEq(task_output_metadata_file_path)
    )).Times(1);

    // BuildBlob
    EXPECT_CALL(mock_api_wrapper, ReadFileIntoVectorWrapper(
        StrEq(output_file_path),
        _
    )).Times(1).WillOnce(DoAll(
        SetArgPointee<1>(TRUE),
        Return(encrypted_output)
    ));

    auto created_reports = TaskReport::getReportableTasks(&mock_api_wrapper, task_output_metadata_file_path);

    ASSERT_TRUE(created_reports.size() == 1);
    auto task_report = created_reports.front();

    EXPECT_EQ(task_report->taskID, task_id);
    EXPECT_EQ(task_report->numFiles, 1);
    ASSERT_THAT(task_report->logFile, StrEq(output_file_path));
    ASSERT_THAT(task_report->objectID, StrEq(object_id));

    auto [data, dataSize] = task_report->BuildBlob(&mock_api_wrapper);

    ASSERT_GE(dataSize, 4*4);
    //task_id | val | tmp_filesize | tmp_content | [OPTIONAL (if val == 2) tmp2_filesize | tmp2_content] | len_object_id | object_id

    int parsed_task_id;
    int parsed_val;
    int parsed_file_size;
    int parsed_len_obj_id;
    memcpy(&parsed_task_id, data.get(), sizeof(parsed_task_id));
    ASSERT_EQ(parsed_task_id, task_id);
    memcpy(&parsed_val, data.get() + 4, sizeof(parsed_val));
    ASSERT_EQ(parsed_val, 1);
    memcpy(&parsed_file_size, data.get() + 8, sizeof(parsed_file_size));
    ASSERT_EQ(parsed_file_size, output.length());
    auto tmp_content = std::vector<char>(parsed_file_size);
    memcpy(&tmp_content[0], data.get() + 12, parsed_file_size);
    std::string parsed_content(tmp_content.begin(), tmp_content.end());
    ASSERT_THAT(parsed_content, StrEq(output));

    memcpy(&parsed_len_obj_id, data.get() + 12 + parsed_file_size, sizeof(parsed_len_obj_id));
    ASSERT_EQ(parsed_len_obj_id, object_id.length());
    auto tmp_obj_id = std::vector<char>(parsed_len_obj_id);
    memcpy(&tmp_obj_id[0], data.get() + 16 + parsed_file_size, parsed_len_obj_id);
    std::string parsed_obj_id(tmp_obj_id.begin(), tmp_obj_id.end());
    ASSERT_THAT(parsed_obj_id, StrEq(object_id));
}

TEST_F(TestTasks, TestGettingEmptyLogFileTask){
    // Log file content:
    std::string output = "";
    int task_id = 5;
    std::string object_id = "objectIdString";
    std::vector<char> encrypted_output = cast128_enc::Cast128Encrypt(std::vector<char>(output.begin(), output.end()), cast128_enc::kCast128Key); 
    std::string output_file_path = "C:\\mock\\output\\file\\output.txt"; 
    // task_id | "1" | task_log_filepath | object_id
    std::string task_output_metadata = std::to_string(task_id) + taskInfoSeperator + "1" + taskInfoSeperator + output_file_path + taskInfoSeperator + object_id;
    std::vector<char> encrypted_task_output_metadata = cast128_enc::Cast128Encrypt(std::vector<char>(task_output_metadata.begin(), task_output_metadata.end()), cast128_enc::kCast128Key); 
    std::string task_output_metadata_file_path = "C:\\mock\\task\\output\\metadata.txt";
    // Catch all logging messages
    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).WillRepeatedly(Return(""));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(_, _)).Times(AtLeast(0));
    // getReportableTasks
    EXPECT_CALL(mock_api_wrapper, FileExistsWrapper(
        StrEq(task_output_metadata_file_path)
    )).Times(1).WillOnce(Return(TRUE));
    EXPECT_CALL(mock_api_wrapper, ReadFileIntoVectorWrapper(
        StrEq(task_output_metadata_file_path),
        _
    )).Times(1).WillOnce(DoAll(
        SetArgPointee<1>(TRUE),
        Return(encrypted_task_output_metadata)
    ));
    EXPECT_CALL(mock_api_wrapper, ClearFileWrapper(
        StrEq(task_output_metadata_file_path)
    )).Times(1);
    // BuildBlob
    EXPECT_CALL(mock_api_wrapper, ReadFileIntoVectorWrapper(
        StrEq(output_file_path),
        _
    )).Times(2).WillRepeatedly(DoAll(
        SetArgPointee<1>(TRUE),
        Return(encrypted_output)
    ));
    auto created_reports = TaskReport::getReportableTasks(&mock_api_wrapper, task_output_metadata_file_path);
    ASSERT_TRUE(created_reports.size() == 1);
    auto task_report = created_reports.front();
    EXPECT_EQ(task_report->taskID, task_id);
    EXPECT_EQ(task_report->numFiles, 1);
    ASSERT_THAT(task_report->logFile, StrEq(output_file_path));
    ASSERT_THAT(task_report->objectID, StrEq(object_id));
    auto [data, dataSize] = task_report->BuildBlob(&mock_api_wrapper);
    ASSERT_GE(dataSize, 4*4);
    //task_id | val | tmp_filesize | tmp_content | [OPTIONAL (if val == 2) tmp2_filesize | tmp2_content] | len_object_id | object_id
    int parsed_task_id;
    int parsed_val;
    int parsed_file_size;
    int parsed_len_obj_id;
    memcpy(&parsed_task_id, data.get(), sizeof(parsed_task_id));
    ASSERT_EQ(parsed_task_id, task_id);
    memcpy(&parsed_val, data.get() + 4, sizeof(parsed_val));
    ASSERT_EQ(parsed_val, 1);
    memcpy(&parsed_file_size, data.get() + 8, sizeof(parsed_file_size));
    ASSERT_EQ(parsed_file_size, output.length());
    auto tmp_content = std::vector<char>(parsed_file_size);
    if (parsed_file_size > 0) memcpy(&tmp_content[0], data.get() + 12, parsed_file_size);
    std::string parsed_content(tmp_content.begin(), tmp_content.end());
    ASSERT_THAT(parsed_content, StrEq(output));
    memcpy(&parsed_len_obj_id, data.get() + 12 + parsed_file_size, sizeof(parsed_len_obj_id));
    ASSERT_EQ(parsed_len_obj_id, object_id.length());
    auto tmp_obj_id = std::vector<char>(parsed_len_obj_id);
    memcpy(&tmp_obj_id[0], data.get() + 16 + parsed_file_size, parsed_len_obj_id);
    std::string parsed_obj_id(tmp_obj_id.begin(), tmp_obj_id.end());
    ASSERT_THAT(parsed_obj_id, StrEq(object_id));

    // Testing C2 server send here
    auto mockHttpConnection = std::make_shared<MockHttpConnection>(kTestingServer, kTestingPort, "", testingUserAgent, kTestingResource);
    mockHttpConnection->setCookie(PHPSESSID, testingUuid, false);
    // EXPECT_THAT(mockHttpConnection, sendData(IS DATA well converted from the buildBlob stuff above.))
    std::shared_ptr<MockHttpSession> mockSession = mockHttpConnection->sessionForConnection;
    ASSERT_NE(mockSession, nullptr);
    EXPECT_CALL(*(mockHttpConnection.get()), InternetOpenWrapper(_, _, _, _, _)).Times(1);
    EXPECT_CALL(*(mockHttpConnection.get()), InternetConnectWrapper(_, _, _, _, _, _, _, _)).Times(1);
    EXPECT_CALL(*(mockSession.get()), HttpOpenRequestWrapper(_, _, _, _, _, _, _, _)).Times(1);
    EXPECT_CALL(*(mockSession.get()), 
        HttpSendRequestWrapper(
            // _, _, _, DecodesAndDecrypts(data), _
            _,_, _, _, _
        )
    ).With(Args<3,4>(DecodesAndDecrypts(data)));
    EXPECT_TRUE(task_report->SendToC2Server(&mock_api_wrapper, mockHttpConnection, kTestingResource));
}
