#pragma once
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <string>
#include "WindowsWrappers.hpp"
#include "Util.hpp"
#include "HttpClient.hpp"
#include "EncUtils.hpp"

using ::testing::_;
using ::testing::Return;
using ::testing::PrintToString;

// Variables only used in testing.

const std::string originalDummyConfigFile = "dummyConfigFile.txt";
const std::string encryptedDummyConfigFile = "encryptedDummyConfigFile.txt";
const std::string testingUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36 Edg/108.0.1462.54";

bool writeEncryptedConfig();

const std::string kTestingServer{"10.0.2.11"};

const int kTestingPort = 8080;

const std::string kTestingResource{"/javascript/view.php"};

const std::string testingUuid{"TESTINGUUID"};

// Mock the wrapper functions for unit tests
class MockWinApiWrapper : public WinApiWrapperInterface {
public:
	virtual ~MockWinApiWrapper(){};

    MOCK_METHOD1(GetFileAttributesWrapper, DWORD(LPCWSTR lpFileName));

    MOCK_METHOD1(SleepWrapper, void(DWORD dwMilliseconds));

    MOCK_METHOD8(CreateNamedPipeWrapper, HANDLE(
        LPCWSTR               lpName,
        DWORD                 dwOpenMode,
        DWORD                 dwPipeMode,
        DWORD                 nMaxInstances,
        DWORD                 nOutBufferSize,
        DWORD                 nInBufferSize,
        DWORD                 nDefaultTimeOut,
        LPSECURITY_ATTRIBUTES lpSecurityAttributes
    ));

    MOCK_METHOD0(GetLastErrorWrapper, DWORD());

    MOCK_METHOD2(ConnectNamedPipeWrapper, BOOL(
        HANDLE       hNamedPipe,
        LPOVERLAPPED lpOverlapped
    ));

    MOCK_METHOD1(DisconnectNamedPipeWrapper, BOOL(HANDLE hNamedPipe));

    MOCK_METHOD1(CloseHandleWrapper, BOOL(HANDLE hObject));

    MOCK_METHOD5(ReadFileWrapper, BOOL(
        HANDLE       hFile,
        LPVOID       lpBuffer,
        DWORD        nNumberOfBytesToRead,
        LPDWORD      lpNumberOfBytesRead,
        LPOVERLAPPED lpOverlapped
    ));

    MOCK_METHOD5(WriteFileWrapper, BOOL(
        HANDLE       hFile,
        LPCVOID      lpBuffer,
        DWORD        nNumberOfBytesToWrite,
        LPDWORD      lpNumberOfBytesWritten,
        LPOVERLAPPED lpOverlapped
    ));

    MOCK_METHOD7(CreateFileWrapper, HANDLE(
        LPCWSTR               lpFileName,
        DWORD                 dwDesiredAccess,
        DWORD                 dwShareMode,
        LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        DWORD                 dwCreationDisposition,
        DWORD                 dwFlagsAndAttributes,
        HANDLE                hTemplateFile
    ));

    MOCK_METHOD1(FlushFileBuffersWrapper, BOOL(HANDLE hFile));

    MOCK_METHOD4(ConvertStringSecurityDescriptorToSecurityDescriptorWrapper, BOOL(
        LPCWSTR              StringSecurityDescriptor,
        DWORD                StringSDRevision,
        PSECURITY_DESCRIPTOR *SecurityDescriptor,
        PULONG               SecurityDescriptorSize
    ));

    MOCK_METHOD1(LocalFreeWrapper, HLOCAL(HLOCAL hMem));

    MOCK_METHOD2(GetComputerNameWrapper, BOOL(
        LPSTR   lpBuffer,
        LPDWORD nSize
    ));

    MOCK_METHOD2(ReadFileIntoVectorWrapper, std::vector<char>(std::string file_path, bool* success));

    MOCK_METHOD1(ClearFileWrapper, void(std::string file_path));

    MOCK_METHOD1(FileExistsWrapper, bool(std::string file_path));

    MOCK_METHOD2(AppendStringWrapper, void(std::string file_path, std::string data));

    MOCK_METHOD0(CurrentUtcTimeWrapper, std::string());

    void setDefaultActions(){
        ON_CALL(*this, ReadFileIntoVectorWrapper).WillByDefault([this](std::string file_path, bool* success){
            return WinApiWrapperInterface::ReadFileIntoVectorWrapper(file_path, success);
        });
    };
};

class MockHttpSession : public HttpSession {
public:
    MockHttpSession(std::shared_ptr<HttpConnection> httpConnection, HINTERNET connectHandle, 
            std::string verb, std::string resource, std::string userAgentValue, 
            std::string httpVersion, std::string uuid, std::string referer):
            HttpSession(httpConnection, connectHandle, verb, resource, userAgentValue, httpVersion, uuid, referer) {
        ON_CALL(*this, HttpOpenRequestWrapper).WillByDefault([this](HINTERNET hConnect, LPCSTR lpszVerb, LPCSTR lpszObjectName, LPCSTR lpszVersion, LPCSTR lpszReferrer, LPCSTR *lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext) {
                return HttpSession::HttpOpenRequestWrapper(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext);
        });
        ON_CALL(*this, HttpAddRequestHeadersWrapper).WillByDefault([this](HINTERNET hRequest, LPCSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwModifiers){
                return HttpSession::HttpAddRequestHeadersWrapper(hRequest, lpszHeaders, dwHeadersLength, dwModifiers);
        });
        ON_CALL(*this, HttpSendRequestWrapper).WillByDefault([this](HINTERNET hRequest, LPCSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength){
                return HttpSession::HttpSendRequestWrapper(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);
        });
        ON_CALL(*this, InternetQueryDataAvailableWrapper).WillByDefault([this](HINTERNET hFile, LPDWORD lpdwNumberOfBytesAvailable, DWORD dwFlags, DWORD_PTR dwContext){
                return HttpSession::InternetQueryDataAvailableWrapper(hFile, lpdwNumberOfBytesAvailable, dwFlags, dwContext);
        });
        ON_CALL(*this, InternetReadFileWrapper).WillByDefault([this](HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead){
                return HttpSession::InternetReadFileWrapper(hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);
        });
    }
    MOCK_METHOD(HINTERNET, HttpOpenRequestWrapper, (HINTERNET hConnect, LPCSTR lpszVerb, LPCSTR lpszObjectName, LPCSTR lpszVersion, LPCSTR lpszReferrer, LPCSTR *lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext),(override));
    MOCK_METHOD(BOOL, HttpAddRequestHeadersWrapper, (HINTERNET hRequest, LPCSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwModifiers), (override));
    MOCK_METHOD(BOOL, HttpSendRequestWrapper, (HINTERNET hRequest, LPCSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength), (override));
    MOCK_METHOD(BOOL, InternetQueryDataAvailableWrapper, (HINTERNET hFile, LPDWORD lpdwNumberOfBytesAvailable, DWORD dwFlags, DWORD_PTR dwContext), (override));
    MOCK_METHOD(BOOL, InternetReadFileWrapper, (HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead), (override));
    void setParentConnection(std::shared_ptr<HttpConnection> newConnection, HINTERNET hConnect) {parentConnection = newConnection; connectionHandle = hConnect;}

};

class MockHttpConnection : public HttpConnection {
public:
    const std::shared_ptr<MockHttpSession> sessionForConnection;
    const std::string httpRequestResource;
    MockHttpConnection(std::string url, unsigned int port, std::string victimUuid, std::string userAgent, std::string testingResource)
        : HttpConnection(url, port, victimUuid, userAgent), httpRequestResource(testingResource),
        sessionForConnection(new MockHttpSession(nullptr, hConnect, 
                "GET", testingResource, httpUserAgent, 
                httpVersion, httpUserAgent, serverUrl)) 
        {
            // By default, all calls are delegated to the real object.
            ON_CALL(*this, InternetOpenWrapper).WillByDefault([this](LPCSTR lpszAgent, DWORD dwAccessType, LPCSTR lpszProxy, LPCSTR lpszProxyBypass, DWORD dwFlags) {
                return HttpConnection::InternetOpenWrapper(lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags);
            });

            ON_CALL(*this, InternetConnectWrapper).WillByDefault([this](HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword,DWORD dwService,DWORD dwFlags,DWORD_PTR dwContext) {
                return HttpConnection::InternetConnectWrapper(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
            });
            ON_CALL(*this, InternetSetOptionWrapper).WillByDefault([this](HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength){
                return HttpConnection::InternetSetOptionWrapper(hInternet, dwOption, lpBuffer, dwBufferLength);
            });

        };
    MOCK_METHOD(HINTERNET, InternetOpenWrapper, (LPCSTR lpszAgent, DWORD dwAccessType, LPCSTR lpszProxy, LPCSTR lpszProxyBypass, DWORD dwFlags), (override));
    MOCK_METHOD(HINTERNET, InternetConnectWrapper, (HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword,DWORD dwService,DWORD dwFlags,DWORD_PTR dwContext), (override));
    MOCK_METHOD(BOOL, InternetSetOptionWrapper, (HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength), (override));
    
    std::shared_ptr<HttpSession> StartSession(WinApiWrapperInterface* api_wrapper,  std::string resource, std::string uuid_override="") override {
        if (!Connect(api_wrapper)) return nullptr;
        // Set to pass some values properly like in normal HttpConnection, since here the Session object was already created without some objects.
        sessionForConnection->setParentConnection(nullptr, hConnect);
        return sessionForConnection;
    };
};



MATCHER_P(DecodesAndDecrypts, plainText, "") {
    *result_listener << "\nGetting the len as " << (std::get<1>(arg)) ; 

    // Arg should be passed in as a tuple.
    LPVOID data = std::get<0>(arg);
    DWORD dataLen = std::get<1>(arg);
    std::vector<char> encodedVals;
    for (unsigned int i = 0; i < dataLen; i++){
        encodedVals.push_back(*((char*)(data) + i));
    }

    auto decodedValue = decodeToString(std::string{encodedVals.begin(), encodedVals.end()});

    auto decryptedValue = cast128_enc::Cast128Decrypt(std::vector<char>(decodedValue.begin(), decodedValue.end()), cast128_enc::kCast128Key);

    *result_listener << "\nFirst byte of incoming data is " << *(plainText.get()) << " and first char of decrypted value is " << decryptedValue[0];
    
    for (int idx = 0; idx < decryptedValue.size(); idx++){
        if (plainText[idx] != decryptedValue[idx]) return false;
    }
    return true;
};
