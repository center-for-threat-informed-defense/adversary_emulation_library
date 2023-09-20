/*
 * Handle P2p communications over windows named pipes
 */

#ifndef CARBON_COMMSLIB_NP_P2P_H_
#define CARBON_COMMSLIB_NP_P2P_H_

#include <windows.h>
#include <errhandlingapi.h>
#include <fileapi.h>
#include <namedpipeapi.h>
#include <iostream>
#include <vector>
#include "EncUtils.hpp"
#include "WindowsWrappers.hpp"

// https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-transactnamedpipe
// "The maximum guaranteed size of a named pipe transaction is 64 kilobytes."
#define PIPE_IN_BUFFER 64*1024
#define PIPE_OUT_BUFFER 64*1024
#define PIPE_MSG_BEACON 1
#define PIPE_MSG_BEACON_RESP 2
#define PIPE_MSG_TASK_OUTPUT 3
#define PIPE_MSG_TASK_OUTPUT_RESP 4
#define PIPE_MSG_ERROR_RESP 5
#define PIPE_CONNECT_SLEEP_MS 20000
#define PIPE_CLIENT_DEFAULT_SLEEP_MS 20000

#define FAIL_PIPE_TASK_OUTPUT_ERROR_RESP 0x2001

#define DEFAULT_PIPE_NAME "dsnap"

namespace comms_pipe {

struct PipeMessage {
    int32_t message_type;
    int32_t client_id_len;
    std::string client_id;
    int32_t response_pipe_path_len;
    std::string response_pipe_path;
    std::vector<char> data;
};

HANDLE ConnectToPipe(
    WinApiWrapperInterface* api_wrapper,
    LPCWSTR pipe_name,
    DWORD* error_code
);

HANDLE CreatePermissivePipe(WinApiWrapperInterface* api_wrapper, std::string pipe_name, DWORD* error_code);

DWORD GetPipeMsg(WinApiWrapperInterface* api_wrapper, HANDLE h_pipe, PipeMessage* msg_buf, bool use_encryption);

DWORD SendPipeMsg(WinApiWrapperInterface* api_wrapper, HANDLE h_pipe, PipeMessage* msg_buf, bool use_encryption);

DWORD SendBeaconRequest(WinApiWrapperInterface* api_wrapper, LPCWSTR dest_pipe, std::string client_id, std::string response_pipe_path, bool use_encryption);

DWORD SendBeaconResp(WinApiWrapperInterface* api_wrapper, LPCWSTR dest_pipe, std::vector<char> resp_data, bool use_encryption);

DWORD SendErrorResp(WinApiWrapperInterface* api_wrapper, LPCWSTR dest_pipe, std::string error_msg, bool use_encryption);

DWORD SendTaskOutput(
    WinApiWrapperInterface* api_wrapper,
    LPCWSTR dest_pipe, 
    std::string client_id, 
    std::string response_pipe_path, 
    std::vector<char> output,
    bool use_encryption
);

DWORD SendTaskOutputResp(WinApiWrapperInterface* api_wrapper, LPCWSTR dest_pipe, std::vector<char> resp_data, bool use_encryption);

} // namespace comms_pipe

#endif
