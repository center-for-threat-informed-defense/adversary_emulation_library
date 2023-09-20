/*
 * Handle pipe communications between comms and execution modes
 */

#ifndef SNAKE_USERLAND_COMMS_PIPE_H_
#define SNAKE_USERLAND_COMMS_PIPE_H_

#include <windows.h>
#include <errhandlingapi.h>
#include <fileapi.h>
#include <namedpipeapi.h>
#include <sddl.h>
#include <iostream>
#include <vector>
#include "api_wrappers.h"
#include "enc_handler.h"
#include "logging.h"
#include "instruction.h"

#define PIPE_NAME_SERVER L"\\\\.\\pipe\\commsecdev"
#define PIPE_NAME_CLIENT L"\\\\.\\pipe\\commctrldev"

// https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-transactnamedpipe
// "The maximum guaranteed size of a named pipe transaction is 64 kilobytes."
#define PIPE_IN_BUFFER 64*1024
#define PIPE_OUT_BUFFER 64*1024
#define PIPE_MSG_INSTRUCTION_ID_OFFSET 4
#define PIPE_MSG_DATA_OFFSET 22
#define PIPE_MSG_BEACON 1
#define PIPE_MSG_CMD_RESP 2
#define PIPE_MSG_PAYLOAD_RESP 3
#define PIPE_MSG_TASK_OUTPUT 4
#define PIPE_MSG_ERROR_RESP 5
#define DUMMY_INSTR_ID "000000000000000000"
#define PIPE_CONNECT_SLEEP_MS 20000
#define PIPE_CLIENT_DEFAULT_SLEEP_MS 5000

namespace comms_pipe {

extern std::vector<unsigned char> pipe_cast128_key;

struct PipeMessage {
    int32_t message_type;
    std::string instruction_id;
    std::vector<char> data;
};

HANDLE ConnectToPipe(ApiWrapperInterface* api_wrapper, LPCWSTR pipe_name);

HANDLE CreateClientPipe(ApiWrapperInterface* api_wrapper, DWORD* error_code);

DWORD GetPipeMsg(ApiWrapperInterface* api_wrapper, HANDLE h_pipe, PipeMessage* msg_buf);

DWORD SendPipeMsg(ApiWrapperInterface* api_wrapper, HANDLE h_pipe, PipeMessage* msg_buf);

DWORD SendCmdResp(ApiWrapperInterface* api_wrapper, HANDLE h_pipe, std::string response);

DWORD SendPayloadResp(ApiWrapperInterface* api_wrapper, HANDLE h_pipe, std::string path, std::vector<char> data);

DWORD SendErrorResp(ApiWrapperInterface* api_wrapper, HANDLE h_pipe, std::string error_msg);

DWORD SendBeaconRequest(ApiWrapperInterface* api_wrapper, HANDLE h_pipe);

DWORD SendTaskOutput(ApiWrapperInterface* api_wrapper, HANDLE h_pipe, std::string instruction_id, std::vector<char> output);

DWORD CreateNamedPipeSecurityAttr(ApiWrapperInterface* api_wrapper, SECURITY_ATTRIBUTES* sa);

} // namespace comms_pipe

#endif
