/*
 * Handle executing tasks
 */

#ifndef SNAKE_USERLAND_EXECUTE_H_
#define SNAKE_USERLAND_EXECUTE_H_

#include <windows.h>
#include <processthreadsapi.h>
#include <errhandlingapi.h>
#include <fileapi.h>
#include <namedpipeapi.h>
#include <synchapi.h>
#include <tlhelp32.h>
#include <vector>
#include "instruction.h"
#include "logging.h"
#include "util.h"
#include "usermodule_errors.h"

#define EXECUTOR_PATH_CMD L"C:\\Windows\\System32\\cmd.exe"
#define EXECUTOR_PATH_PSH L"powershell.exe"
#define DEFAULT_TIMEOUT_SECONDS 60
#define PIPE_READ_BUFFER_SIZE 100*1024
#define MAX_CMD_LINE_LENGTH 2048
#define WAIT_CHUNK_MS 100

namespace execute {

std::vector<char> ExecuteCmdCommand(
    ApiWrapperInterface* api_wrapper,
    LPCWSTR command, 
    std::wstring runas_user,
    DWORD timeout_seconds, 
    DWORD* error_code
);

std::vector<char> ExecutePshCommand(
    ApiWrapperInterface* api_wrapper,
    LPCWSTR command, 
    std::wstring runas_user,
    DWORD timeout_seconds, 
    DWORD* error_code
);

std::vector<char> ExecuteProcCommand(
    ApiWrapperInterface* api_wrapper,
    LPCWSTR binary_path, 
    LPCWSTR proc_args,
    std::wstring runas_user,
    DWORD timeout_seconds, 
    DWORD* error_code
);

DWORD GetRunasToken(
    ApiWrapperInterface* api_wrapper,
    std::wstring target_user,
    PHANDLE ph_new_token
);

} // namespace execute

#endif
