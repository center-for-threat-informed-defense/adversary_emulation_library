#ifndef SNAKE_USERLAND_LOGGING_H_
#define SNAKE_USERLAND_LOGGING_H_

#include <Windows.h>
#include <sddl.h>
#include <fstream>
#include <iostream>
#include <ctime>
#include "api_wrappers.h"
#include "file_handler.h"
#include "usermodule_errors.h"

#define DEBUG_MODE TRUE
#define LOG_C2 1
#define LOG_PIPE_SERVER 2
#define LOG_PIPE_CLIENT 3
#define LOG_EXECUTION 4
#define LOG_LEVEL_DEBUG 1
#define LOG_LEVEL_INFO 2
#define LOG_LEVEL_ERROR 3

#define MUTEX_WAIT_MS 10000

#define PIPE_LOG_MUTEX L"Global\\WindowsCommCtrlDB"
#define EXECUTION_LOG_MUTEX L"Global\\WinBaseSvcDBLock"

#define PATH_SEPARATOR L"\\"
#define C2_LOG_FILE_NAME L"svcmon32.sdb"
#define C2_LOG_FILE_PATH HOME_DIRECTORY PATH_SEPARATOR C2_LOG_FILE_NAME
#define PIPE_SERVER_LOG_FILE_NAME L"svcstat64.bin"
#define PIPE_SERVER_LOG_FILE_PATH HOME_DIRECTORY PATH_SEPARATOR PIPE_SERVER_LOG_FILE_NAME
#define PIPE_CLIENT_LOG_FILE_NAME L"udmon32.bin"
#define PIPE_CLIENT_LOG_FILE_PATH HOME_DIRECTORY PATH_SEPARATOR PIPE_CLIENT_LOG_FILE_NAME
#define EXECUTION_LOG_FILE_NAME L"dbsvcng64.bin"
#define EXECUTION_LOG_FILE_PATH HOME_DIRECTORY PATH_SEPARATOR EXECUTION_LOG_FILE_NAME


namespace logging {

const std::wstring kC2LogFile(C2_LOG_FILE_PATH);
const std::wstring kPipeServerLogFile(PIPE_SERVER_LOG_FILE_PATH);
const std::wstring kPipeClientLogFile(PIPE_CLIENT_LOG_FILE_PATH);
const std::wstring kExecutionLogFile(EXECUTION_LOG_FILE_PATH);

const std::wstring kC2LogId(L"62810421015953103444");
const std::wstring kPipeServerLogId(L"59463656487865612747");
const std::wstring kPipeClientLogId(L"16488587954892310865");
const std::wstring kExecutionLogId(L"23329841273669992682");

const std::wstring kPipeClientLogMutexName(PIPE_LOG_MUTEX);
const std::wstring kExecutionLogMutexName(EXECUTION_LOG_MUTEX);

extern HANDLE h_pipe_client_log_mutex;
extern HANDLE h_execution_log_mutex;

DWORD LogData(ApiWrapperInterface* api_wrapper, int log_type, const unsigned char* data, int data_len);

DWORD LogMessage(ApiWrapperInterface* api_wrapper, int log_type, int log_level, std::string data_str);

DWORD CreatePipeClientLogMutex(ApiWrapperInterface* api_wrapper, BOOL permissive);

DWORD CreateExecutionLogMutex(ApiWrapperInterface* api_wrapper, BOOL permissive);

void CloseMutexHandles(ApiWrapperInterface* api_wrapper);

} // namespace logging

#endif
