/*
 * Logging utilities
 */

#ifndef CARBON_COMMSLIB_LOGGING_H_
#define CARBON_COMMSLIB_LOGGING_H_

#include "WindowsWrappers.hpp"

#define DEBUG_MODE TRUE
#define LOG_CORE 1
#define LOG_P2P_HANDLER 2
#define LOG_HTTP_CLIENT 3
#define LOG_NAMED_PIPE 4
#define LOG_TASKING 5
#define LOG_ENCRYPTION 6
#define LOG_LEVEL_DEBUG 1
#define LOG_LEVEL_INFO 2
#define LOG_LEVEL_ERROR 3

#define FAIL_INVALID_LOG_LEVEL 0x5001
#define FAIL_INVALID_LOG_TYPE 0x5002
#define FAIL_APPEND_LOG_FILE 0x5003
#define FAIL_ENCRYPT_ENCODE_LOG_DATA 0x5004

namespace logging {

DWORD LogMessage(WinApiWrapperInterface* api_wrapper, int log_type, int log_level, std::string msg);

}

#endif
