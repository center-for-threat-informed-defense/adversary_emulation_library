/*
 * Handle logging
 */
#include <iostream>
#include <mutex>
#include "Config.hpp"
#include "Logging.hpp"
#include "EncUtils.hpp"

namespace logging {

std::mutex m_module_log;

std::string EncryptAndEncodeLogMsg(std::string to_log) {
    std::vector<char> ciphertext = cast128_enc::Cast128Encrypt(std::vector<char>(to_log.begin(), to_log.end()), cast128_enc::kCast128Key);
    std::vector<unsigned char> to_encode(ciphertext.begin(), ciphertext.end());
    return encodeData(&to_encode[0], to_encode.size()) + "\n"; 
}

// Log given message with prepended timestamp and with given log level. Also logs to console if DEBUG_MODE is enabled.
DWORD LogMessage(WinApiWrapperInterface* api_wrapper, int log_type, int log_level, std::string msg) {
    std::string log_prefix;
    std::string log_type_str;

    switch (log_level) {
        case LOG_LEVEL_DEBUG:
            log_prefix = "[DEBUG] ";
            break;
        case LOG_LEVEL_INFO:
            log_prefix = "[INFO]  ";
            break;
        case LOG_LEVEL_ERROR:
            log_prefix = "[ERROR] ";
            break;
        default:
            if (DEBUG_MODE) std::wcerr << L"Invalid log level " << log_level << std::endl;
            return FAIL_INVALID_LOG_LEVEL;
    }
    switch (log_type) {
        case LOG_CORE:
            log_type_str = " [MODULE CORE]: ";
            break;
        case LOG_P2P_HANDLER:
            log_type_str = " [P2P HANDLER]: ";
            break;
        case LOG_HTTP_CLIENT:
            log_type_str = " [HTTP CLIENT]: ";
            break;
        case LOG_NAMED_PIPE:
            log_type_str = "[PIPE HANDLER]: ";
            break;
        case LOG_TASKING:
            log_type_str = "[TASK HANDLER]: ";
            break;
        case LOG_ENCRYPTION:
            log_type_str = " [ENC HANDLER]: ";
            break;
        default:
            if (DEBUG_MODE) std::wcerr << L"Invalid log type " << log_type << std::endl;
            return FAIL_INVALID_LOG_TYPE;
    }
    std::string to_log = log_prefix + "[" + api_wrapper->CurrentUtcTimeWrapper() + "] " + log_type_str + msg;
    std::string encrypted_encoded_log_msg;
    try {
        encrypted_encoded_log_msg = EncryptAndEncodeLogMsg(to_log);
    } catch (...) {
        // Critical section
        if (DEBUG_MODE) {
            std::lock_guard<std::mutex> lock(m_module_log);
            std::cerr << "[ERROR] [" << api_wrapper->CurrentUtcTimeWrapper() << "]: Failed to encode and encrypt log data" << std::endl;
        } // Critical section
        return FAIL_ENCRYPT_ENCODE_LOG_DATA;
    }
    
    // Critical section
    {
        std::lock_guard<std::mutex> lock(m_module_log);
        if (DEBUG_MODE) {
            if (log_level == LOG_LEVEL_ERROR) {
                std::cerr << to_log << std::endl;
            } else {
                std::cout << to_log << std::endl;
            }
        }
        try {
            api_wrapper->AppendStringWrapper(kCommsModuleLogPath, encrypted_encoded_log_msg);
        } catch (...) {
            if (DEBUG_MODE) std::cerr << "[ERROR] [" << api_wrapper->CurrentUtcTimeWrapper() << "]: Failed to append data to log file " << kCommsModuleLogPath << std::endl;
            return FAIL_APPEND_LOG_FILE;
        }
    } // Critical section
    
    return ERROR_SUCCESS;
}

} // namespace logging