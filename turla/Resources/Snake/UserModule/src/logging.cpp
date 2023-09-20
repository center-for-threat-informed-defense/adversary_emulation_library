/*
 * Handle logging
 * 
 * CTI references:
 * [1] https://artemonsecurity.com/snake_whitepaper.pdf
 * [2] https://public.gdatasoftware.com/Web/Content/INT/Blog/2014/02_2014/documents/GData_Uroburos_RedPaper_EN_v1.pdf
 */

#include "logging.h"
#include "enc_handler.h"
#include "base64.h"

namespace fs = std::filesystem;

namespace logging {

HANDLE h_pipe_client_log_mutex = NULL;
HANDLE h_execution_log_mutex = NULL;

DWORD LogDataWithMutex(ApiWrapperInterface* api_wrapper, HANDLE h_mutex, std::wstring log_path, std::string encoded_data) {
    // Grab mutex if we're writing to pipe client log or execution log
    DWORD wait_result = api_wrapper->WaitForSingleObjectWrapper(h_mutex, MUTEX_WAIT_MS);
    DWORD result = ERROR_SUCCESS;
    switch (wait_result) {
        case WAIT_OBJECT_0:
            // Append data
            try {
                api_wrapper->AppendStringWrapper(log_path, encoded_data);
            } catch (...) {
                if (DEBUG_MODE) std::wcerr << L"[ERROR] Failed to append data to log file " << log_path << std::endl;
                result = FAIL_APPEND_LOG_FILE;
            }
            if (!api_wrapper->ReleaseMutexWrapper(h_mutex)) {
                if (DEBUG_MODE) std::wcerr << L"[ERROR] Failed to release mutex. Error code: " << api_wrapper->GetLastErrorWrapper() << std::endl;
                return FAIL_MUTEX_RELEASE;
            }
            break;
        case WAIT_ABANDONED:
            if (DEBUG_MODE) {
                std::wcerr << L"[ERROR] Mutex in abandoned state." << std::endl;
            }
            return FAIL_MUTEX_ABANDONED;
        case WAIT_TIMEOUT:
            if (DEBUG_MODE) {
                std::wcerr << L"[ERROR] Timeout elapsed when waiting for mutex." << std::endl;
            }
            return FAIL_MUTEX_TIMEOUT;
        case WAIT_FAILED:
            result = api_wrapper->GetLastErrorWrapper();
            if (DEBUG_MODE) {
                std::wcerr << L"[ERROR] Failed to wait for mutex. Error code: " << result << std::endl;
            }
            return result;
        default:
            return FAIL_MUTEX_WAIT_FAILED;
    }
    return result;
}

// Log raw  data (no timestamp added).
DWORD LogData(ApiWrapperInterface* api_wrapper, int log_type, const unsigned char* data, int data_len) {
    std::wstring log_path;
    std::string encoded_data;

    switch (log_type) {
        case LOG_C2:
            log_path = kC2LogFile;
            break;
        case LOG_PIPE_SERVER:
            log_path = kPipeServerLogFile;
            break;
        case LOG_PIPE_CLIENT:
            log_path = kPipeClientLogFile;
            break;
        case LOG_EXECUTION:
            log_path = kExecutionLogFile;
            break;
        default:
            if (DEBUG_MODE) std::wcerr << L"Unsupported log type " << log_type << std::endl;
            return FAIL_INVALID_LOG_TYPE;
    }

    // XOR encrypt log message
    std::vector<unsigned char> ciphertext_buffer(data_len);
    std::memcpy(&ciphertext_buffer[0], data, data_len);
    XorInPlace(&ciphertext_buffer[0], data_len);

    // Encode to base64
    try {
        CryptoPP::StringSource ss(
            &ciphertext_buffer[0], 
            data_len, 
            true, 
            new CryptoPP::Base64Encoder(
                new CryptoPP::StringSink(encoded_data),
                false // no line breaks
            )
        );
    } catch (...) {
        if (DEBUG_MODE) std::wcerr << L"Failed to base64 encode data." << std::endl;
        return FAIL_BASE64_ENCODE;
    }

    // Check if we need to use a mutex.
    if (log_type == LOG_PIPE_CLIENT) {
        return LogDataWithMutex(api_wrapper, logging::h_pipe_client_log_mutex, log_path, encoded_data);
    } else if (log_type == LOG_EXECUTION) {
         return LogDataWithMutex(api_wrapper, logging::h_execution_log_mutex, log_path, encoded_data);
    } else {
        try {
            api_wrapper->AppendStringWrapper(log_path, encoded_data);
        } catch (...) {
            if (DEBUG_MODE) std::wcerr << L"Failed to append data to log file " << log_path << std::endl;
            return FAIL_APPEND_LOG_FILE;
        }
    }
    return ERROR_SUCCESS;
}

// Log given message with prepended timestamp and with given log level. Also logs to console if DEBUG_MODE is enabled.
DWORD LogMessage(ApiWrapperInterface* api_wrapper, int log_type, int log_level, std::string data_str) {
    std::string log_level_prefix;

    switch (log_level) {
        case LOG_LEVEL_DEBUG:
            log_level_prefix = "[DEBUG] ";
            break;
        case LOG_LEVEL_INFO:
            log_level_prefix = "[INFO]  ";
            break;
        case LOG_LEVEL_ERROR:
            log_level_prefix = "[ERROR] ";
            break;
        default:
            if (DEBUG_MODE) std::wcerr << L"Invalid log level " << log_level << std::endl;
            return FAIL_INVALID_LOG_LEVEL;
    }
    std::string to_log = log_level_prefix + "[" + api_wrapper->CurrentUtcTimeWrapper() + "] " + data_str;
    if (DEBUG_MODE) {
        if (log_level == LOG_LEVEL_ERROR) {
            std::cerr << to_log << std::endl;
        } else {
            std::cout << to_log << std::endl;
        }
    }
    return LogData(api_wrapper, log_type, reinterpret_cast<const unsigned char*>(to_log.c_str()), to_log.length());
}

// Reference: https://learn.microsoft.com/en-us/windows/win32/secbp/creating-a-dacl
DWORD CreateMutexSecurityAttr(ApiWrapperInterface* api_wrapper, SECURITY_ATTRIBUTES* sa) {
    sa->nLength = sizeof(SECURITY_ATTRIBUTES);
    sa->bInheritHandle = FALSE;

    std::wstring dacl_str = std::wstring(L"D:") + // Discretionary ACL
        L"(D;OICI;GA;;;BG)" +      // Deny access to built-in guests
        L"(D;OICI;GA;;;AN)" +      // Deny access to anonymous logon
        L"(A;OICI;0x1F0003;;;AU)" +  // Allow EVENT_ALL_ACCESS to authenticated users
        L"(A;OICI;0x1F0003;;;BA)"; // Allow EVENT_ALL_ACCESS to administrators

    BOOL result = api_wrapper->ConvertStringSecurityDescriptorToSecurityDescriptorWrapper(
        dacl_str.c_str(),
        SDDL_REVISION_1,
        &(sa->lpSecurityDescriptor),
        NULL
    );
    if (!result) {
        return api_wrapper->GetLastErrorWrapper();
    }
    return ERROR_SUCCESS;
}

DWORD CreateSingleMutex(ApiWrapperInterface* api_wrapper, LPCWSTR mutex_name, PHANDLE ph_mutex, BOOL permissive) {
    SECURITY_ATTRIBUTES mutex_sa;
    SECURITY_ATTRIBUTES* p_sa = NULL;
    DWORD error_code;
    if (permissive) {
        error_code = CreateMutexSecurityAttr(api_wrapper, &mutex_sa);
        if (error_code != ERROR_SUCCESS) {
            if (DEBUG_MODE) std::wcerr << L"Failed to create mutex security attributes. Error code: " << error_code << std::endl;
            return error_code;
        }
        p_sa = &mutex_sa;
    }
    
    *ph_mutex = api_wrapper->CreateMutexWrapper(p_sa, FALSE, mutex_name);
    if (*ph_mutex == NULL) {
        error_code = api_wrapper->GetLastErrorWrapper();
        if (DEBUG_MODE) std::wcerr << L"Failed to create mutex. Error code: " << error_code << std::endl;
        return error_code;
    }

    if (p_sa != NULL && api_wrapper->LocalFreeWrapper(mutex_sa.lpSecurityDescriptor) != NULL) {
        error_code = api_wrapper->GetLastErrorWrapper();
        api_wrapper->CloseHandleWrapper(*ph_mutex);
        if (DEBUG_MODE) std::wcerr << L"Failed to free security attribute struct. Error code: " << error_code << std::endl;
        return error_code;
    }
    return ERROR_SUCCESS;
}

DWORD CreatePipeClientLogMutex(ApiWrapperInterface* api_wrapper, BOOL permissive) {
    return CreateSingleMutex(api_wrapper, kPipeClientLogMutexName.c_str(), &h_pipe_client_log_mutex, permissive);
}

DWORD CreateExecutionLogMutex(ApiWrapperInterface* api_wrapper, BOOL permissive) {
    return CreateSingleMutex(api_wrapper, kExecutionLogMutexName.c_str(), &h_execution_log_mutex, permissive);
}

void CloseMutexHandles(ApiWrapperInterface* api_wrapper) {
    if (h_execution_log_mutex != NULL) api_wrapper->CloseHandleWrapper(h_execution_log_mutex);
    if (h_pipe_client_log_mutex != NULL) api_wrapper->CloseHandleWrapper(h_pipe_client_log_mutex);
}

} // namespace logging