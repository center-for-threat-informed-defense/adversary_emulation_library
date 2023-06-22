#include "clientPP.hpp"

/* 
osInfo
    About:
        Modeled after HandlePP::infoClient function. Responsible for collecting
        OS info and submitting info to the C2 server.
    Result:
        boolean - true if already executed or executed successfully, false
                otherwise
    MITRE ATT&CK Techniques:
    CTI:
        https://www.trendmicro.com/en_us/research/18/d/new-macos-backdoor-linked-to-oceanlotus-found.html
    References:
*/
bool clientPP::osInfo (int dwRandomTimeSleep) {
    // if parameters are populated, just return true

    // otherwise, perform discovery actions, then return true
    
    // return false on any issues or errors
    return true;
}

/*
runClient
    About:
        Modeled after HandlePP::runHandle function. Responsible for performing
        backdoor capabilities
    Result:
        void - no return value, just performs backdoor capabilities
    MITRE ATT&CK Techniques:
    CTI:
        https://www.trendmicro.com/en_us/research/18/d/new-macos-backdoor-linked-to-oceanlotus-found.html
    References:
*/
void clientPP::runClient(int dwRandomTimeSleep) {
    return;
}

/*
createClientID
    About:
        Modeled after HandlePP::getClientID method. Responsible for generating
        an MD5 hash from the following pieces of information:
            - OS serial number
            - Hardware UUID
            - MAC address 
            - Randomly generated UUID
    Result:
        int8_t - pointer to first value of the ID array
    MITRE ATT&CK Techniques:
    CTI:
        https://www.trendmicro.com/en_us/research/18/d/new-macos-backdoor-linked-to-oceanlotus-found.html
    References:
*/
int8_t clientPP::createClientID() {
    int8_t id[24];

    //  serial number - ioreg -rdl -c IOPlatformExpertDevice | awk '/IOPlatformSerialNumber/ {split ($0, line, "\""); printf("%s", line[4]); }'
    //  hardware UUID - ioreg -rdl -c IOPlatformExpertDevice | awk '/IOPlatformUUID/ {split ($0, line, "\""); printf("%s", line[4]); }'
    //  mac address - ifconfig en0 | awk '/ether/{print $2}'
    //  randomly generated UUID - uuidgen

    return *id;
}
