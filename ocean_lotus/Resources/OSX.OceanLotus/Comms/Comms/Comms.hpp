#ifndef Comms_
#define Comms_

#include <vector>

/*
sendRequest
    About:
        Sends an HTTP request of type (GET/POST) with contained data
    Result:
        void - the HTTP response is stored at the addresses pointed to by the
        response and response_length parameters
    MITRE ATT&CK Techniques:
        T1071.001 Application Layer Protocol: Web Protocols
    CTI:
        https://www.trendmicro.com/en_us/research/18/d/new-macos-backdoor-linked-to-oceanlotus-found.html
        https://www.trendmicro.com/en_us/research/20/k/new-macos-backdoor-connected-to-oceanlotus-surfaces.html
        https://www.welivesecurity.com/2019/04/09/oceanlotus-macos-malware-update/
    References:
        https://stackoverflow.com/questions/70550983/http-request-using-sockets-on-c
        https://codereview.stackexchange.com/questions/51270/socket-http-post-request
        https://developer.apple.com/library/archive/documentation/DeveloperTools/Conceptual/DynamicLibraries/100-Articles/DynamicLibraryDesignGuidelines.html
*/
extern "C" void sendRequest(const char * type, const std::vector<unsigned char> data, unsigned char ** response, int ** response_length);

#endif
