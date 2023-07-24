#ifndef Comms_
#define Comms_

#include <iostream>
#include <vector>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sstream>

const int RESP_BUFFER_SIZE = 65535;

const int HEADER_LENGTH = 82;
const unsigned char MAGIC_BYTES[] = {0x3B, 0x91, 0x01, 0x10};
const int PAYLOAD_LENGTH_POS = 8;
const int KEY_LENGTH_POS = 12;
const int INSTRUCTION_POS = 14;
const unsigned char MARKER_1[] = {0xC2};
const int MARKER_1A_POS = 19;
const unsigned char MARKER_2[] = {0xE2};
const int MARKER_2_POS = 24;
const unsigned char MARKER_3[] = {0xFF};
const int MARKER_1B_POS = 29;
const int MARKER_3_POS = 75;

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
        https://www.geeksforgeeks.org/socket-programming-cc/
        https://developer.apple.com/library/archive/documentation/DeveloperTools/Conceptual/DynamicLibraries/100-Articles/DynamicLibraryDesignGuidelines.html
*/
extern "C" void sendRequest(const char * type, const std::vector<unsigned char> data, unsigned char ** response, int ** response_length, unsigned char ** instruction);

#endif
