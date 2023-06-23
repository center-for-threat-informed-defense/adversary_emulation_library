#ifndef Communication_hpp
#define Communication_hpp

#include <vector>
#include "stdint.h"

class Communication {
public:

    /*
    Communication constructor
        About:
            Modeled after Packet::Packet. Takes in scrambled byte sequence and
            generates a random AES256 key and encrypts the buffer.
        Result:
            Communication object - contains encrypted buffer
        MITRE ATT&CK Techniques:
        CTI:
            https://www.trendmicro.com/en_us/research/18/d/new-macos-backdoor-linked-to-oceanlotus-found.html
        References:
    */
    Communication(std::vector<unsigned char> buf);

    /*
    decryptData
        About:
            Modeled after Packet::decryptData. Decrypts the received C2
            communication
        Result:
            Vector of unsigned char - decrypted C2 communication
        MITRE ATT&CK Techniques:
        CTI:
            https://www.trendmicro.com/en_us/research/18/d/new-macos-backdoor-linked-to-oceanlotus-found.html
        References:
    */
    static std::vector<unsigned char> decryptData(std::vector<unsigned char> data);

    /*
    extractCommand
        About:
            Modeled after Packet::getCommand. Extracts the command instruction from
            the received C2 communication
        Result:
            uint8_t - one byte long code containing instruction to perform
        MITRE ATT&CK Techniques:
        CTI:
            https://www.trendmicro.com/en_us/research/18/d/new-macos-backdoor-linked-to-oceanlotus-found.html
        References:
    */
    static uint8_t extractCommand(Communication packet);
};

#endif /* Communication_hpp */
