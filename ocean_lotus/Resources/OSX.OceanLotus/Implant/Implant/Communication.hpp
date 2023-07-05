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
            and encrypts the buffer with the provided AES key.
        Result:
            Communication object - contains encrypted buffer
        MITRE ATT&CK Techniques:
        CTI:
            https://www.trendmicro.com/en_us/research/18/d/new-macos-backdoor-linked-to-oceanlotus-found.html
        References:
    */
    Communication(std::vector<unsigned char> buf, std::vector<unsigned char> key);

    /*
    getPayload
        About:
            Modeled after Packet::getData. Gets and calls the Transform class
            to decrypt the payload data
        Result:
            Vector of unsigned char - decrypted C2 communication
        MITRE ATT&CK Techniques:
        CTI:
            https://www.trendmicro.com/en_us/research/18/d/new-macos-backdoor-linked-to-oceanlotus-found.html
        References:
    */
    static std::vector<unsigned char> getPayload(Communication packet);

    /*
    getInstruction
        About:
            Modeled after Packet::getCommand. Gets the command instruction from
            the Communication packet
        Result:
            uint8_t - one byte long code containing instruction to perform
        MITRE ATT&CK Techniques:
        CTI:
            https://www.trendmicro.com/en_us/research/18/d/new-macos-backdoor-linked-to-oceanlotus-found.html
        References:
    */
    static uint8_t getInstruction(Communication packet);

    /*
    getKey
        About:
            Gets the key used for decryption of the payload and encryption of
            the response
        Result:
            Vector of unsigned char - key bytes
        MITRE ATT&CK Techniques:
        CTI:
        References:
    */
   static std::vector<unsigned char> getKey(Communication packet);
};

#endif /* Communication_hpp */
