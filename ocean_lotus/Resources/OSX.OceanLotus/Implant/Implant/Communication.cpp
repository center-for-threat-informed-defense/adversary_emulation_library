#include "Communication.hpp"

Communication::Communication(std::vector<unsigned char> buf, std::vector<unsigned char> key) {
    // use key to encrypt buf
}

Communication::Communication(std::vector<unsigned char> buf) {
    payload_length = (int)((uint64_t)buf[15] << 24 | (uint64_t)buf[14] << 16 |
        (uint64_t)buf[12] << 8 | (uint64_t)buf[13]);
    key_length = buf[comms::KEY_LENGTH_POS];

    instruction = buf[comms::INSTRUCTION_POS];

    key = std::vector<unsigned char>(&buf[comms::HEADER_LENGTH], &buf[comms::HEADER_LENGTH] + key_length);
    payload = std::vector<unsigned char>(&buf[comms::HEADER_LENGTH] + key_length, &buf[comms::HEADER_LENGTH] + key_length + payload_length);
}

std::vector<unsigned char> Communication::getPayload(Communication packet) {    
    return packet.payload;
}

uint8_t Communication::getInstruction(Communication packet) {
    return packet.instruction;
}

std::vector<unsigned char> Communication::getKey(Communication packet)
{
    return packet.key;
}
