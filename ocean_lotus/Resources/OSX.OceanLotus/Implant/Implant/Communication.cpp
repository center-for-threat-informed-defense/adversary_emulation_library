#include "Communication.hpp"

Communication::Communication(std::vector<unsigned char> buf, std::vector<unsigned char> key) {
    // use key to encrypt buf
}

Communication::Communication(std::vector<unsigned char> buf) {
    payload_length = (int)((buf[comms::PAYLOAD_LENGTH_POS]) | (buf[comms::PAYLOAD_LENGTH_POS + 1] << 8) | (buf[comms::PAYLOAD_LENGTH_POS + 2] << 16) | (buf[comms::PAYLOAD_LENGTH_POS + 3] << 24));
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
