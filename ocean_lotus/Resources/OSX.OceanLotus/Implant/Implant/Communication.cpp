#include "Communication.hpp"

Communication::Communication(std::vector<unsigned char> buf, std::vector<unsigned char> key) {
    // use key to encrypt buf
}

std::vector<unsigned char> Communication::getPayload(Communication packet) {
    std::vector<unsigned char> result;
    return result;
}

uint8_t Communication::getInstruction(Communication packet) {
    return 0;
}

std::vector<unsigned char> Communication::getKey(Communication packet)
{
    std::vector<unsigned char> result;
    return result;
}