#pragma once

#include <string>
#include <map>


namespace instruction {
    struct Instruction {
        uint32_t commandID = 0;
        uint32_t payloadSize = 0;
        std::vector<unsigned char> payload = std::vector<unsigned char>();
        uint32_t configSize = 0;
        std::map<std::string, std::string> config = std::map<std::string, std::string>();
    };
}