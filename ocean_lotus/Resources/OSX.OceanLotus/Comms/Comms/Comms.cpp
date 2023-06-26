#include <iostream>
#include "Comms.hpp"

void sendRequest(const char * s, const std::vector<unsigned char> data)
{
    std::cout << s << std::endl;
    std::string test(data.begin(), data.end());
    std::cout << test << std::endl;
};
