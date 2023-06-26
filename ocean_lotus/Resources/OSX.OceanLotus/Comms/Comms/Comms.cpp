#include <iostream>
#include "Comms.hpp"

std::string buildGETRequestString(const std::vector<unsigned char> data) {
    // User-Agent: curl/7.11.3
    // Accept: */*
    // Cookie: m_pixel_ratio=... | erp=...
    return "";
}

std::string buildPOSTRequestString(const std::vector<unsigned char> data) {
    // User-Agent: curl 7.64.2
    // Accept: */*
    // Content-Length: 355
    // Content-Type: application/x-www-form-urlencoded
    return "";
}

void sendRequest(const char * type, const std::vector<unsigned char> data)
{
    std::cout << "Type recieved: " + std::string(type) << std::endl;
    std::string data_str(data.begin(), data.end());
    std::cout << "Data: " + data_str << std::endl;

    std::string requestBody;
    if (strcmp(type, "GET")) {
        requestBody = buildGETRequestString(data);
    }
    else if (strcmp(type, "POST")) {
        requestBody = buildPOSTRequestString(data);
    }
    else {
        std::cout << "Ignoring: " + std::string(type) << std::endl;
        return;
    }

    // create socket

    // send data to socket

    // recv data from socket

    // return the data to caller
};
