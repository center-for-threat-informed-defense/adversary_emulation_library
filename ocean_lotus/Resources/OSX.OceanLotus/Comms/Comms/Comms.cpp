#include "Comms.hpp"

#define EXPORT __attribute__((visibility("default")))

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

EXPORT
void sendRequest(const char * type, const std::vector<unsigned char> data, unsigned char ** response, int ** response_length) {
    char httpGET[] = "GET";
    char httpPOST[] = "POST";
    std::string requestBody;

    // convert data to string for building HTTP request
    std::string data_str(data.begin(), data.end());

    // build HTTP request string
    if (strcmp(type, httpGET) == 0) {
        requestBody = buildGETRequestString(data);
        std::cout << "[COMMS] Received data to GET: " + data_str << std::endl;
    }
    else if (strcmp(type, httpPOST) == 0) {
        requestBody = buildPOSTRequestString(data);
        std::cout << "[COMMS] Received data to POST: " + data_str << std::endl;
    }
    else {
        return;
    }

    // create socket

    // send data to socket

    // recv data from socket

    std::string resp_str = "Goodbye";   // temporary received socket data

    std::vector<unsigned char> resp(resp_str.begin(), resp_str.end());
    unsigned char * converted = &resp[0];
    int resp_length = resp.size();

    // update response buffer and response length values for return to caller
    memcpy(*response, converted, resp_length);
    **response_length = resp_length;
}
