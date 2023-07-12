#include "Comms.hpp"

#define EXPORT __attribute__((visibility("default")))

std::string buildGETRequestString(std::string data) {
    std::ostringstream buf;

    buf << "GET / HTTP/1.1\n";
    buf << "User-Agent: curl 7.64.2\n";
    buf << "Accept: */*\n";
    buf << "Connection: close\n";
    buf << "Cookie: erp=" << data;
    buf << "\n\n";

    const auto str = buf.str();

    return str;
}

std::string buildPOSTRequestString(std::string data) {
    std::ostringstream buf;

    buf << "POST / HTTP/1.1\n";
    buf << "User-Agent: curl 7.64.2\n";
    buf << "Accept: */*\n";
    buf << "Content-Length: " << std::to_string(data.length()) << "\n";
    buf << "Content-Type: application/x-www-form-urlencoded\n\n";
    buf << data;

    const auto str = buf.str();

    return str;
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
        requestBody = buildGETRequestString(data_str);
        std::cout << "[COMMS] Received data to GET: " + data_str << std::endl;
    }
    else if (strcmp(type, httpPOST) == 0) {
        requestBody = buildPOSTRequestString(data_str);
        std::cout << "[COMMS] Received data to POST: " + data_str << std::endl;
    }
    else {
        return;
    }

    // create socket
    std::string host = "127.0.0.1";
    int port = 9000;
    
    int sock_connect_status, bytes_read, sock;
    struct sockaddr_in serv_addr;
    unsigned char buffer[RESP_BUFFER_SIZE] = { 0 };

    // send data to socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        std::cout << "[COMMS] Socket creation error" << std::endl;
        return;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    // convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, &host[0], &serv_addr.sin_addr) <= 0) {
        std::cout << "[COMMS] Invalid address" << std::endl;
        return;
    }

    // connect to server
    if ((sock_connect_status = connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr))) < 0) {
        std::cout << "[COMMS] Connection Failed" << std::endl;
        return;
    }
    send(sock, requestBody.data(), requestBody.size(), 0);
    std::cout << "[COMMS] Message sent, attempting to read response..." << std::endl;

    // receive data from socket
    bytes_read = read(sock, buffer, RESP_BUFFER_SIZE);

    // update response buffer and response length values for return to caller
    memcpy(*response, buffer, bytes_read);
    **response_length = bytes_read;
}
