#pragma once
#include <string>
#include <memory>
#include <unordered_map>
#include <list>
#include <fstream>
#include <iostream>
#include <sstream>
#include <array>
#include "WindowsWrappers.hpp"

// Config file key characters
static const char SECTION_START_NAME = '[';
static const char SECTION_END_NAME = ']';

// Config file sections
static const std::string SECTION_NAME {"NAME"};
static const std::string SECTION_PROC {"PROC"};
static const std::string SECTION_CRYPTO {"CRYPTO"};
static const std::string SECTION_TIME{"TIME"};
static const std::string SECTION_CW_LOCAL{"CW_LOCAL"};
static const std::string SECTION_CW_INET{"CW_INET"};
static const std::string SECTION_TRANSPORT{"TRANSPORT"};
static const std::string SECTION_DHCP{"DHCP"};
static const std::string SECTION_LOG{"LOG"};
static const std::string SECTION_WORKDATA{"WORKDATA"};
static const std::string SECTION_LOCATION{"LOCATION"};
static const std::string SECTION_FILE{"FILE"};
static const std::string SECTION_MTX{"MTX"};
static const std::array<std::string, 13> SECTION_NAMES 
    {{
        SECTION_NAME, 
        SECTION_PROC, 
        SECTION_CRYPTO, 
        SECTION_TIME, 
        SECTION_CW_LOCAL,
        SECTION_CW_INET,
        SECTION_TRANSPORT,
        SECTION_DHCP,
        SECTION_LOG,
        SECTION_WORKDATA,
        SECTION_LOCATION,
        SECTION_FILE,
        SECTION_MTX
    }};


// Defaults for when config file is missing these values
const unsigned int defaultPort = 80;
const std::string defaultHttpResource{"/javascript/view.php"};

// Helper Aliases for uniform types
using ConfigMap = std::unordered_map<std::string, std::unordered_map<std::string, std::string>>;
using networkAddress = std::tuple<std::string, int, std::string> ;

//Helper functions
bool isValidAddress(std::string url);
bool canBeInteger(std::string incomingStringOfNumber);
std::string trim(const std::string& str,
                 const std::string& whitespace = " \t\n");
bool lineIsSectionStart(std::string line);

std::shared_ptr<networkAddress> stringToNetworkAddress(std::string networkAddrString);

std::shared_ptr<ConfigMap> ParseConfigString(std::string config_string);
std::shared_ptr<ConfigMap> ParseConfigFile(WinApiWrapperInterface* api_wrapper, std::string file_path);


