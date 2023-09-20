#ifndef ORCHESTRATOR_H_
#define ORCHESTRATOR_H_

#include <windows.h>
#include <map>
#include <string>
#include <vector>
#include <iostream>
#include <algorithm>
#include "../include/util.h"
#include "../include/enc_handler.h"
#include "../include/locker.h"

// Below are the various fail codes the orchestrator can output
// as well as their decimal counterparts so you can just CTRL+F

// fail codes for parsing the config
#define FAIL_CONFIG_BUILD_PATH 0x100                // 256
#define FAIL_CONFIG_READ 0x101                      // 257
#define FAIL_CONFIG_FIND_PROCS 0x102                // 258
#define FAIL_CONFIG_POPULATE_VECTOR 0x103           // 259

// fail codes for enabling debug privs
#define FAIL_DEBUG_PRIVS_OPEN_PROCESS_TOKEN 0x200   // 512
#define FAIL_DEBUG_PRIVS_LOOKUP_PRIV_VALUE 0x201    // 513
#define FAIL_DEBUG_PRIVS_ADJUST_TOKEN_PRIVS 0x202   // 514

// fail codes for getting a process handle
#define FAIL_PROC_VECTOR_CREATE_SNAPSHOT 0x300      // 768
#define FAIL_PROC_VECTOR_SNAPSHOT_EMPTY 0x301       // 769
#define FAIL_PROC_VECTOR_OPEN_PROCESS 0x302         // 770
#define FAIL_PROC_VECTOR_CANNOT_FIND_PROC 0x303     // 771

// fail codes for getting a module handle
#define FAIL_MOD_HANDLE_CREATE_SNAPSHOT 0x400       // 1024
#define FAIL_MOD_HANDLE_SNAPSHOT_EMPTY 0x401        // 1025
#define FAIL_MOD_HANDLE_CANNOT_FIND_MOD 0x402       // 1026

// fail codes for actual injection
#define FAIL_INJ_GET_PROC_ADDRESS 0x500             // 1280
#define FAIL_INJ_OPEN_PROCESS 0x502                 // 1281
#define FAIL_INJ_BUILD_FILE_PATH 0x503              // 1282
#define FAIL_INJ_VIRTUAL_ALLOC_EX 0x504             // 1283
#define FAIL_INJ_WRITE_PROCESS_MEMORY 0x505         // 1284
#define FAIL_INJ_CREATE_REMOTE_THREAD 0x506         // 1285
#define FAIL_INJ_NO_SUCCESSFUL_INJ 0x506            // 1286
#define FAIL_INJ_CANT_FIND_DLL 0x507                // 1287
#define FAIL_INJ_NO_VALID_TARGET 0x508              // 1288

// fail codes for mutex
#define FAIL_MUTEX_CREATE_MUTEX 0x600               // 1536
#define FAIL_MUTEX_OPEN_MUTEX 0x601                 // 1537
#define FAIL_MUTEX_ABANDONED 0x602                  // 1538
#define FAIL_MUTEX_NOT_MAPPED 0x603                 // 1539
#define FAIL_MUTEX_WAIT_FAILED 0x604                // 1540
#define FAIL_MUTEX_SA_CONVERT_FAILED 0x605          // 1541

// fail codes for tasking
#define FAIL_TASKING_CANT_READ_FILE 0x700           // 1792
#define FAIL_TASKING_BAD_NUM_ARGUMENTS 0x701        // 1793
#define FAIL_TASKING_BAD_TASK_ID 0x702              // 1794
#define FAIL_TASKING_BAD_RESULT_PATH 0x703          // 1795
#define FAIL_TASKING_BAD_LOG_PATH 0x704             // 1796
#define FAIL_TASKING_BAD_OUTPUT_PATHS 0x705         // 1797
#define FAIL_TASKING_BAD_CONFIG_FIELDS 0x706        // 1798
#define FAIL_TASKING_CREATEPROCESS_FAIL 0x707       // 1799
#define FAIL_TASKING_TIMEOUT_REACHED 0x708          // 1800
#define FAIL_TASKING_CREATE_PIPE 0x709              // 1801
#define FAIL_TASKING_SET_PIPE_HANDLE 0x70A          // 1802
#define FAIL_TASKING_WAITCLEANUPTASK 0x70B          // 1803
#define FAIL_TASKING_BAD_TASK_ARG 0x70C             // 1804

// fail codes for tasking test
#define FAIL_TTEST_WAIT 0x800                       // 2048
#define FAIL_TTEST_RELEASE 0x801                    // 2049

// fail codes for pipes
#define FAIL_PIPE_SA_CONVERT_FAILED 0x900           // 2304
#define FAIL_PIPE_CREATE_PIPE_FAILED 0x901          // 2305
#define FAIL_PIPE_CREATE_THREAD_FAILED 0x902        // 2306

// fail codes for pipe testing
#define FAIL_PTEST_CANT_OPEN 0xA00                  // 2560
#define FAIL_PTEST_TIMEOUT 0xA01                    // 2561
#define FAIL_PTEST_SET_STATE_FAILED 0xA02           // 2562
#define FAIL_PTEST_WRITEFILE_FAILED 0xA03           // 2563
#define FAIL_PTEST_READFILE_FAILED 0xA04            // 2564

// fail codes for util
#define FAIL_BASE64_ENCODE 0xB00                    // 2816

// fail codes for orchestrator
#define FAIL_ORCH_POPULATE_CONFIG 0xC00                  // 3072

namespace orchestrator {

extern std::string workingDir;
extern std::string defaultErrorLogPath;
extern std::string defaultRegLogPath;
extern std::string configFileName;
extern std::string configPipeSection;
extern std::string configFilePath;
extern std::string configFileContents;
extern std::map<std::string,Mutex> mMutexMap;
extern std::string lpLogAccessName;
extern std::string lpELogAccessName;
extern std::string lpFileUploadName;
extern std::string lpTasksName;
extern std::string lpConfigName;
extern std::string taskDir;
extern std::string taskDirPath;
extern std::string logDir;
extern std::string logDirPath;
extern std::string taskConfigDir;
extern std::string taskConfigDirPath;
extern std::string taskFilePath;
extern std::vector<unsigned char> key;
extern std::string errorLogName;
extern std::string errorLogPath;
extern std::string regLogName;
extern std::string regLogPath;
extern std::string sendFileName;
extern std::string sendFilePath;
extern std::string uuid;
extern bool commsActiveFlag;
extern bool logMutexFlag;

int PopulateConfigValues();

}
#endif