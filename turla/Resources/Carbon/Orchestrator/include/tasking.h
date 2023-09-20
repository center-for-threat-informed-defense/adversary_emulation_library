#ifndef TASKING_H_
#define TASKING_H_

#include <windows.h>
#include <string>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>
#include <algorithm>
#include <filesystem>
#include <map>
#include <tchar.h>
#include "../include/orchestrator.h"
#include "../include/mutex.h"

#define PIPE_READ_BUFFER_SIZE 100*1024

namespace tasking {

extern std::string taskFileName;

struct task{ // struct for a task
    std::string task_id;
    std::string task_filepath;
    std::string task_config_filepath;
    std::string task_result_filepath;
    std::string task_log_filepath;
};

struct taskConfig{ // struct for the config file for a task
    std::string name;
    std::string arg;
};

class TaskingCallWrapperInterface {
public:
    TaskingCallWrapperInterface(){}
    virtual ~TaskingCallWrapperInterface(){}
    virtual BOOL CreateProcessWrapper(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes,
                                      LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags,
                                      LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo,
                                      LPPROCESS_INFORMATION lpProcessInformation) = 0;
    virtual DWORD WaitForSingleObjectWrapper(HANDLE hHandle, DWORD dwMilliseconds) = 0;
    virtual WINBOOL CloseHandleWrapper(HANDLE hObject) = 0;
    virtual DWORD GetLastErrorWrapper() = 0;
    virtual BOOL ReadFileWrapper(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead,
                                 LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) = 0;
    virtual BOOL CreatePipeWrapper(PHANDLE hReadPipe, PHANDLE hWritePipe, LPSECURITY_ATTRIBUTES lpPipeAttributes, DWORD nSize) = 0;
    virtual BOOL SetHandleInformationWrapper(HANDLE hObject, DWORD dwMask, DWORD dwFlags) = 0;
    virtual BOOL GetExitCodeProcessWrapper(HANDLE hProcess, LPDWORD lpExitCode) = 0;
};

class TaskingCallWrapper : public TaskingCallWrapperInterface {
public:
    BOOL CreateProcessWrapper(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes,
                              LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags,
                              LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo,
                              LPPROCESS_INFORMATION lpProcessInformation);
    DWORD WaitForSingleObjectWrapper(HANDLE hHandle, DWORD dwMilliseconds);
    WINBOOL CloseHandleWrapper(HANDLE hObject);
    DWORD GetLastErrorWrapper();
    BOOL ReadFileWrapper(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead,
                         LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
    BOOL CreatePipeWrapper(PHANDLE hReadPipe, PHANDLE hWritePipe, LPSECURITY_ATTRIBUTES lpPipeAttributes, DWORD nSize);
    BOOL SetHandleInformationWrapper(HANDLE hObject, DWORD dwMask, DWORD dwFlags);
    BOOL GetExitCodeProcessWrapper(HANDLE hProcess, LPDWORD lpExitCode);
};

int BuildTaskFromLine(std::string taskLine, task *orchTask);

int BuildConfigFromContents(std::string taskConfigContents, taskConfig *orchTaskConfig);

int GetTaskLinesFromContents(std::string fileContents, std::vector<std::string> *taskLines);

int CreateOutputFiles(task *orchTask, std::string resultFilePathStr, std::string logFilePathStr);

int SpawnProcess(TaskingCallWrapperInterface* t_call_wrapper, taskConfig *orchTaskConfig, HANDLE h_output_pipe, PROCESS_INFORMATION* pi);

DWORD WaitCleanupTask(TaskingCallWrapperInterface* t_call_wrapper, PROCESS_INFORMATION* pi, std::string logFilePathStr);

std::vector<char> GetProcessOutputAndCleanupTaskProcess(
    TaskingCallWrapperInterface* t_call_wrapper,
    HANDLE h_pipe_rd, 
    PROCESS_INFORMATION* pi,
    DWORD timeout_seconds,
    DWORD* error_code,
    std::string logFilePathStr,
    std::string taskID
);

std::vector<char> GetProcessOutput(TaskingCallWrapperInterface* t_call_wrapper, HANDLE h_pipe_rd, DWORD* error_code, std::string logFilePathStr);

int ExecuteTask(TaskingCallWrapperInterface* t_call_wrapper, task *orchTask, std::string logFilePathStr, std::vector<char>* output);

int DeleteOutputFiles(task *orchTask);

int TaskingManager(TaskingCallWrapperInterface* t_call_wrapper);

} // namespace tasking

#endif