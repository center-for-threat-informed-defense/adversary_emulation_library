#include <windows.h>
#include <strsafe.h>
#include <functional>

// Win32 Helper Function to retrieve and display error codes: https://learn.microsoft.com/en-us/windows/win32/debug/retrieving-the-last-error-code
void ErrorExit(LPTSTR lpszFunction)
{
	// Retrieve the system error message for the last-error code

	LPVOID lpMsgBuf;
	LPVOID lpDisplayBuf;
	DWORD dw = GetLastError();

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dw,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&lpMsgBuf,
		0, NULL);

	// Display the error message and exit the process

	lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT,
		(lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40) * sizeof(TCHAR));
	StringCchPrintf((LPTSTR)lpDisplayBuf,
		LocalSize(lpDisplayBuf) / sizeof(TCHAR),
		TEXT("%s failed with error %d: %s"),
		lpszFunction, dw, lpMsgBuf);
	MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("Error"), MB_OK);

	LocalFree(lpMsgBuf);
	LocalFree(lpDisplayBuf);
	ExitProcess(dw);
}

constexpr const wchar_t* dll_path{ L"Intermediary.dll" };
constexpr const char* function_name{ "Protection" };

int wmain(int argc, wchar_t* argv[]) {
	HMODULE hGuard = LoadLibraryW(dll_path);
	if (hGuard) {
		printf("guard dll found\n");
	}
	else {
		printf("ERROR: guard HMODULE is null\n");
		int error = GetLastError();
		printf("Last error was %d\n", error);
		ErrorExit((LPTSTR)L"LoadLibraryW");
		return 1;
	}


	FARPROC pGuard = GetProcAddress(hGuard, function_name);
	if (pGuard) {
		printf("guard exported found\n");
	}
	else {
		printf("ERROR: guard FARPROC is null\n");
		int error = GetLastError();
		printf("Last error was %d\n", error);
		ErrorExit((LPTSTR)L"GetProcAddress");
		return 1;
	}

	auto function = reinterpret_cast<void(*)(HWND, HINSTANCE, LPSTR, int)>(pGuard);
	function(nullptr, nullptr, nullptr, 0);
	return 0;
}