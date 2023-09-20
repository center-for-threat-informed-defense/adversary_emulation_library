#include <windows.h>

extern "C" __declspec(dllexport) void MsgBox(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow) {
    MessageBoxW(NULL, L"Hello there...", L"General Kenobi", MB_ICONWARNING | MB_CANCELTRYCONTINUE | MB_DEFBUTTON2);
    return;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    HWND hwnd; 
    HINSTANCE hinst; 
    LPSTR lpszCmdLine;
    int nCmdShow;
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        // attach to process
        MessageBoxW(NULL, L"Process Attach", L"Robleh", MB_ICONWARNING | MB_CANCELTRYCONTINUE | MB_DEFBUTTON2);
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