//
// runner exe to kick off the main dll
//

#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <libloaderapi.h>
#include <wchar.h>
#include <iostream>
#include <string>
#include <filesystem>
//#include <dllInfo.h>

typedef void(__stdcall* fp_func)(); // typedef for function pointer to the start function in the main dll so we can call it from here

int main (int argc, char *argv[]) { // TODO: put dll location in an .h file?
    (void)argc;
    (void)argv;
    std::string dllName = "MSSVCCFG.DLL"; // make into a config variable
    LPCSTR dllFunctionName = "CompCreate";
    //std::string pwd = std::filesystem::current_path().string() + "\\"; // make into a variable somehow
    std::string dllPath = "C:\\Program Files\\Windows NT\\" + dllName;
    char dllLocation[dllPath.length()+1]; // char array to hold the path to the dll
    strcpy(dllLocation, dllPath.c_str());
    
    HINSTANCE hModule = LoadLibraryA(dllLocation); // get a handle to the dll
    if (!hModule) {
        std::cout << "Could not load DLL from path " << dllPath << std::endl;
        int x;
        std::cin >> x;
        return 1;
    }

    fp_func dllFunc = (fp_func)GetProcAddress(hModule, dllFunctionName); // get a pointer to the dll's init function
    if (!dllFunc) {
        std::cout << "Could not locate the function " << dllFunctionName << std::endl;
        int x;
        std::cin >> x;
        return 2;
    }

    dllFunc(); // run the dll's init function
    return 0;
}