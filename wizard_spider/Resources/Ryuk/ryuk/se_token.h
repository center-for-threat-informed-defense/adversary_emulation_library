#ifndef RYUK_SE_TOKEN_H_
#define RYUK_SE_TOKEN_H_

#include <cstdio>

#include <windows.h>
#include <tchar.h>
#include <processthreadsapi.h>

namespace ryuk {

    BOOL SetPrivilege(HANDLE hToken, const TCHAR* lpszPrivilege, BOOL bEnablePrivilege);

} // namespace ryuk

#endif RYUK_SE_TOKEN_H_
