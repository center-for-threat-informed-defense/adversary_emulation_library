/*
 * Various shared utilities
 */

#ifndef SNAKE_USERLAND_UTIL_H_
#define SNAKE_USERLAND_UTIL_H_

#include <locale>
#include <codecvt>
#include <string>

namespace util {

std::wstring ConvertStringToWstring(std::string input);

std::string ConvertWstringToString(std::wstring input);

}

#endif
