#pragma once
#include <string>

namespace common {

std::wstring string_to_wstring(const std::string& str);
std::string wstring_to_string(const std::wstring& str);

} // namespace common