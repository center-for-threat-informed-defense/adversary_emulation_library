#include "Util.hpp"

namespace util {

static std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;

// Reference: https://stackoverflow.com/a/18597384

std::wstring ConvertStringToWstring(std::string input) {
    return converter.from_bytes(input);
}

std::string ConvertWstringToString(std::wstring input) {
    return converter.to_bytes(input);
}

} // namespace