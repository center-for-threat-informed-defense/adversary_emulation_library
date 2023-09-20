#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "util.h"

using ::testing::StrEq;

TEST(UtilTest, TestStringConversion) {
    std::string narrow_str("This is a test string to convert");
    std::string narrow_empty("");
    std::wstring wide_str(L"This is a test string to convert");
    std::wstring wide_empty(L"");

    std::wstring converted_wide_str = util::ConvertStringToWstring(narrow_str);
    EXPECT_THAT(converted_wide_str, StrEq(wide_str));
    std::string converted_narrow_str = util::ConvertWstringToString(wide_str);
    EXPECT_THAT(converted_narrow_str, StrEq(narrow_str));
    std::wstring converted_wide_empty = util::ConvertStringToWstring(narrow_empty);
    EXPECT_THAT(converted_wide_empty, StrEq(wide_empty));
    std::string converted_narrow_empty = util::ConvertWstringToString(wide_empty);
    EXPECT_THAT(converted_narrow_empty, StrEq(narrow_empty));
}
