#include "gtest/gtest.h"
#include "../ryuk/se_token.h"
#include "../ryuk/mount_share_operations.h"
#include "../ryuk/file_encryption.h"
#include "../ryuk/bat_actions.h"


TEST(RyukImpactTestCase, TestSeDebugPrivilegeIsSet)
{
    HANDLE hProcessTokenHandle;
    OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hProcessTokenHandle);
    EXPECT_TRUE(ryuk::SetPrivilege(hProcessTokenHandle, SE_DEBUG_NAME, TRUE));
}


TEST(RyukImpactTestCase, TestFileEncryption)
{
    LPCWSTR location = TEXT("C:\\Projects\\wizard_spider\\Resources\\Ryuk\\RyukTests\\commands.txt");
    EXPECT_EQ(0, ryuk::EncryptionProcedure(location));
}

TEST(RyukImpactTestCase, TestRansomNoteDrop)
{
    LPCWSTR location = TEXT("C:\\Projects\\wizard_spider\\Resources\\Ryuk\\RyukTests");
    EXPECT_EQ(TRUE, ryuk::WriteRansomNote(location));
}

GTEST_API_ int wmain(int argc, wchar_t** argv)
{
    _ftprintf_s(stdout, TEXT("Running main() from gtest_main.cc\n"));
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
