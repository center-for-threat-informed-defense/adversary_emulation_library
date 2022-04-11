#include "pch.h"
#include "latmove.h"

using namespace std;

/*
 * executeLatMovementCmd: Execute given lateral movement command and retrieve output from stdout
 *		   Src: https://stackoverflow.com/questions/478898/how-do-i-execute-a-command-and-get-the-output-of-the-command-within-c-using-po
 */
string ExecuteLatMovementCmd(string cmd) {
	array<char, 128> buffer;
	string result = "";
	std::unique_ptr<FILE, decltype(&_pclose)> pipe(_popen(cmd.c_str(), "r"), _pclose);
	if (!pipe) {
		printf("Unable to start pipe\n");
		return result;
	}
	while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
		result += buffer.data();
	}
	return result;
}