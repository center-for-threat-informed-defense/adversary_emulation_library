#include "parser.h"

/**
* Splits the incoming string on pipe (|) characters, adds the tokens
* to the supplied vector pointer.
* 
* @param the data string to split
* @param the vector pointer in which to push the tokens
*/
void splitOnPipe(std::string &data, std::vector<std::string>* pFieldsVector)
{
	std::string delim = "|";

	size_t pos = 0;
	std::string token;
	while ((pos = data.find(delim)) != std::string::npos)
	{
		token = data.substr(0, pos);
		pFieldsVector->push_back(token);
		data.erase(0, pos + delim.length());
	}

	// Add the last field
	pFieldsVector->push_back(data);
}

void parseHTML(std::string &data)
{
	std::string startDelim = "<script>/*";
	size_t start = data.find(startDelim);
	size_t stop = data.find("*/</script>");

	//Erase all but the obfuscated task
	data.erase(stop, data.length());
	data.erase(0, start + startDelim.length());
}