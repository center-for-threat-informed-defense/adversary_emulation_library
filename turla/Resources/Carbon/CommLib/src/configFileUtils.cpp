#include "configFile.h"
#include "WindowsWrappers.hpp"
#include "EncUtils.hpp"
#include "Config.hpp"
#include "Logging.hpp"

// Make simple check for valid url
bool isValidAddress(std::string url){
    return url.length() > 0 && (url.find('.') != std::string::npos || url.find("TESTING_C2_SERVER_IP") != std::string::npos);
}

// Helper function to check if string has only integer values
bool canBeInteger(std::string incomingStringOfNumber){
    return std::isdigit(incomingStringOfNumber.front())     // Check that the first digit is a digit 
    && (
        incomingStringOfNumber.length() == 1                // Check that there are either no more items ...
        || canBeInteger(incomingStringOfNumber.substr(1))   // or the next items are also digits.
        );
}

// Trim function for strings. Similar to python's .strip() function.
std::string trim(const std::string& str,
                 const std::string& whitespace)
{
    const auto strBegin = str.find_first_not_of(whitespace);
    if (strBegin == std::string::npos)
        return ""; // no content

    const auto strEnd = str.find_last_not_of(whitespace);
    const auto strRange = strEnd - strBegin + 1;

    return str.substr(strBegin, strRange);
}

// Check if line starts the section of properties in config file
bool lineIsSectionStart(std::string line){
    std::string trimmedLine = trim(line);
    return trimmedLine.at(0) == SECTION_START_NAME && trimmedLine.at(trimmedLine.length() - 1) == SECTION_END_NAME;
}

// Convert a string to the type defined for network addresses. Returns nullptr if the string cannot be converted.
std::shared_ptr<networkAddress> stringToNetworkAddress(std::string networkAddrString){
    
    // Split the given string by :
    std::list<std::string> pathParts;
    std::string possibleUrlAddrHdr = "";

    // An exception must be made is the first colon is actually in "https://" or "http://"
    if (networkAddrString.substr(0,4).compare("http") == 0){
        size_t minimumSizeToSave = std::string("http://").length();
        possibleUrlAddrHdr = networkAddrString.substr(0,minimumSizeToSave);
        networkAddrString = networkAddrString.substr(minimumSizeToSave);
    }

    // Now going through rest of string.
    while (networkAddrString.length() > 0){
        
        size_t nextDelim = networkAddrString.find_first_of(":");
        
        // If there is a colon coming up, add string up to that colon to list. Next string is everything after the colon.
        if (nextDelim != std::string::npos) {
            pathParts.push_back(networkAddrString.substr(0,nextDelim));
            networkAddrString = networkAddrString.substr(nextDelim+1);
        }
        // If there is no more colons, just add the string to the list and make the next string empty.
        else {
            pathParts.push_back(networkAddrString);
            networkAddrString = "";
        }
    }

    std::string baseAddress;
    int portNum = defaultPort;
    std::string path = defaultHttpResource;

    // There is always a first part
    if (pathParts.size() > 0 && isValidAddress(pathParts.front())){
        baseAddress = possibleUrlAddrHdr + pathParts.front();
        pathParts.pop_front();
    }
    else {
        // If there is no first part, fail.
        return nullptr;
    }
    // If the next part is a number, then add to tuple, increment current string.
    if (pathParts.size() > 0 && canBeInteger(pathParts.front())){
        portNum = std::stoi(pathParts.front());
        pathParts.pop_front();
    }
    // If there is a next part, set the last of the tuple to it.
    if (pathParts.size() > 0 && pathParts.size() > 0){
        path = pathParts.front();
    }

    // Return the new items as a tuple.
    return std::make_shared<networkAddress>(std::forward_as_tuple(baseAddress, portNum, path));
}

std::shared_ptr<ConfigMap> ParseConfigString(std::string config_string) {
    std::istringstream input;
    input.str(config_string);
    
    // Unordered map of unordered map of strings to report. 
    // Section Name -> Parameter Name -> Parameter Value
    std::shared_ptr<ConfigMap> params = std::make_shared<ConfigMap>();
    
    // Get fetch line. If line is not empty: check if section name, then check if parameter
    std::string currentSectionName = "";
    std::string trimmed_line;

    for (std::string current_line; std::getline(input, current_line); ) {
        trimmed_line = trim(current_line);
        if (trimmed_line.length() > 0){
            // Check if current line starts a new section.
            if (lineIsSectionStart(trimmed_line)){ 
                const auto sectionNameBeginIdx = trimmed_line.find_first_not_of(SECTION_START_NAME);
                const auto sectionNameEndIdx = trimmed_line.find_last_not_of(SECTION_END_NAME);
                const auto sectionNameLength = sectionNameEndIdx - sectionNameBeginIdx + 1;
                currentSectionName = trimmed_line.substr(sectionNameBeginIdx, sectionNameLength);
            }

            // Check if current line has a parameter.
            else if (auto assignmentLoc = trimmed_line.find_first_of("="); assignmentLoc != std::string::npos){
                std::string parameterName = trim(trimmed_line.substr(0, assignmentLoc));
                std::string parameterValue = trim(trimmed_line.substr(assignmentLoc + 1));
                
                // If the section name is valid, save the parameter and it's value in the map.
                if (currentSectionName.length() > 0){
                    (*params.get())[currentSectionName][parameterName] = parameterValue;
                }
            }
        }
    }
    return params;
}

// Parse the config file into a map for easy access.
std::shared_ptr<ConfigMap> ParseConfigFile(WinApiWrapperInterface* api_wrapper, std::string file_path) {

    // Input file as filestream
    std::ifstream ifs(file_path, std::ifstream::in | std::ios::binary);
    
    // Check that input file opened
    if (!ifs.good()) {
        logging::LogMessage(api_wrapper, LOG_CORE, LOG_LEVEL_ERROR, "Could not open config file " + file_path);
        return nullptr;
    }
    
    // Convery file content to vector
    std::vector<char> encryptedConfigChars(std::istreambuf_iterator<char>(ifs), {});

    ifs.close();

    // Attempt to decrypt file and parse
    try {
        auto decryptedString = cast128_enc::Cast128Decrypt(encryptedConfigChars, cast128_enc::kCast128Key);
        try {
            // Parse the config file content as one long string
            return ParseConfigString(std::string{decryptedString.begin(), decryptedString.end()});
        }
        catch (const std::exception& e){
            logging::LogMessage(api_wrapper, LOG_CORE, LOG_LEVEL_ERROR, "Exception caught when parsing config string: " + std::string(e.what()));
            return nullptr;
        }
    }
    catch (const std::exception& e){
        logging::LogMessage(api_wrapper, LOG_CORE, LOG_LEVEL_ERROR, "Exception caught when decrypting config file: " + std::string(e.what()));
        return nullptr;
    }
};
