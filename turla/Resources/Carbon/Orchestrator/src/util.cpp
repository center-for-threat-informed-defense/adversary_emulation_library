#include "../include/util.h"

namespace util {

bool test = false;

// given a string target file name or path to file (\directory\file.file) return an absolute string path
// this assumes that the target file or file path is inside the working directory
std::string BuildFilePath(std::string targetFile) {
    return orchestrator::workingDir + targetFile;
}

// Four helper functions to trim whitespace from a string
void leftTrim(std::string &str) {
    str.erase(str.begin(), std::find_if(str.begin(), str.end(), [](unsigned char ch) {
        return !std::isspace(ch);
    }));
}

void rightTrim(std::string &str) {
    str.erase(std::find_if(str.rbegin(), str.rend(), [](unsigned char ch) {
        return !std::isspace(ch);
    }).base(), str.end());
}

void trim(std::string &str) {
    leftTrim(str);
    rightTrim(str);
}

std::string trimCopy(std::string str) {
    trim(str);
    return str;
}

// read the target file's contents into a string
std::string readFile(std::string targetFileName) {
    std::ifstream configFile;
    std::string line;
    std::string retStr;
    configFile.open(targetFileName);

    if (configFile.is_open()) {

        retStr = "";

        while (getline(configFile, line)) {
            retStr += line + "\n";
        }
        
        configFile.close();
        return retStr;

    } else {
        configFile.close();
        return "";
    }
}

// given absolute string path to a target file, put the contents of that file into a string and return it
// If there is a mutex associated with the target file, lock it before reading
// The calling function is expected to throw an error when this function returns ""
std::string GetStringContentsFromFile(std::string targetFileName) {
    // check if config values have been populated
    if (orchestrator::lpLogAccessName != "") {
        // check to see if there is a mutex associated with this file. if so, lock it. if not, just read file normally
        std::string fileName = targetFileName.substr(targetFileName.rfind("\\")+1);
        if (fileName == orchestrator::taskFilePath) {
            Locker fileLock(orchestrator::mMutexMap.at(orchestrator::lpTasksName));
            return readFile(targetFileName);
        }
        if (fileName == orchestrator::errorLogPath) {
            Locker fileLock(orchestrator::mMutexMap.at(orchestrator::lpELogAccessName));
            return readFile(targetFileName);
        }
        if (fileName == orchestrator::regLogPath) {
            Locker fileLock(orchestrator::mMutexMap.at(orchestrator::lpLogAccessName));
            return readFile(targetFileName);
        }
    }
    return readFile(targetFileName);
}

// read the target file as bytes, put bytes int char vector
std::vector<char> readEncryptedFile(std::string targetFile) {
    std::ifstream fileStream(targetFile, std::ios::binary);

    if (fileStream.good() && fileStream.is_open()) {
        std::vector<char> ciphertext ((std::istreambuf_iterator<char>(fileStream)), std::istreambuf_iterator<char>());
        return ciphertext;
    }

    return std::vector<char>();
}

// given absolute string path to a target file, put the contents of that file into a string and return it
// If there is a mutex associated with the target file, lock it before reading
// The calling function is expected to throw an error when this function returns an empty vector
std::vector<char> GetEncryptedFileContents(std::string targetFileName) {
    // check if config values have been populated
    if (orchestrator::lpLogAccessName != "") {
        // check to see if there is a mutex associated with this file. if so, lock it. if not, just read file normally
        std::string fileName = targetFileName.substr(targetFileName.rfind("\\")+1);
        if (fileName == orchestrator::taskFilePath) {
            Locker fileLock(orchestrator::mMutexMap.at(orchestrator::lpTasksName));
            return readEncryptedFile(targetFileName);
        }
        if (fileName == orchestrator::errorLogPath) {
            Locker fileLock(orchestrator::mMutexMap.at(orchestrator::lpELogAccessName));
            return readEncryptedFile(targetFileName);
        }
        if (fileName == orchestrator::regLogPath) {
            Locker fileLock(orchestrator::mMutexMap.at(orchestrator::lpLogAccessName));
            return readEncryptedFile(targetFileName);
        }
    }
    return readEncryptedFile(targetFileName);
}

// Helper function to get a value from a config file given that file's contents, the target section (ex:[NAME]), and the target setting (ex:iproc)
// Returns the string following the target setting
// The calling function is expected to throw an error when this function returns ""
std::string GetConfigValue(std::string targetSectionName, std::string targetSettingName, std::string configFileContents) {
    std::string configValue = "";
    std::string targetSectionFormatted = "[" + targetSectionName + "]";

    try {

        // find the beginning of the target section where the setting we want is
        int sectionBeginPos = configFileContents.find(targetSectionFormatted);
        if (sectionBeginPos == (int)std::string::npos) {
            return configValue;
        }

        // find the end of the target section where the setting we want is
        std::string targetSectionContents = configFileContents.substr(sectionBeginPos + targetSectionFormatted.length());
        int sectionEndPos = targetSectionContents.find("[");
        if (sectionEndPos == (int)std::string::npos) {
            sectionEndPos = targetSectionContents.length(); // if we can't find another section header, keep going as the target section might be the last
        }

        // parse the target section for the setting we want
        targetSectionContents = targetSectionContents.substr(0, sectionEndPos);
        std::stringstream ss(targetSectionContents);
        std::string token;
        while (getline(ss, token, '\n')) {
            trim(token);
            if (token.substr(0, targetSettingName.length()) == targetSettingName) {
                configValue = trimCopy(token.substr(token.find("=")+1)); // remove everything before and including "=", trim
                break;
            }
        }

    } catch (const std::exception& e) {
        util::logEncrypted(orchestrator::defaultErrorLogPath, "[ERROR-ORCH] GetConfigValue encountered error: " + std::string(e.what()));
        return "";
    }

    return configValue;
}

// attempt to extract an int from a string. if success, return true. if fail, return false
BOOL GetIntFromString(std::string targetString, int* num) {
    try {
        *num = stoi(targetString);
        return TRUE;
    } catch (...) {
        return FALSE;
    }
}

// given a LPCWSTR return the equivalent string
std::string LPCWSTRtoString(LPCWSTR string) {
    std::wstring ws(string);
    return std::string(ws.begin(), ws.end());
}

// given a string return the equivalent LPCWSTR
LPCWSTR StringtoLPCWSTR(std::string str) {
    std::wstring tmp = std::wstring(str.begin(), str.end());
    return tmp.c_str();
}

// given a vector of chars return the equivalent string
std::string VCharToStr(std::vector<char> vChar) {
    std::string s(vChar.begin(), vChar.end());
    return s;
}

// given a string return the equivalent vector of chars
std::vector<char> StrToVChar(std::string str) {
    std::vector<char> v(str.begin(), str.end());
    return v;
}

// actually output encrypted contents to a file
void outputEncrypted(std::string filePath, std::string message) {
    std::vector<char> outputCast = enc_handler::Cast128Encrypt(StrToVChar(message), orchestrator::key);

    std::ofstream file;
    file.open(filePath, std::ios::out | std::ios::binary);
    file.write((const char*)&outputCast[0], outputCast.size());
    file.close();
}

// intermediary to determine if we should append or just write to a file
void encryptOutput(std::string filePath, std::string message) {
    std::filesystem::path fsFilePath = filePath;

    // if the file doesn't exist, output normally
    if (!std::filesystem::exists(fsFilePath)) {
        outputEncrypted(filePath, message);
        return;
    }

    // if the file exists but is empty, output normally
    if (readEncryptedFile(filePath).empty()) {
        outputEncrypted(filePath, message);
        return;
    }

    // file should now exist and have content, so append
    // get the plaintext of what's already there
    std::string oldPlainText = VCharToStr(enc_handler::Cast128Decrypt(readEncryptedFile(filePath), orchestrator::key)) + "\n";

    // append to msg and then call actual output function
    outputEncrypted(filePath, oldPlainText + message);
}

// append the current time to the message and write it to the target file
void logNoMutex(std::string filePath, std::string message) {
    // get the current time and add it to the message
    std::time_t t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::string ts = std::ctime(&t);
    ts.resize(ts.size()-1);
    std::string output = ts + " | " + message;

    encryptOutput(filePath, output);
}

// log with the given mutex
void logMutex(std::string filePath, std::string message, std::string mutexName) {
    Locker fileLock(orchestrator::mMutexMap.at(mutexName));
    logNoMutex(filePath, message);
}

// Take a log message, encrypt it, and output it to the target file
// Also determine if that target file has an associated mutex
// If it does, lock that mutex before outputting
void logEncrypted(std::string filePath, std::string message) {

    // Spit out anything that gets logged. Needs to be removed for final release
    std::cout << "message: " + message + " | filePath: " + filePath << std::endl;

    if (!orchestrator::logMutexFlag){
        std::cout << "logmutexflag false" << std::endl;
        logNoMutex(filePath, message);
        return;
    }

    // if we're logging to either of the main log files, lock the corresponding mutex
    if (filePath == orchestrator::errorLogPath) {
        logMutex(filePath, message, orchestrator::lpELogAccessName);
    } else if (filePath == orchestrator::regLogPath) {
        logMutex(filePath, message, orchestrator::lpLogAccessName);
    } else {
        logNoMutex(filePath, message);
    }    
}

} //namespace util