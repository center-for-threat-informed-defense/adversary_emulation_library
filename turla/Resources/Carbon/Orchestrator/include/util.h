#ifndef UTIL_H_
#define UTIL_H_

#include <windows.h>
#include <string>
#include <filesystem>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <vector>
#include <iterator>
#include <chrono>
#include <codecvt>
#include "base64.h"
#include "..\include\orchestrator.h"

// contains helper functions for the rest of the orchestrator

namespace util {

std::string BuildFilePath(std::string targetFile);
void leftTrim(std::string &str);
void rightTrim(std::string &str);
void trim(std::string &str);
std::string trimCopy(std::string str);
std::string readFile(std::string targetFileName);
std::string GetStringContentsFromFile(std::string targetFileName);
std::vector<char> readEncryptedFile(std::string targetFile);
std::vector<char> GetEncryptedFileContents(std::string targetFileName);
std::string GetConfigValue(std::string targetSectionName, std::string targetSettingName, std::string configFileContents);
BOOL GetIntFromString(std::string targetString, int* num);
std::string LPCWSTRtoString(LPCWSTR string);
LPCWSTR StringtoLPCWSTR(std::string str);
std::string VCharToStr(std::vector<char> vChar);
std::vector<char> StrToVChar(std::string str);
void encryptOutput(std::string filePath, std::string message);
void logEncrypted(std::string filePath, std::string message);

} // namespace util
#endif