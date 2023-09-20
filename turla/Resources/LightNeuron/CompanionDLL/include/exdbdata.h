#ifndef UNICODE
#define UNICODE
#endif 

#ifndef __EXRWDB_H__
#define __EXRWDB_H__

#include <windows.h>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <string>
#include <sysinfoapi.h>
#include <sstream>
#include "pugixml.hpp"
#include "stego.h"


namespace data_transform
{
    struct mail {
        char* name;
        int totalRecipients;
        char** recipients;
        int totalAttachments;
        char** attachmentFileNames;
        char** attachmentContents;
        char* subject;
        char* body;
    };
    struct config {
        std::string EMAIL_LOG_FILE;
        std::string SIGNATURE_KEY;
        std::string RULE_FILE;
        std::string FROM;
        std::string SUBJECT;
        std::string TO;
    };

    extern config conf;


    extern "C" __declspec (dllexport) int MessageValidator(mail * s);
    void parse_config_file(std::string config_path);
    int checkAttachment(mail &mailItem);
    void sendMessage(mail &mailItem);
    int logMessage(mail &mailItem, std::string zip_file_path);
    int checkSubstring(std::string str1, std::string str2);
    bool checkConditions(pugi::xml_node rule, mail &mail);
    int processXMLRules(std::string RULE_FILE, mail &mail);

}

#endif