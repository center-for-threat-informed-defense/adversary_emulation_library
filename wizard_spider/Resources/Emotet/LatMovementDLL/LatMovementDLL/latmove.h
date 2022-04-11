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

#ifndef LATMOVE_H
#define LATMOVE_H

#ifdef LATMOVE
#define LATMOVE __declspec(dllexport)
#else
#define LATMOVE __declspec(dllimport)
#endif

// Exported functions
extern "C" LATMOVE std::string __cdecl ExecuteLatMovementCmd(std::string);

#endif