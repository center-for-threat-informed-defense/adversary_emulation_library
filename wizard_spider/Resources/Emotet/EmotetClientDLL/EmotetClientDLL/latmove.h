#include "pch.h"
#include "stdio.h"
#include <tchar.h>
#include <iostream>
#include <tlhelp32.h>
#include <string>
#include <array>
#include <memory>
#include <cstdio>
#include "comms.h"

#ifndef LATMOVE_H
#define LATMOVE_H

#ifdef LATMOVE_H
#define LATMOVE_H __declspec(dllexport)
#else
#define LATMOVE_H __declspec(dllimport)
#endif

typedef string(__cdecl* ExecuteLatMovementCmdPtr)(string);

// functions
LATMOVE_H bool loadLatMovementModule(EmotetComms*, string);
LATMOVE_H bool executeLatMovementCmd(EmotetComms*, string);

#endif