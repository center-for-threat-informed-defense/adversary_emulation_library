// File: dllmain.h
//
#include "stdio.h"
#include <iostream>

#ifndef INDLL_H
#define INDLL_H

#ifdef EXPORTING_DLL
extern "C" __declspec(dllexport) bool Control_RunDLL();
#else
extern "C" __declspec(dllimport) bool Control_RunDLL();
#endif

#endif