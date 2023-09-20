#ifndef MUTEX_H_
#define MUTEX_H_

#include <windows.h>
#include <map>
#include <vector>
#include <fstream>
#include <map>
#include <sddl.h>
#include <sstream>
#include "../include/orchestrator.h"

namespace mutex {

extern std::vector<std::string> vMutexNames; // vector to hold the names of the mutexes we'll create

// populate vMutexNames with values from the config
void PopulateNamesVector();

int CreateMutexes();

// main part of the mutex portion that calls other functions, the "main" function
int MutexManager();

} //namespace mutex

#endif