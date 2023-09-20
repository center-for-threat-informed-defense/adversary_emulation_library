#pragma once

// debugging ifdefs and printouts, swap to 0 when done testing
#ifdef DEBUG_PRINT
#define kprintf(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, __VA_ARGS__)
#else
#define kprintf(...) 
#endif

// If anything is OS version dependent, make sure it is associated with the correct preprocessor definition. Ex: WIN10_1809, WIN10_1903

extern char gSysModName[9];
#define SYSTEM_MODULE_NAME gSysModName

// Enumerate all registry keys, so that our InfinityHook hooks know what to block access to
// NtEnumerateKey expects base key names, whereas NtOpenKey expects (almost) fully qualified names
// defined and set in driver.h
#define NUM_REGKEYS 1
extern PWSTR gRegKeys[NUM_REGKEYS];
#define NUM_REGKEYS_FULLPATH 1
extern PWSTR gRegKeysFullPath[NUM_REGKEYS_FULLPATH];

// Enumerate all files to which we will deny access
#define NUM_FILES 1
extern PWSTR gFiles[NUM_FILES];
#define NUM_FILES_FULLPATH 1
extern PWSTR gFilesFullPath[NUM_FILES_FULLPATH];
