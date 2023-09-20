/*
 * Handle file operation
 */

#ifndef SNAKE_USERLAND_FILE_HANDLER_H_
#define SNAKE_USERLAND_FILE_HANDLER_H_

#include <windows.h>
#include <errhandlingapi.h>
#include <string>
#include <fstream>
#include <iostream>
#include <filesystem>
#include <vector>
#include <stdio.h>
#include "usermodule_errors.h"
#include "api_wrappers.h"

#define QUOTE_HOME_DIRECTORY(X) L ## #X
#define EXPAND_AND_QUOTE_HOME_DIR(X) QUOTE_HOME_DIRECTORY(X)
#ifndef HOME_DIR
#define HOME_DIRECTORY L"C:\\Users\\Public"
#else
#define HOME_DIRECTORY EXPAND_AND_QUOTE_HOME_DIR(HOME_DIR)
#endif

namespace file_handler {

std::wstring GetFileNameFromPath(std::wstring path);

DWORD ReadFileBytes(ApiWrapperInterface* api_wrapper, HANDLE h_file, char* buffer, DWORD file_size);

DWORD WriteFileBytes(ApiWrapperInterface* api_wrapper, HANDLE h_file, unsigned char* buffer, DWORD buffer_len);

} // namespace file_handler

#endif
