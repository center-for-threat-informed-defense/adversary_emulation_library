#pragma once
#include <Windows.h>
#include <sddl.h>
#include <expected>
#include <string>
#include "../common/error.hpp"

namespace resource {

std::expected<void, common::windows_error>
drop(int id, std::wstring path, HMODULE pe = nullptr);

std::expected<std::wstring, common::windows_error>
create_directory(const std::wstring& dir);

// Define the SDDL for the DACL. This example sets 
// the following access:
//     Built-in guests are denied all access.
//     Anonymous logon is denied all access.
//     Authenticated users are allowed 
//     read/write/execute access.
//     Administrators are allowed full control.
// Modify these values as needed to generate the proper
// DACL for your application. 
std::expected<SECURITY_ATTRIBUTES, common::windows_error> create_dacl();
}
