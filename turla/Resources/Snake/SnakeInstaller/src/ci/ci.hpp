#pragma once
#include <unordered_map>
#include "nt.hpp"

namespace ci {

std::expected<void*, common::windows_error> get_ci_options();

std::expected<void*, common::windows_error>
get_preferred_address(std::vector<std::byte>& pe);

std::expected<void*, common::windows_error>
map_file(std::wstring file, void* addr);

std::expected<std::vector<std::byte>, common::windows_error>
read_file(std::wstring file);

uintptr_t resolve_mapped_import(ULONG_PTR dll_base, PCSTR func);

void* resolve_ci_options(void* mapped_base, void* kernel_base);

} // namespace ci
