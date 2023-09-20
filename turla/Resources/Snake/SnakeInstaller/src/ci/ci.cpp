#include <Windows.h>
#include <iostream>
#include <format>
#include <external/hde64/hde64.h>
#include "../common/handle.hpp"
#include "../common/string.hpp"
#include "ci.hpp"

namespace ci {

// Walk a PE header that has been mapped to memory and find the target export.
// Adapted from: https://github.com/v1k1ngfr/gdrv-loader/blob/master/src/pe.cpp
uintptr_t resolve_mapped_import(ULONG_PTR dllBase, PCSTR func) {
	// Validate that this is a PE.
	auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(dllBase);
	if (IMAGE_DOS_SIGNATURE != dos->e_magic) {
		return {};
	}

	// Validate that the NT header was parsed properly.
	auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(
		reinterpret_cast<std::byte*>(dllBase) + dos->e_lfanew
		);
	if (IMAGE_NT_SIGNATURE != nt->Signature) {
		return {};
	}

	auto optional = reinterpret_cast<PIMAGE_OPTIONAL_HEADER>(
		&nt->OptionalHeader
		);
	auto base = reinterpret_cast<PVOID*>(optional->ImageBase);

	// Get the export directory RVA and size.
	auto imageDir = optional->DataDirectory;
	auto exportDirRva = imageDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	auto exportDirSz = imageDir[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	// Read the export directory.
	auto exportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(dllBase + exportDirRva);
	auto funcsAddr = reinterpret_cast<PULONG>(dllBase + exportDir->AddressOfFunctions);
	auto namedOrdAddr = reinterpret_cast<PUSHORT>(dllBase + exportDir->AddressOfNameOrdinals);
	auto namesAddr = reinterpret_cast<PULONG>(dllBase + exportDir->AddressOfNames);

	// Look up the import name in the name table using a binary search.
	LONG low = 0;
	LONG middle = 0;
	LONG high = exportDir->NumberOfNames - 1;

	while (high >= low)
	{
		// Compute the next probe index and compare the import name.
		middle = (low + high) >> 1;
		const LONG Result = strcmp(func, reinterpret_cast<PCHAR>(dllBase + namesAddr[middle]));
		if (Result < 0)
			high = middle - 1;
		else if (Result > 0)
			low = middle + 1;
		else
			break;
	}

	// If the high index is less than the low index, then a matching table entry
	// was not found. Otherwise, get the ordinal number from the ordinal table
	if (high < low || middle >= static_cast<LONG>(exportDir->NumberOfFunctions))
		return {};
	const ULONG_PTR funcRva = funcsAddr[namedOrdAddr[middle]];
	if (funcRva >= exportDirRva && funcRva < exportDirRva + exportDirSz)
		return {}; // Ignore forwarded exports

	return dllBase + funcRva;
}


std::expected<common::unique_handle, common::windows_error>
get_file_handle(std::wstring file) {
	// Reading the file despite the Windows API name.
	common::unique_handle handle = ::CreateFileW(
		file.c_str(),
		GENERIC_READ,
		FILE_SHARE_READ,
		nullptr,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
		nullptr
	);
	if (!handle) {
		return std::unexpected{
			common::get_last_error(
				std::format(
					"Could not open {}",
					common::wstring_to_string(file)
		)) };
	}
	
	return handle;
}

std::expected<std::vector<std::byte>, common::windows_error>
read_file(std::wstring file) {
	auto handle = get_file_handle(file);
	if (!handle) {
		return std::unexpected(handle.error());
	}

	LARGE_INTEGER size{};
	if (!::GetFileSizeEx(handle.value().get(), &size)) {
		return std::unexpected{
			common::get_last_error(
				std::format(
					"Could not determine size of {}",
					common::wstring_to_string(file)
		)) };
	}
	else if (!size.QuadPart) {
		return std::unexpected{
			// Need a generic error type since this won't have a Windows error.
			common::get_last_error(
				std::format(
					"{} was empty",
					common::wstring_to_string(file)
		)) };
	}

	// Going to assume the system is 64 bit and reference the QuadPart.
	std::vector<std::byte> buf(size.QuadPart);
	OVERLAPPED ol{};
	if (!::ReadFileEx(
		handle.value().get(),
		buf.data(),
		size.QuadPart,
		&ol,
		nullptr
	)) {
		return std::unexpected{
			common::get_last_error(
				std::format(
					"Could not read {}",
					common::wstring_to_string(file)
		)) };
	}

	return buf;
}

// Parse a PE's headers to find its preferred base address.
// PE file documentation: https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
std::expected<void*, common::windows_error>
get_preferred_address(std::vector<std::byte>& pe) {
	HMODULE ntdll{ ::GetModuleHandleW(L"ntdll") };
	if (!ntdll) {
		return std::unexpected{
			common::get_last_error("Could not get handle to NTDLL")
		};
	}

	auto rtlinhe = reinterpret_cast<RtlImageNtHeaderEx_t>(
		::GetProcAddress(ntdll, "RtlImageNtHeaderEx")
	);
	if (!rtlinhe) {
		return std::unexpected{
			common::get_last_error("Could not resolve RtlImageNtHeaderEx")
		};
	}

	PIMAGE_NT_HEADERS ntHeaders{};
	NTSTATUS status = rtlinhe(
		0,
		pe.data(),
		pe.size(),
		&ntHeaders
	);
	if (NT_ERROR(status)) {
		return std::unexpected{
			common::ntstatus_to_error(
				status,
				"Could not parse CI.dll PE headers"
		) };
	}

	return reinterpret_cast<void*>(ntHeaders->OptionalHeader.ImageBase);
}

// Map a file to the specified address of a shared memory section.
// Section documentation: https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/section-objects-and-views
std::expected<void*, common::windows_error>
map_file(std::wstring file,	void* addr) {
	HMODULE ntdll{ ::GetModuleHandleW(L"ntdll") };
	if (!ntdll) {
		return std::unexpected{
			common::get_last_error("Could not get handle to NTDLL")
		};
	}

	auto ntcs = reinterpret_cast<NtCreateSection_t>(
		::GetProcAddress(ntdll, "NtCreateSection")
	);
	if (!ntcs) {
		return std::unexpected{
			common::get_last_error("Could not resolve NtCreateSection")
		};
	}

	auto handle = get_file_handle(file);
	if (!handle) {
		return std::unexpected{ handle.error() };
	}

	common::unique_handle section{};
	NTSTATUS status = ntcs(
		section.addressof(),
		STANDARD_RIGHTS_REQUIRED | SECTION_MAP_READ,
		nullptr,
		nullptr,
		PAGE_READONLY,
		SEC_IMAGE,
		handle.value().get()
	);
	if (NT_ERROR(status)) {
		return std::unexpected{
			common::ntstatus_to_error(status, "Could not create section")
		};
	}

	// Map the section view into our process.
	auto ntmvos = reinterpret_cast<NtMapViewOfSection_t>(
		::GetProcAddress(ntdll, "NtMapViewOfSection")
	);
	if (!ntmvos) {
		return std::unexpected{
			common::get_last_error("Could not resolve NtMapViewOfSection")
		};
	}

	size_t viewSz{};
	status = ntmvos(
		section.get(),
		::GetCurrentProcess(),
		&addr,
		0,
		0,
		nullptr,
		reinterpret_cast<PSIZE_T>(&viewSz),
		ViewUnmap,
		0,
		PAGE_READONLY
	);

	return addr;
}

// Calculate the address of the variable CI!g_ciOptions in kernel space. To
// accomplish this we need the base address of the CI kernel module and the
// base address of ci.dll once it has been mapped into memory. Then we walk
// the PE header to find the relative addresss of the ci.dll export
// CiInitialize.
// 
// The disassembly of CiInitialize can then be used to hunt for g_ciOptions.
// Assuming the function CipInitialize (no typo) is the 4th procedure call
// (opcode 0xE8) within CiInitialize. We can follow that address and again
// traverse the disassembly. CipInitialize should contain a reference to
// g_ciOptions bytes (0x0D89). Now that we have a relative offset we can
// calculate location of that variable in kernel space using the previously
// mentioned address.
//
// Reference code: https://github.com/v1k1ngfr/gdrv-loader/blob/master/src/swind2.cpp#L109
// Of note, I modified this to search for the 4th call (0xE8) because that was
// the earliest reference of CipInitialize within CiInitialize on Win 10 21H2.
void* resolve_ci_options(void* mapped_base, void* kernel_base) {
	ULONG c;
	LONG Rel = 0;
	hde64s hs;

	const PUCHAR CiInitialize = reinterpret_cast<PUCHAR>(
		resolve_mapped_import(reinterpret_cast<ULONG_PTR>(mapped_base), "CiInitialize")
		);
	if (CiInitialize == nullptr) {
		return 0;
	}

	c = 0;
	ULONG j = 0;
	do
	{
		// Search for the 2nd proceduce call on 1809
		if (CiInitialize[c] == 0xE8)
			j++;

		if (j > 1)
		{
			Rel = *reinterpret_cast<PLONG>(CiInitialize + c + 1);
			break;
		}

		hde64_disasm(CiInitialize + c, &hs);
		if (hs.flags & F_ERROR)
			break;
		c += hs.len;

	} while (c < 256);

	const PUCHAR CipInitialize = CiInitialize + c + 5 + Rel;
	c = 0;
	do
	{
		// Search for the CiOptionsAddress
		if (*reinterpret_cast<PUSHORT>(CipInitialize + c) == 0x0d89)
		{
			Rel = *reinterpret_cast<PLONG>(CipInitialize + c + 2);
			break;
		}
		hde64_disasm(CipInitialize + c, &hs);
		if (hs.flags & F_ERROR)
			break;
		c += hs.len;

	} while (c < 256);

	const PUCHAR MappedCiOptions = CipInitialize + c + 6 + Rel;

	return reinterpret_cast<void*>((uintptr_t)kernel_base + (uintptr_t)MappedCiOptions - (uintptr_t)(mapped_base));
}

std::expected<void*, common::windows_error> get_ci_options() {
	auto ci_path = L"C:\\Windows\\System32\\ci.dll";

	auto ci = read_file(ci_path);
	if (!ci) {
		return std::unexpected(ci.error());
	}

	auto preferred_addresss = get_preferred_address(ci.value());
	if (!preferred_addresss) {
		return std::unexpected(preferred_addresss.error());
	}

	auto mapped_base = map_file(ci_path, preferred_addresss.value());
	if (!mapped_base) {
		return std::unexpected(mapped_base.error());
	}

	auto mods = get_modules();
	if (!mods) {
		return std::unexpected(mods.error());
	}

	// Add error checking
	auto ci_options = resolve_ci_options(mapped_base.value(), mods.value()["CI.dll"]);
	if (!ci_options) {
		return std::unexpected{
			common::get_last_error(
				"Could not calculate offset to CI!g_ciOptions"
		) };
	}

	return ci_options;
}

} // namespace ci
