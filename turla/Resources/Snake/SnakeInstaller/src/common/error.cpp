#include "error.hpp"
#include "string.hpp"
#include "handle.hpp"

namespace common {

std::wstring windows_error::w_what() const {
	return string_to_wstring(what());
}

std::wstring windows_error_code::w_message() const {
	return string_to_wstring(message());
}

const windows_error get_last_error(std::string prefix) {
	if (prefix.empty()) {
		return windows_error{
			static_cast<int>(::GetLastError()),
			std::system_category()
		};
	}
	else {
		return windows_error{
			static_cast<int>(::GetLastError()),
			std::system_category(),
			prefix
		};
	}
}

const windows_error get_last_error(const std::error_category& cat, std::string prefix) {
	if (prefix.empty()) {
		return windows_error{
			static_cast<int>(::GetLastError()),
			cat
		};
	}
	else {
		return windows_error{
			static_cast<int>(::GetLastError()),
			cat,
			prefix
		};
	}
}

const windows_error ntstatus_to_error(const NTSTATUS status, std::string prefix) {
	if (prefix.empty()) {
		return windows_error{
			static_cast<int>(status),
			ntdll_category()
		};
	}
	else {
		return windows_error{
			static_cast<int>(status),
			ntdll_category(),
			prefix
		};
	}
}

const char* ntdll_category::name() const noexcept{
	return "NTDLL";
}

std::string ntdll_category::message(int status) const {
	HMODULE ntdll{ ::GetModuleHandleW(L"ntdll") };
	if (!ntdll) {
		return std::to_string(status);
	}
	return wstring_to_string(get_error_message(status, ntdll));
}

const std::wstring get_error_message(const DWORD code) {
	PWSTR p{};
	auto len = ::FormatMessageW(
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		nullptr,
		code,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		reinterpret_cast<PWSTR>(&p),
		0,
		nullptr
	);

	std::unique_ptr<wchar_t, decltype(&::LocalFree)> buf(p, ::LocalFree);
	if (0 == len) {
		return std::to_wstring(code);
	}
	return std::wstring{ buf.get(), len };
}

const std::wstring get_error_message(const DWORD code, const HMODULE dll) {
	PWSTR p{};
	auto len= ::FormatMessageW(
		FORMAT_MESSAGE_FROM_HMODULE |
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		dll,
		code,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		reinterpret_cast<PWSTR>(&p),
		0,
		nullptr
	);

	std::unique_ptr<wchar_t, decltype(&::LocalFree)> buf(p, ::LocalFree);
	if (0 == len) {
		return std::to_wstring(code);
	}
	return std::wstring{ buf.get(), len };
}

} // namespace common
