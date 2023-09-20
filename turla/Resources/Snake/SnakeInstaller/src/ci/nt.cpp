#include <Windows.h>
#include <vector>
#include "nt.hpp"

namespace ci {

std::expected<std::map<std::string, bool>, common::windows_error>
get_settings() {
	ULONG len{};
	SYSTEM_CODEINTEGRITY_INFORMATION ci{ sizeof(SYSTEM_CODEINTEGRITY_INFORMATION) };
	NTSTATUS status = ::NtQuerySystemInformation(
		SystemCodeIntegrityInformation,
		&ci,
		sizeof(ci),
		&len
	);
	if (NT_ERROR(status)) {
		return std::unexpected{
			common::ntstatus_to_error(
				status,
				"Could not query Code Integrity settings"
		) };
	}

	std::map<std::string, bool> settings{};
	settings["Debug Mode"] = (ci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED);
	settings["Test Signing"] = (ci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_TESTSIGN);
	settings["Code Integrity"] = (ci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_ENABLED);
	settings["HVCI Kernel"] = (ci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED);
	settings["HVCI Strict Mode"] = (ci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_HVCI_KMCI_STRICTMODE_ENABLED);
	settings["HVCI User Mode"] = (ci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED);
	return settings;
}

// Enumerate kernel modules currently loaded by the system. This uses an
// undocumented SYSTEM_INFORMATION_CLASS called SystemModuleInformation to
// retrieve the base of address of each module in kernel space.
std::expected<std::map<std::string, void*>, common::windows_error>
get_modules() {
	ULONG len{};
	::NtQuerySystemInformation(
		(SYSTEM_INFORMATION_CLASS)0xb,
		nullptr,
		0,
		&len
	);

	std::vector<std::byte> buffer(len);
	NTSTATUS status = ::NtQuerySystemInformation(
		(SYSTEM_INFORMATION_CLASS)0xb,
		buffer.data(),
		len,
		&len
	);
	if (NT_ERROR(status)) {
		return std::unexpected{
			common::ntstatus_to_error(
				status,
				"Failed to enumerate kernel modules"
		) };
	}

	std::map<std::string, void*> addresses{};
	auto module_info{ reinterpret_cast<PSYSTEM_MODULE_INFORMATION>(buffer.data()) };
	for (ULONG i = 0; i < module_info->ModulesCount; i++) {
		SYSTEM_MODULE module = module_info->Modules[i];
		auto name = static_cast<char*>(module.Name) + module.NameOffset;
		auto addr = reinterpret_cast<void*>(module.ImageBaseAddress);
		addresses[name] = addr;
	}
	return addresses;
}

} // namespace ci