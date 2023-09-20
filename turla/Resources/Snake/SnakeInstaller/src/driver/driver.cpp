#pragma once
#include <chrono>
#include <thread>
#include <format>
#include "../common/string.hpp"
#include "driver.hpp"

namespace driver {

// Path can be relative but will be expanded for use by SCManager.
driver::driver(const std::wstring& path, const std::wstring& name) :
    m_path{ path },
    m_name{ name }
{}

// Start type defaults to SERVICE_DEMAND_START if not specified.
std::expected<std::unique_ptr<driver>, common::windows_error> driver::create(
    const std::wstring& path,
    const std::wstring& name,
    DWORD start_t
) {
    // If GetFullPathName is called with a buffer size less than what it needs
    // it will return the length needed.
    std::vector<wchar_t> buf{}; // Can this be switched to a string? I think .data() is non const
    auto len = ::GetFullPathNameW(
        path.c_str(),
        buf.size(),
        buf.data(),
        nullptr 
    );

    buf.resize(len);
    len = ::GetFullPathNameW(
        path.c_str(),
        buf.size(),
        buf.data(),
        nullptr
    );

    auto as = ::GetFileAttributesW(buf.data());
    if ((INVALID_FILE_ATTRIBUTES == as) || (FILE_ATTRIBUTE_DIRECTORY == as)) {
        return std::unexpected{
            common::get_last_error(
                std::format(
                    "Could not find {}",
                    common::wstring_to_string(path)
        )) };
    }

    auto d = std::make_unique<driver>(buf.data(), name);

    d->m_service.reset(::CreateServiceW(
        g_sc_manager,
        d->m_name.c_str(),      // Service name
        d->m_name.c_str(),      // Display name
        SERVICE_ALL_ACCESS,    // Can the privileges of our handle be reduced?
        SERVICE_KERNEL_DRIVER,
        start_t,
        SERVICE_ERROR_IGNORE,  // Possibly reduces event logs
        d->m_path.c_str(),
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr
    ));
    if (!d->m_service) {
        return std::unexpected{
            common::get_last_error(
                std::format(
                    "Could not create {} service",
                    common::wstring_to_string(d->m_name)
        )) };
    }

    return d;
}

// Marks the driver service for deletion without blocking.
std::optional<common::windows_error> driver::remove() {
    if (!m_service) {
        // Need program error category
        return std::nullopt;
    }
    
    if (!::DeleteService(m_service.get())) {
        return common::get_last_error(
            std::format(
                "Could not delete {} service",
                common::wstring_to_string(m_name) 
        ));
    }
    return std::nullopt;
}

/*
 * driver::start():
 *      About:
 *          Start the driver. Will block until the service is running or the request times out.
 *      Result:
 *          Returns any errors.
 *      MITRE ATT&CK Techniques:
 *          T1543.003: Create or Modify System Process: Windows Service
 *      CTI:
 *          https://www.coresecurity.com/core-labs/advisories/virtualbox-privilege-escalation-vulnerability
 *          https://unit42.paloaltonetworks.com/acidbox-rare-malware/
 *          https://artemonsecurity.com/snake_whitepaper.pdf
 *      Other References:
 *          https://docs.microsoft.com/en-us/windows/win32/services/starting-a-service
 */
std::optional<common::windows_error> driver::start() {
    if (!::StartServiceW(
        m_service.get(),
        0,
        nullptr
    )) {
        return common::get_last_error(
            std::format(
                "Could not start {} service",
                common::wstring_to_string(m_name) 
        ));
    }

    auto ss = get_status();
    if (!ss) {
        return ss.error();
    }

    DWORD wait{};
    auto aliveTime = ::GetTickCount64();
    auto oldCheckpoint = ss.value().dwCheckPoint;

    while (SERVICE_START_PENDING == ss.value().dwCurrentState) {
        // Microsoft suggests one tenth the suggested wait time.
        wait = ss.value().dwWaitHint / 10;

        // Wait no less than 1 second and no more than 10.
        if (wait < 1000) {
            wait = 1000;
        }
        else if (wait > 10000) {
            wait = 10000;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(wait));

        ss = get_status();
        if (ss.value().dwCheckPoint > oldCheckpoint) {
            aliveTime = ::GetTickCount64();
            oldCheckpoint = ss.value().dwCheckPoint;
        }
        else if (::GetTickCount64() - aliveTime > ss.value().dwWaitHint) {
            // need generic program error, probably no GetLastError code
            return common::get_last_error(
                std::format(
                    "{} service timed out while starting",
                    common::wstring_to_string(m_name) 
            ));
        }
    }
    return std::nullopt;
}

// SERVICE_STATUS_PROCESS returns a state of SERVICE_STOP_PENDING. However,
// dwCheckpoint and dwWaitHint both return zero which should mean the action
// is immediate. If this causes a race in the future, consider blocking until
// state returns SERVICE_STOPPED.
std::optional<common::windows_error> driver::stop() {
    if (!m_service) {
        // need program error category
        return std::nullopt;
    }

    SERVICE_STATUS_PROCESS ss{};
    if (!::ControlService(
        m_service.get(),
        SERVICE_CONTROL_STOP,
        reinterpret_cast<LPSERVICE_STATUS>(&ss)
    )) {
        return common::get_last_error(
            std::format(
                "Could not delete {} service",
				common::wstring_to_string(m_name) 
        ));
    }
    return std::nullopt;
}

// Uses the handle of a service to get its status.
std::expected<SERVICE_STATUS_PROCESS, common::windows_error>
driver::get_status() const {
    SERVICE_STATUS_PROCESS ss{};

    // There's a newer QueryServiceStatusEx but it requires a dynamic buffer.
    // Keeping it old school for now.
    if (!::QueryServiceStatus(
        m_service.get(),
        reinterpret_cast<LPSERVICE_STATUS>(&ss)
    )) {
        return std::unexpected{
            common::get_last_error(
                std::format(
                    "Could not query status of {} service",
					common::wstring_to_string(m_name) 
        )) };
    }
    return ss;
}
} // namespace driver
