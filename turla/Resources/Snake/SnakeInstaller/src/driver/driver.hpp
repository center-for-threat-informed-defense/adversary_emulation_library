#pragma once
#include <Windows.h>
#include <optional>
#include <expected>
#include "../common/error.hpp"
#include "../common/handle.hpp"

namespace driver {

extern SC_HANDLE g_sc_manager;

// Wraps the Windows API functions required to manage a driver service. It is
// initialized using the named constructor driver::create.
class driver {
protected:
    std::wstring             m_path{}; 
    std::wstring             m_name{}; 
    common::unique_sc_handle m_sc_mgr{};
    common::unique_sc_handle m_service{};

public:
    driver(const std::wstring& path, const std::wstring& name);

    // Creates a driver kernel service using the Service Control Manager.
    // Start type documentation: https://docs.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew#parameters
    //
    // sc.exe <service_name> create type= kernel binPath= C:\pathto\driver.sys
    static std::expected<std::unique_ptr<driver>, common::windows_error> create(
        const std::wstring& path,
        const std::wstring& name,
        const DWORD start_t = SERVICE_DEMAND_START
    );

    std::optional<common::windows_error> remove();
    std::optional<common::windows_error> start();
    std::optional<common::windows_error> stop();

    // Gets the current status of a service.
    // Return struct documentation: https://docs.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_status_process
    std::expected<SERVICE_STATUS_PROCESS, common::windows_error>
    get_status() const;
};

} // namespace driver