#pragma once
#include <Windows.h>
#include <memory>

namespace common{

template<
	typename Handle,
	typename Closer,
	Closer close,
	typename Invalid = Handle,
	Invalid invalid = Invalid{}
>
class unique_handle_t {
	Handle m_handle;

public:
	unique_handle_t(const unique_handle_t&) = delete;
	unique_handle_t& operator=(const unique_handle_t&) = delete;

	unique_handle_t() : m_handle{ invalid } {}
	unique_handle_t(Handle handle) : m_handle{ handle } {}

	unique_handle_t(unique_handle_t&& other) noexcept :
		m_handle{ other.release() } {
	}

	~unique_handle_t() {
		if (is_valid()) {
			close(m_handle);
		}
	}

	Handle  get() const { return m_handle; }
	Handle* addressof() { return &m_handle; }

	bool is_valid() const {
		return m_handle != invalid;
	}

	void reset(Handle handle = invalid) {
		if (is_valid()) {
			close(m_handle);
		}
		m_handle = handle;
	}

	void replace(unique_handle_t &&other) {
		reset(other.m_handle);
		other.m_handle = invalid;
	}

	Handle release() {
		Handle tmp = m_handle;
		m_handle = invalid;
		return tmp;
	}

	explicit operator bool() const {
		return is_valid();
	}

	unique_handle_t& operator=(unique_handle_t&& other) {
		if (this != std::addressof(other)) {
			replace(std::move(other));
		}
		return *this;
	}
};

using unique_handle = unique_handle_t<
	HANDLE,
	decltype(&::CloseHandle),
	::CloseHandle,
	HANDLE,
	INVALID_HANDLE_VALUE
>;

using unique_hmodule = unique_handle_t<
	HMODULE,
	decltype(&::FreeLibrary),
	::FreeLibrary,
	nullptr_t
>;

inline void nop_closer([[maybe_unused]] SC_HANDLE h) {}

using unique_sc_handle = unique_handle_t<
	SC_HANDLE,
	decltype(&nop_closer),
	nop_closer,
	nullptr_t
>;

} // namespace common
