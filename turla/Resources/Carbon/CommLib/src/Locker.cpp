#include "Locker.hpp"

// Will initialize an unowned and unnamed mutex by default.
Mutex::Mutex(const wchar_t* name, bool owner) {
    m_mutex = ::CreateMutexW(nullptr, owner, name);
}

Mutex::~Mutex() {
    ::CloseHandle(m_mutex);
}

void Mutex::lock() {
    ::WaitForSingleObject(m_mutex, INFINITE);
}

void Mutex::unlock() {
    ::ReleaseMutex(m_mutex);
}