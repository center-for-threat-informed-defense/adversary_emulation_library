#include "../include/locker.h"

// Whenever a Locker struct is created, it will gain ownership of a mutex
// for the scope of the function it was created in.

// Will initialize an unowned and unnamed mutex by default.
Mutex::Mutex(const wchar_t* name, bool owner) {
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;

    std::string dacl_str = std::string("D:") + // Discretionary ACL
        "(D;OICI;GA;;;BG)" +      // Deny access to built-in guests
        "(D;OICI;GA;;;AN)" +      // Deny access to anonymous logon
        "(A;OICI;GRGWGX;;;AU)" +  // Allow RWX to authenticated users
        "(A;OICI;GA;;;BA)";       // Allow full control to administrators

    ConvertStringSecurityDescriptorToSecurityDescriptor(
        dacl_str.c_str(),
        SDDL_REVISION_1,
        &(sa.lpSecurityDescriptor),
        NULL
    );

    m_mutex = ::CreateMutexW(&sa, owner, name);

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