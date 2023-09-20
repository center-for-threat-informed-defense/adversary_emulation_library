#pragma once
#include <Windows.h>

class Mutex {
public:
    Mutex(const wchar_t* name = nullptr, bool owner = false);
    ~Mutex();
    void lock();
    void unlock();

private:
    HANDLE m_mutex{};
};

template<typename Lock>
struct Locker {
    Locker(Lock& lock) : m_lock(lock) {
        m_lock.lock();
    }

    ~Locker() {
        m_lock.unlock();
    }

private:
    Lock& m_lock{};
};