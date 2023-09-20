#include <Windows.h>
#include <sddl.h>
#include <string>

class Mutex {
public:
    Mutex(const wchar_t* name = nullptr, bool owner = false);
    ~Mutex();
    void lock();
    void unlock();

    // add operator function to work with maps
    bool operator<(const Mutex& mtx) const {
        return mtx.m_mutex < this->m_mutex;
    }

private:
    HANDLE m_mutex{};
};

// Whenever a Locker struct is created, it will gain ownership of a mutex
// for the scope of the function it was created in.

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