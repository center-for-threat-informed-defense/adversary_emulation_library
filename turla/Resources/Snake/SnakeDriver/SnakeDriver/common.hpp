#pragma once
#include <ntifs.h>

namespace common {

class QueuedSpinLock {
private:
    KSPIN_LOCK        m_lock{};
    KLOCK_QUEUE_HANDLE m_queue{};

public:
    void Init();
    void Lock();
    void Unlock();
};

template<typename Lock>
struct Locker {
private:
    Lock& m_lock{};

public:
    Locker(Lock& lock) : m_lock(lock) {
        m_lock.Lock();
    }

    ~Locker() {
        m_lock.Unlock();
    }
};

} // namespace common