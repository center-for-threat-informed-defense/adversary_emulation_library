#include "common.hpp"

namespace common {

void QueuedSpinLock::Init() {
    ::KeInitializeSpinLock(&m_lock);
}

void QueuedSpinLock::Lock() {
    ::KeAcquireInStackQueuedSpinLock(&m_lock, &m_queue);
}

void QueuedSpinLock::Unlock() {
    ::KeReleaseInStackQueuedSpinLock(&m_queue);
}

} // namespace common