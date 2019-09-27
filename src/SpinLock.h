/* Copyright (c) 2011-2018, Stanford University
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef HOMA_SPINLOCK_H
#define HOMA_SPINLOCK_H

#include <atomic>
#include <mutex>

namespace Homa {

/**
 * This class implements a lock that will never cause an std::thread to block
 * (i.e. sleep) if the lock is unavailable.  Instead the SpinLock will busy-wait
 * for the lock to become available. The SpinLock is intended to enforce short
 * periods of mutual exclusion where the lock is not held for very long. These
 * locks are not recursive; if the same thread tries to lock a SpinLock while
 * holding it, the thread will deadlock.
 *
 * This class implements the C++ "Lockable" named requirement.
 */
class SpinLock {
  private:
    /// Implements the lock: False means free, True means locked.
    // _mutex_ must be initialized here since it seems the C++11 standard has
    // not yet agree on whether the ATOMIC_FLAG_INIT macro can be used in an
    // initializer list (July 2018).
    std::atomic_flag flag = ATOMIC_FLAG_INIT;

  public:
    /**
     * Create a new unlocked SpinLock.
     */
    explicit SpinLock()
    {
        // It should have already been initialized to false but we clear it here
        // just in case.
        flag.clear();
    }

    /**
     * Destroy the SpinLock regardless of its current state.
     */
    ~SpinLock() {}

    /**
     * Acquire the SpinLock; blocks the thread (by continuously polling the
     * lock) until the lock has been acquired.
     */
    void lock()
    {
        // test_and_set sets the flag to true and returns the previous value;
        // if it's True, someone else is owning the lock.
        while (flag.test_and_set(std::memory_order_acquire))
            ;
    }

    /**
     * Try to acquire the SpinLock; does not block the thread and returns
     * immediately.
     *
     * @return
     *      True if the lock was successfully acquired, false if it was already
     *      owned by some other thread.
     */
    bool try_lock()
    {
        // test_and_set sets the flag to true and returns the previous value;
        // if it's True, someone else is owning the lock.
        return !flag.test_and_set(std::memory_order_acquire);
    }

    /**
     * Release the SpinLock.  The caller must previously have acquired the
     * SpinLock with a call to lock() or try_lock().
     */
    void unlock()
    {
        flag.clear();
    }

    /**
     * Define a type alias for an RAII SpinLock lock_guard for convenience.
     */
    using Lock = std::lock_guard<SpinLock>;

    /**
     * Define a type alias for a movable SpinLock unique_lock for convenience.
     */
    using UniqueLock = std::unique_lock<SpinLock>;

  private:
    // Disable copy and assign
    SpinLock(const SpinLock&) = delete;
    SpinLock& operator=(const SpinLock&) = delete;
};

}  // namespace Homa

#endif  // HOMA_SPINLOCK_H