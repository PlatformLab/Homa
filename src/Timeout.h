/* Copyright (c) 2019, Stanford University
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

#ifndef HOMA_CORE_INTERVALTIMER_H
#define HOMA_CORE_INTERVALTIMER_H

#include <Cycles.h>

#include <atomic>

#include "Intrusive.h"

namespace Homa {
namespace Core {

// Forward declaration.
template <typename ElementType>
class TimeoutManager;

/**
 * Intrusive structure to keep track of a per object timeout.
 *
 * This structure is not thread-safe.
 */
template <typename ElementType>
class Timeout {
  public:
    /**
     * Initialize this Timeout, associating it with a particular object.
     *
     * @param owner
     *      Pointer to the object associated with this Timeout.
     */
    explicit Timeout(ElementType* owner)
        : expirationCycleTime(0)
        , owner(owner)
        , node(this)
    {}

    /**
     * Return true if this Timeout has elapsed; false otherwise.
     *
     * @param now
     *      Optionally provided "current" timestamp cycle time. Used to avoid
     *      unnecessary calls to PerfUtils::Cycles::rdtsc() if the current time
     *      is already available to the caller.
     */
    inline bool hasElapsed(uint64_t now = PerfUtils::Cycles::rdtsc())
    {
        return now >= expirationCycleTime;
    }

  private:
    /// Cycle timestamp when timeout should elapse.
    uint64_t expirationCycleTime;

    /// Pointer to the object that is associated with this timeout.
    ElementType* owner;

    /// Intrusive member to help track this timeout.
    typename Intrusive::List<Timeout<ElementType>>::Node node;

    friend class TimeoutManager<ElementType>;
};

/**
 * Structure to keep track of multiple instances of the same kind of timeout.
 *
 * This structure is not thread-safe.
 */
template <typename ElementType>
class TimeoutManager {
  public:
    /**
     * Construct a new TimeoutManager with a particular timeout interval.  All
     * timeouts tracked by this manager will have the same timeout interval.
     *
     */
    explicit TimeoutManager(uint64_t timeoutIntervalCycles)
        : timeoutIntervalCycles(timeoutIntervalCycles)
        , nextTimeout(UINT64_MAX)
        , list()
    {}

    /**
     * Schedule the Timeout to elapse one timeout interval from this point.  If
     * the Timeout was previously scheduled, this call will reschedule it.
     *
     * @param timeout
     *      The Timeout that should be scheduled.
     */
    inline void setTimeout(Timeout<ElementType>* timeout)
    {
        list.remove(&timeout->node);
        timeout->expirationCycleTime =
            PerfUtils::Cycles::rdtsc() + timeoutIntervalCycles;
        list.push_back(&timeout->node);
        nextTimeout.store(list.front().expirationCycleTime,
                          std::memory_order_relaxed);
    }

    /**
     * Cancel the Timeout if it was previously scheduled.
     *
     * @param timeout
     *      The Timeout that should be canceled.
     */
    inline void cancelTimeout(Timeout<ElementType>* timeout)
    {
        list.remove(&timeout->node);
        if (list.empty()) {
            nextTimeout.store(UINT64_MAX, std::memory_order_relaxed);
        } else {
            nextTimeout.store(list.front().expirationCycleTime,
                              std::memory_order_relaxed);
        }
    }

    /**
     * Check if any managed Timeouts have elapsed.
     *
     * This method is thread-safe but may race with the other
     * non-thread-safe methods of the TimeoutManager (e.g. concurrent calls
     * to setTimeout() or cancelTimeout() may not be reflected in the result
     * of this method call).
     *
     * @param now
     *      Optionally provided "current" timestamp cycle time. Used to
     * avoid unnecessary calls to PerfUtils::Cycles::rdtsc() if the current
     * time is already available to the caller.
     */
    inline bool anyElapsed(uint64_t now = PerfUtils::Cycles::rdtsc())
    {
        return now >= nextTimeout.load(std::memory_order_relaxed);
    }

    /**
     * Check if the TimeoutManager manages no Timeouts.
     *
     * @return
     *      True, if there are no Timeouts being managed; false, otherwise.
     */
    inline bool empty() const
    {
        return list.empty();
    }

    /**
     * Return a reference the managed timeout element that expires first.
     *
     * Calling front() an empty TimeoutManager is undefined.
     */
    inline ElementType& front()
    {
        return *list.front().owner;
    }

    /**
     * Return a const reference the managed timeout element that expires
     * first.
     *
     * Calling front() an empty TimeoutManager is undefined.
     */
    inline const ElementType& front() const
    {
        return *list.front().owner;
    }

  private:
    /// The number of cycles this newly scheduled timeouts would wait before
    /// they elapse.
    uint64_t timeoutIntervalCycles;

    /// The smallest timeout expiration time of all timeouts under
    /// management. Accessing this value is thread-safe.
    std::atomic<uint64_t> nextTimeout;

    /// Used to keep track of all timeouts under management.
    Intrusive::List<Timeout<ElementType>> list;
};

}  // namespace Core
}  // namespace Homa

#endif  // HOMA_CORE_INTERVALTIMER_H
