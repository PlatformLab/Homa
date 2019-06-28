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

#include "Intrusive.h"

namespace Homa {
namespace Core {

/**
 * Intrusive structure to keep track of a per object timeout.
 *
 * This structure is not thread-safe.
 */
template <typename ElementType>
struct Timeout {
    /**
     * Initialize this Timeout, associating it with a particular object.
     *
     * @param owner
     *      Pointer to the object associated with this Timeout.
     */
    explicit Timeout(ElementType* owner)
        : expirationCycleTime(0)
        , node(owner)
    {}

    /**
     * Return true if this Timeout has elapsed; false otherwise.
     */
    bool hasElapsed()
    {
        return PerfUtils::Cycles::rdtsc() >= expirationCycleTime;
    }

    /// Cycle timestamp when timeout should elapse.
    uint64_t expirationCycleTime;
    /// Intrusive member to help track this timeout.
    typename Intrusive::List<ElementType>::Node node;
};

/**
 * Structure to keep track of multiple instances of the same kind of timeout.
 *
 * This structure is not thread-safe.
 */
template <typename ElementType>
struct TimeoutManager {
    /**
     * Construct a new TimeoutManager with a particular timeout interval.  All
     * timeouts tracked by this manager will have the same timeout interval.
     *
     */
    explicit TimeoutManager(uint64_t timeoutIntervalCycles)
        : timeoutIntervalCycles(timeoutIntervalCycles)
        , list()
    {}

    /**
     * Schedule the Timeout to elapse one timeout interval from this point.  If
     * the Timeout was previously scheduled, this call will reschedule it.
     *
     * @param timeout
     *      The Timeout that should be scheduled.
     */
    void setTimeout(Timeout<ElementType>* timeout)
    {
        list.remove(&timeout->node);
        timeout->expirationCycleTime =
            PerfUtils::Cycles::rdtsc() + timeoutIntervalCycles;
        list.push_back(&timeout->node);
    }

    /**
     * Cancel the Timeout if it was previously scheduled.
     *
     * @param timeout
     *      The Timeout that should be canceled.
     */
    void cancelTimeout(Timeout<ElementType>* timeout)
    {
        list.remove(&timeout->node);
    }

    /// The number of cycles this newly scheduled timeouts would wait before
    /// they elapse.
    uint64_t timeoutIntervalCycles;
    /// Used to keep track of all timeouts under management.
    Intrusive::List<ElementType> list;
};

}  // namespace Core
}  // namespace Homa

#endif  // HOMA_CORE_INTERVALTIMER_H
