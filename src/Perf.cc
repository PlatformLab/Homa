/* Copyright (c) 2020, Stanford University
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

#include "Perf.h"

#include <mutex>
#include <unordered_set>

namespace Homa {
namespace Perf {

namespace Internal {

/**
 * Protects access to globalCounters and perThreadCounters
 */
std::mutex mutex;

/**
 * Contains statistics information for any thread that as already exited.
 */
Counters globalCounters;

/**
 * Set of all counters for all threads.
 */
std::unordered_set<const Counters*> perThreadCounters;

}  // namespace Internal

// Init thread local thread counters
thread_local ThreadCounters counters;

/**
 * Construct and register a new per thread set of counters.
 */
ThreadCounters::ThreadCounters()
    : Counters()
{
    std::lock_guard<std::mutex> lock(Internal::mutex);
    Internal::perThreadCounters.insert(this);
}

/**
 * Deregister and destruct a per thread set of counters.
 */
ThreadCounters::~ThreadCounters()
{
    std::lock_guard<std::mutex> lock(Internal::mutex);
    Internal::globalCounters.add(this);
    Internal::perThreadCounters.erase(this);
}

/**
 */
void
getStats(Stats* stats)
{
    std::lock_guard<std::mutex> lock(Internal::mutex);
    stats->timestamp = PerfUtils::Cycles::rdtsc();
    stats->cycles_per_second = PerfUtils::Cycles::perSecond();

    Counters output;
    output.add(&Internal::globalCounters);

    for (const Counters* counters : Internal::perThreadCounters) {
        output.add(counters);
    }

    output.dumpStats(stats);
}

}  // namespace Perf
}  // namespace Homa
