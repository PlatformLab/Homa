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

#ifndef HOMA_PERF_H
#define HOMA_PERF_H

#include <Homa/Perf.h>

#include <atomic>

namespace Homa {
namespace Perf {

/**
 * Collection of collected performance counters.
 */
struct Counters {
    /// CPU time spent actively processing Homa messages in cycles.
    std::atomic<uint64_t> active_cycles;
};

/**
 * Thread-local collection of performance counters.
 */
struct ThreadCounters : public Counters {
    ThreadCounters();
    ~ThreadCounters();
};

/**
 * Per thread counters.
 */
extern thread_local ThreadCounters threadCounters;

}  // namespace Perf
}  // namespace Homa

#endif  // HOMA_PERF_H
