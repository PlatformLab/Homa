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

#pragma once

#include <atomic>

namespace Homa {

/// Forward declaration.
class Transport;

/**
 * Provides a means to drive the execution of a transport through repeated
 * calls to the poll() method.
 *
 * This class demonstrates a simple way to invoke the Homa::Transport APIs
 * in a poll-based programming style. In practice, users will often need to
 * invoke the Transport APIs in ways that fit their systems better. The Homa-
 * Shenango integration provides a concrete example.
 *
 * This class is thread-safe; although calling poll() from multiple threads
 * provides no performance benefit.
 *
 * @sa Homa/Shenango.h
 */
class TransportPoller {
  public:
    explicit TransportPoller(Transport* transport);
    ~TransportPoller() = default;
    void poll();

  private:
    void processPackets();

    /// Transport instance whose execution is driven by this poller.
    Transport* const transport;

    /// Caches the next cycle time that timeouts will need to rechecked.
    std::atomic<uint64_t> nextTimeoutCycles;
};

}  // namespace Homa