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

#include <Cycles.h>
#include "Homa/Homa.h"
#include "Homa/Utils/TransportPoller.h"
#include "Perf.h"

namespace Homa {

/**
 * Transport poller constructor.
 *
 * @param transport
 *      Transport instance driven by this poller.
 */
TransportPoller::TransportPoller(Transport* transport)
    : transport(transport)
    , nextTimeoutCycles(0)
{}

/**
 * Make incremental progress performing all Transport functionality.
 *
 * This method MUST be called for the Transport to make progress and should
 * be called frequently to ensure timely progress.
 */
void
TransportPoller::poll()
{
    // Receive and dispatch incoming packets.
    processPackets();

    // Allow sender and receiver to make incremental progress.
    uint64_t waitUntil;
    transport->trySend(&waitUntil);
    transport->trySendGrants();

    if (PerfUtils::Cycles::rdtsc() >= nextTimeoutCycles.load()) {
        uint64_t requestedTimeoutCycles = transport->checkTimeouts();
        nextTimeoutCycles.store(requestedTimeoutCycles);
    }
}

/**
 * Helper method which receives a burst of incoming packets and process them
 * through the transport protocol.  Pulled out of TransportPoller::poll() to
 * simplify unit testing.
 */
void
TransportPoller::processPackets()
{
    // Keep track of time spent doing active processing versus idle.
    uint64_t cycles = PerfUtils::Cycles::rdtsc();

    const int MAX_BURST = 32;
    Driver::Packet packets[MAX_BURST];
    IpAddress srcAddrs[MAX_BURST];
    Driver* driver = transport->getDriver();
    int numPackets = driver->receivePackets(MAX_BURST, packets, srcAddrs);
    for (int i = 0; i < numPackets; ++i) {
        transport->processPacket(&packets[i], srcAddrs[i]);
    }

    cycles = PerfUtils::Cycles::rdtsc() - cycles;
    if (numPackets > 0) {
        Perf::counters.active_cycles.add(cycles);
    } else {
        Perf::counters.idle_cycles.add(cycles);
    }
}

}  // namespace Homa
