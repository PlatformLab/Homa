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

#include "PollModeTransportImpl.h"

namespace Homa {

Homa::unique_ptr<PollModeTransport>
PollModeTransport::create(Driver* driver, uint64_t transportId)
{
    return Homa::unique_ptr<PollModeTransport>(
        new PollModeTransportImpl(driver, transportId));
}

/**
 * Constructor.
 *
 * @param driver
 *      Driver with which this transport should send and receive packets.
 * @param transportId
 *      This transport's unique identifier in the group of transports among
 *      which this transport will communicate.
 */
PollModeTransportImpl::PollModeTransportImpl(Driver* driver,
                                             uint64_t transportId)
    : callbacks(this)
    , core(driver, &callbacks, transportId)
    , nextTimeoutCycles(0)
{}

/**
 * Construct for unit testing.
 */
PollModeTransportImpl::PollModeTransportImpl(Driver* driver,
                                             Core::Sender* sender,
                                             Core::Receiver* receiver,
                                             uint64_t transportId)
    : callbacks(this)
    , core(driver, &callbacks, sender, receiver, transportId)
    , nextTimeoutCycles(0)
{}

/// See Homa::PollModeTransport::alloc()
Homa::unique_ptr<OutMessage>
PollModeTransportImpl::alloc(uint16_t port)
{
    return core.alloc(port);
}

/// See Homa::PollModeTransport::free()
void
PollModeTransportImpl::free()
{
    // This instance must be allocated via new from PollModeTransport::create().
    delete this;
}

/// See Homa::PollModeTransport::getId()
uint64_t
PollModeTransportImpl::getId()
{
    return core.getId();
}

void
PollModeTransportImpl::poll()
{
    // Receive and dispatch incoming packets.
    processPackets();

    // Allow sender and receiver to make incremental progress.
    core.trySend();
    core.trySendGrants();

    if (PerfUtils::Cycles::rdtsc() >= nextTimeoutCycles.load()) {
        uint64_t requestedTimeoutCycles = core.checkTimeouts();
        nextTimeoutCycles.store(requestedTimeoutCycles);
    }
}

/// See Homa::PollModeTransport::receive
Homa::unique_ptr<Homa::InMessage>
PollModeTransportImpl::receive()
{
    if (receiveQueue.empty()) {
        return nullptr;
    }
    Homa::unique_ptr<InMessage> message = std::move(receiveQueue.back());
    receiveQueue.pop_back();
    return message;
}

/**
 * Helper method which receives a burst of incoming packets and process them
 * through the transport protocol.  Pulled out of PollModeTransportImpl::poll()
 * to simplify unit testing.
 */
void
PollModeTransportImpl::processPackets()
{
    // Keep track of time spent doing active processing versus idle.
    uint64_t cycles = PerfUtils::Cycles::rdtsc();

    const int MAX_BURST = 32;
    Driver::Packet packets[MAX_BURST];
    IpAddress srcAddrs[MAX_BURST];
    Driver* driver = core.getDriver();
    int numPackets = driver->receivePackets(MAX_BURST, packets, srcAddrs);
    for (int i = 0; i < numPackets; ++i) {
        core.processPacket(&packets[i], srcAddrs[i]);
    }

    cycles = PerfUtils::Cycles::rdtsc() - cycles;
    if (numPackets > 0) {
        Perf::counters.active_cycles.add(cycles);
    } else {
        Perf::counters.idle_cycles.add(cycles);
    }
}

}  // namespace Homa
