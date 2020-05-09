/* Copyright (c) 2018-2020, Stanford University
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

#include "TransportImpl.h"

#include <algorithm>
#include <memory>
#include <utility>

#include "Cycles.h"
#include "Perf.h"
#include "Protocol.h"

namespace Homa {
namespace Core {

// Basic timeout unit.
const uint64_t BASE_TIMEOUT_US = 2000;
/// Microseconds to wait before timeout out and failing a message.
const uint64_t MESSAGE_TIMEOUT_US = 40 * BASE_TIMEOUT_US;
/// Microseconds to wait before pinging to check on outbound messages.
const uint64_t PING_INTERVAL_US = 3 * BASE_TIMEOUT_US;
/// Microseconds to wait before performing retires on inbound messages.
const uint64_t RESEND_INTERVAL_US = BASE_TIMEOUT_US;

/**
 * Construct an instances of a Homa-based transport.
 *
 * @param driver
 *      Driver with which this transport should send and receive packets.
 * @param transportId
 *      This transport's unique identifier in the group of transports among
 *      which this transport will communicate.
 */
TransportImpl::TransportImpl(Driver* driver, uint64_t transportId)
    : transportId(transportId)
    , driver(driver)
    , policyManager(new Policy::Manager(driver))
    , sender(new Sender(transportId, driver, policyManager.get(),
                        PerfUtils::Cycles::fromMicroseconds(MESSAGE_TIMEOUT_US),
                        PerfUtils::Cycles::fromMicroseconds(PING_INTERVAL_US)))
    , receiver(
          new Receiver(driver, policyManager.get(),
                       PerfUtils::Cycles::fromMicroseconds(MESSAGE_TIMEOUT_US),
                       PerfUtils::Cycles::fromMicroseconds(RESEND_INTERVAL_US)))
    , nextTimeoutCycles(0)
{}

/**
 * TransportImpl Destructor.
 */
TransportImpl::~TransportImpl() = default;

/// See Homa::Transport::poll()
void
TransportImpl::poll()
{
    // Receive and dispatch incoming packets.
    processPackets();

    // Allow sender and receiver to make incremental progress.
    sender->poll();
    receiver->poll();

    if (PerfUtils::Cycles::rdtsc() >= nextTimeoutCycles.load()) {
        uint64_t requestedTimeoutCycles;
        requestedTimeoutCycles = sender->checkTimeouts();
        nextTimeoutCycles.store(requestedTimeoutCycles);
        requestedTimeoutCycles = receiver->checkTimeouts();
        if (nextTimeoutCycles.load() > requestedTimeoutCycles) {
            nextTimeoutCycles.store(requestedTimeoutCycles);
        }
    }
}

/**
 * Helper method which receives a burst of incoming packets and process them
 * through the transport protocol.  Pulled out of TransportImpl::poll() to
 * simplify unit testing.
 */
void
TransportImpl::processPackets()
{
    uint64_t start_tsc = PerfUtils::Cycles::rdtsc();
    bool idle = true;
    const int MAX_BURST = 32;
    Driver::Packet* packets[MAX_BURST];
    int numPackets = driver->receivePackets(MAX_BURST, packets);
    for (int i = 0; i < numPackets; ++i) {
        idle = false;
        Driver::Packet* packet = packets[i];
        assert(packet->length >=
               Util::downCast<int>(sizeof(Protocol::Packet::CommonHeader)));
        Protocol::Packet::CommonHeader* header =
            static_cast<Protocol::Packet::CommonHeader*>(packet->payload);
        switch (header->opcode) {
            case Protocol::Packet::DATA:
                receiver->handleDataPacket(packet, driver);
                break;
            case Protocol::Packet::GRANT:
                sender->handleGrantPacket(packet, driver);
                break;
            case Protocol::Packet::DONE:
                sender->handleDonePacket(packet, driver);
                break;
            case Protocol::Packet::RESEND:
                sender->handleResendPacket(packet, driver);
                break;
            case Protocol::Packet::BUSY:
                receiver->handleBusyPacket(packet, driver);
                break;
            case Protocol::Packet::PING:
                receiver->handlePingPacket(packet, driver);
                break;
            case Protocol::Packet::UNKNOWN:
                sender->handleUnknownPacket(packet, driver);
                break;
            case Protocol::Packet::ERROR:
                sender->handleErrorPacket(packet, driver);
                break;
        }
    }
    uint64_t elapsed_cycles = PerfUtils::Cycles::rdtsc() - start_tsc;
    if (!idle) {
        Perf::counters.active_cycles.add(elapsed_cycles);
    }
}

}  // namespace Core
}  // namespace Homa
