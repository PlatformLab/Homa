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
#include "Cycles.h"
#include "Perf.h"
#include "Protocol.h"

namespace Homa::Core {

// Basic timeout unit.
const uint64_t BASE_TIMEOUT_US = 2000;
/// Microseconds to wait before timeout out and failing a message.
const uint64_t MESSAGE_TIMEOUT_US = 40 * BASE_TIMEOUT_US;
/// Microseconds to wait before pinging to check on outbound messages.
const uint64_t PING_INTERVAL_US = 3 * BASE_TIMEOUT_US;
/// Microseconds to wait before performing retires on inbound messages.
const uint64_t RESEND_INTERVAL_US = BASE_TIMEOUT_US;

/// See Homa::Core::Transport::create()
Homa::unique_ptr<Transport>
Transport::create(Driver* driver, Callbacks* callbacks, uint64_t transportId)
{
    Transport* transport =
        new Core::TransportImpl(driver, callbacks, transportId);
    return Homa::unique_ptr<Transport>(transport);
}

/**
 * Construct an instance of a Homa-based transport.
 *
 * @param driver
 *      Driver with which this transport should send and receive packets.
 * @param callbacks
 *      User-defined transport callbacks.
 * @param transportId
 *      This transport's unique identifier in the group of transports among
 *      which this transport will communicate.
 */
TransportImpl::TransportImpl(Driver* driver, Callbacks* callbacks,
                             uint64_t transportId)
    : transportId(transportId)
    , callbacks(callbacks)
    , driver(driver)
    , policyManager(new Policy::Manager(driver))
    , sender(new Sender(transportId, driver, callbacks, policyManager.get(),
                        PerfUtils::Cycles::fromMicroseconds(MESSAGE_TIMEOUT_US),
                        PerfUtils::Cycles::fromMicroseconds(PING_INTERVAL_US)))
    , receiver(
          new Receiver(driver, callbacks, policyManager.get(),
                       PerfUtils::Cycles::fromMicroseconds(MESSAGE_TIMEOUT_US),
                       PerfUtils::Cycles::fromMicroseconds(RESEND_INTERVAL_US)))
{}

/**
 * Construct an instance of a Homa-based transport for unit testing.
 */
TransportImpl::TransportImpl(Driver* driver, Callbacks* callbacks,
                             Sender* sender, Receiver* receiver,
                             uint64_t transportId)
    : transportId(transportId)
    , callbacks(callbacks)
    , driver(driver)
    , policyManager(new Policy::Manager(driver))
    , sender(sender)
    , receiver(receiver)
{}

/// See Homa::TransportBase::free()
void
TransportImpl::free()
{
    // We simply call "delete this" here because the only way to instantiate
    // a Core::TransportImpl instance is via "new" in Transport::create().
    // An alternative would be to provide a static free() method that takes
    // a pointer to Transport, the downside of this approach is that we must
    // cast the argument to TransportImpl* because polymorphic deletion is
    // disabled on the Transport interface.
    delete this;
}

/// See Homa::TransportBase::alloc()
Homa::unique_ptr<OutMessage>
TransportImpl::alloc(uint16_t port)
{
    OutMessage* outMessage = sender->allocMessage(port);
    return unique_ptr<OutMessage>(outMessage);
}

/// See Homa::Core::Transport::checkTimeouts()
uint64_t
TransportImpl::checkTimeouts()
{
    uint64_t requestedTimeoutCycles =
        std::min(sender->checkTimeouts(), receiver->checkTimeouts());
    return requestedTimeoutCycles;
}

/// See Homa::Core::Transport::processPacket()
void
TransportImpl::processPacket(Driver::Packet* packet, IpAddress sourceIp)
{
    assert(packet->length >=
           Util::downCast<int>(sizeof(Protocol::Packet::CommonHeader)));
    Perf::counters.rx_bytes.add(packet->length);
    Protocol::Packet::CommonHeader* header =
        static_cast<Protocol::Packet::CommonHeader*>(packet->payload);
    switch (header->opcode) {
        case Protocol::Packet::DATA:
            Perf::counters.rx_data_pkts.add(1);
            receiver->handleDataPacket(packet, sourceIp);
            break;
        case Protocol::Packet::GRANT:
            Perf::counters.rx_grant_pkts.add(1);
            sender->handleGrantPacket(packet);
            break;
        case Protocol::Packet::DONE:
            Perf::counters.rx_done_pkts.add(1);
            sender->handleDonePacket(packet);
            break;
        case Protocol::Packet::RESEND:
            Perf::counters.rx_resend_pkts.add(1);
            sender->handleResendPacket(packet);
            break;
        case Protocol::Packet::BUSY:
            Perf::counters.rx_busy_pkts.add(1);
            receiver->handleBusyPacket(packet);
            break;
        case Protocol::Packet::PING:
            Perf::counters.rx_ping_pkts.add(1);
            receiver->handlePingPacket(packet, sourceIp);
            break;
        case Protocol::Packet::UNKNOWN:
            Perf::counters.rx_unknown_pkts.add(1);
            sender->handleUnknownPacket(packet);
            break;
        case Protocol::Packet::ERROR:
            Perf::counters.rx_error_pkts.add(1);
            sender->handleErrorPacket(packet);
            break;
    }
}

/// See Homa::Core::Transport::trySend()
uint64_t
TransportImpl::trySend()
{
    return sender->trySend();
}

/// See Homa::Core::Transport::trySendGrants()
bool
TransportImpl::trySendGrants()
{
    return receiver->trySendGrants();
}

}  // namespace Homa::Core
