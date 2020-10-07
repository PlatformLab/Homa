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

/**
 * Construct an instance of a Homa-based transport.
 *
 * @param driver
 *      Driver with which this transport should send and receive packets.
 * @param mailboxDir
 *      Mailbox directory with which this transport should deliver messages.
 * @param transportId
 *      This transport's unique identifier in the group of transports among
 *      which this transport will communicate.
 */
TransportImpl::TransportImpl(Driver* driver, MailboxDir* mailboxDir,
                             uint64_t transportId)
    : transportId(transportId)
    , driver(driver)
    , policyManager(new Policy::Manager(driver))
    , sender(new Sender(transportId, driver, policyManager.get(),
                        PerfUtils::Cycles::fromMicroseconds(MESSAGE_TIMEOUT_US),
                        PerfUtils::Cycles::fromMicroseconds(PING_INTERVAL_US)))
    , receiver(
          new Receiver(driver, mailboxDir, policyManager.get(),
                       PerfUtils::Cycles::fromMicroseconds(MESSAGE_TIMEOUT_US),
                       PerfUtils::Cycles::fromMicroseconds(RESEND_INTERVAL_US)))
    , mailboxDir(mailboxDir)
{}

/**
 * Construct an instance of a Homa-based transport for unit testing.
 */
TransportImpl::TransportImpl(Driver* driver, MailboxDir* mailboxDir,
                             Sender* sender, Receiver* receiver,
                             uint64_t transportId)
    : transportId(transportId)
    , driver(driver)
    , policyManager(new Policy::Manager(driver))
    , sender(sender)
    , receiver(receiver)
    , mailboxDir(mailboxDir)
{}

/**
 * TransportImpl Destructor.
 */
TransportImpl::~TransportImpl() = default;

/// See Homa::Transport::free()
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

/// See Homa::Transport::open()
Homa::unique_ptr<Socket>
TransportImpl::open(uint16_t port)
{
    Mailbox* mailbox = mailboxDir->alloc(port);
    if (!mailbox) {
        return nullptr;
    }
    SocketImpl* socket = new SocketImpl(this, port, mailbox);
    return Homa::unique_ptr<Socket>(socket);
}

/// See Homa::Transport::checkTimeouts()
uint64_t
TransportImpl::checkTimeouts()
{
    uint64_t requestedTimeoutCycles = std::min(sender->checkTimeouts(),
        receiver->checkTimeouts());
    return requestedTimeoutCycles;
}

/// See Homa::Transport::processPacket()
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

/// See Homa::Transport::registerCallbackSendReady()
void
TransportImpl::registerCallbackSendReady(Callback func)
{
    sender->registerCallbackSendReady(func);
}

/// See Homa::Transport::trySend()
bool
TransportImpl::trySend(uint64_t* waitUntil)
{
    return sender->trySend(waitUntil);
}

/// See Homa::Transport::trySendGrants()
bool
TransportImpl::trySendGrants()
{
    return receiver->trySendGrants();
}

/**
 * Construct an instance of a Homa socket.
 *
 * @param transport
 *      Transport that owns the socket.
 * @param port
 *      Local port number of the socket.
 * @param mailbox
 *      Mailbox assigned to this socket.
 */
TransportImpl::SocketImpl::SocketImpl(TransportImpl* transport, uint16_t port,
                                      Mailbox* mailbox)
    : Socket()
    , disabled()
    , localAddress{transport->getDriver()->getLocalAddress(), port}
    , mailbox(mailbox)
    , transport(transport)
{}

/// See Homa::Socket::alloc()
unique_ptr<Homa::OutMessage>
TransportImpl::SocketImpl::alloc()
{
    if (isShutdown()) {
        return nullptr;
    }
    OutMessage* outMessage = transport->sender->allocMessage(localAddress.port);
    return unique_ptr<OutMessage>(outMessage);
}

/// See Homa::Socket::close()
void
TransportImpl::SocketImpl::close()
{
    bool success = transport->mailboxDir->remove(localAddress.port);
    if (!success) {
        ERROR("Failed to remove mailbox (port = %u)", localAddress.port);
    }

    // Destruct the socket (the mailbox may be still in use).
    // Note: it's actually legal to say "delete this" from a member function:
    // https://isocpp.org/wiki/faq/freestore-mgmt#delete-this
    delete this;
}

/// See Homa::Socket::receive()
unique_ptr<Homa::InMessage>
TransportImpl::SocketImpl::receive(bool blocking)
{
    if (isShutdown()) {
        return nullptr;
    }
    return unique_ptr<InMessage>(mailbox->retrieve(blocking));
}

/// See Homa::Socket::shutdown()
void
TransportImpl::SocketImpl::shutdown()
{
    disabled.store(true);
    mailbox->socketShutdown();
}

}  // namespace Homa::Core
