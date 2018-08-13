/* Copyright (c) 2018, Stanford University
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

#include "Protocol.h"

#include <algorithm>
#include <utility>

namespace Homa {

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
    : driver(driver)
    , messagePool()
    , sender()
    , scheduler(driver)
    , receiver(&scheduler, &messagePool)
    , transportId(transportId)
    , nextMessgeId(1)
{}

/**
 * TransportImpl Destructor.
 */
TransportImpl::~TransportImpl() {}

/// See Homa::Transport::newMessage()
Message
TransportImpl::newMessage()
{
    Message message;
    Core::MessageContext* context = messagePool.construct(
        Protocol::MessageId(transportId, nextMessgeId.fetch_add(1)),
        sizeof(Protocol::DataHeader), driver);
    return Message(context);
}

/// See Homa::Transport::receiveMessage()
Message
TransportImpl::receiveMessage()
{
    Core::MessageContext* context = receiver.receiveMessage();
    return Message(context);
}

/// See Homa::Transport::sendMessage()
void
TransportImpl::sendMessage(Message* message, SendFlag flags,
                           Message* completes[], uint16_t numCompletes)
{
    // TODO(cstlee): actually use the flags and completes
    assert(message->getContext()->address != nullptr);
    sender.sendMessage(message->getContext());
}

/// See Homa::Transport::poll()
void
TransportImpl::poll()
{
    const int MAX_BURST = 32;
    Driver::Packet* packets[MAX_BURST];
    int numPackets = driver->receivePackets(MAX_BURST, packets);
    for (int i = 0; i < numPackets; ++i) {
        Driver::Packet* packet = packets[i];
        assert(packet->len >= sizeof(Protocol::CommonHeader));
        Protocol::CommonHeader* header =
            static_cast<Protocol::CommonHeader*>(packet->payload);

        switch (header->opcode) {
            case Protocol::DATA:
                LOG(DEBUG, "Handle DataPacket");
                receiver.handleDataPacket(packet, driver);
                break;
            case Protocol::GRANT:
                LOG(DEBUG, "Handle GrantPacket");
                sender.handleGrantPacket(packet, driver);
                break;
        }
    }
    sender.poll();
    receiver.poll();
}

}  // namespace Homa
