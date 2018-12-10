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

#include "Receiver.h"

#include "OpContext.h"

namespace Homa {
namespace Core {

/**
 * Receiver constructor.
 *
 * @param scheduler
 *      Scheudler that should be informed when message packets are received.
 * @param messagePool
 *      MessagePool from which the Receiver can allocate MessageContext objects.
 */
Receiver::Receiver(Scheduler* scheduler)
    : scheduler(scheduler)
{}

/**
 * Receiver distructor.
 */
Receiver::~Receiver() {}

/**
 * Process an incoming DATA packet.
 *
 * @param op
 *      OpContext containing the InboundMessage that corresponds to the
 *      incomming DATA packet.
 * @param packet
 *      The incoming packet to be processed.
 * @param driver
 *      The driver from which the packet was received.
 */
void
Receiver::handleDataPacket(OpContext* op, Driver::Packet* packet,
                           Driver* driver)
{
    Protocol::DataHeader* header =
        static_cast<Protocol::DataHeader*>(packet->payload);
    uint16_t dataHeaderLength = sizeof(Protocol::DataHeader);
    Protocol::MessageId msgId = header->common.messageId;

    if (!op->inMessage) {
        op->inMessage.construct(msgId, dataHeaderLength, driver);
        // Get an address pointer from the driver; the one in the packet
        // may disappear when the packet goes away.
        std::string addrStr = packet->address->toString();
        op->inMessage->address = driver->getAddress(&addrStr);
        op->inMessage->messageLength = header->totalLength;
    }

    InboundMessage* message = op->inMessage.get();
    std::lock_guard<SpinLock> messageLock(message->mutex);

    // All packets already received; must be a duplicate.
    if (message->fullMessageReceived) {
        // drop packet
        driver->releasePackets(&packet, 1);
        return;
    }

    // Things that must be true (sanity check)
    assert(message->address->toString() == packet->address->toString());
    assert(message->messageLength == header->totalLength);

    // Add the packet
    bool packetAdded = message->setPacket(header->index, packet);
    if (packetAdded) {
        // This value is technically sloppy since last packet of the message
        // which may not be a full packet. However, this should be fine since
        // receiving the last packet means we don't need the scheduler to GRANT
        // more packets anyway.
        uint32_t totalReceivedBytes =
            message->PACKET_DATA_LENGTH * message->getNumPackets();

        // Let the Scheduler know that we received a packet.
        scheduler->packetReceived(msgId, message->address,
                                  message->messageLength, totalReceivedBytes);
        if (totalReceivedBytes >= message->messageLength) {
            message->fullMessageReceived = true;
        }
    } else {
        // must be a duplicate packet; drop packet.
        driver->releasePackets(&packet, 1);
    }
}

/**
 * Allow the Receiver to make incremental progress on background tasks.
 */
void
Receiver::poll()
{}

}  // namespace Core
}  // namespace Homa