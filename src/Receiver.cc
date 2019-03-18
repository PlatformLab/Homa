/* Copyright (c) 2018-2019, Stanford University
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
 *      Scheduler that should be informed when message packets are received.
 * @param opPool
 *      OpContextPool from which the Receiver can allocate OpContext objects.
 */
Receiver::Receiver(Scheduler* scheduler, OpContextPool* opPool)
    : scheduler(scheduler)
    , opPool(opPool)
    , inboundMessages()
    , receivedMessages()
{}

/**
 * Receiver distructor.
 */
Receiver::~Receiver() {}

/**
 * Process an incoming DATA packet.
 *
 * @param packet
 *      The incoming packet to be processed.
 * @param driver
 *      The driver from which the packet was received.
 */
void
Receiver::handleDataPacket(Driver::Packet* packet, Driver* driver)
{
    Protocol::Packet::DataHeader* header =
        static_cast<Protocol::Packet::DataHeader*>(packet->payload);
    uint16_t dataHeaderLength = sizeof(Protocol::Packet::DataHeader);
    Protocol::MessageId msgId = header->common.messageId;

    OpContext* op = nullptr;
    InboundMessage* message = nullptr;
    {
        std::lock_guard<SpinLock> lock(inboundMessages.mutex);
        auto it = inboundMessages.message.find(msgId);
        if (it != inboundMessages.message.end()) {
            op = it->second;
        } else {
            op = opPool->construct();
            op->inMessage.id = msgId;  // Touch OK w/o lock; op not externalized
            inboundMessages.message.insert(it, {msgId, op});
        }
        message = &op->inMessage;
        message->mutex.lock();
    }

    std::lock_guard<SpinLock> lock_op(message->mutex, std::adopt_lock);
    assert(msgId == message->id);
    if (!message->message) {
        uint32_t messageLength = header->totalLength;
        message->message.construct(driver, dataHeaderLength, messageLength);
        // Get an address pointer from the driver; the one in the packet
        // may disappear when the packet goes away.
        std::string addrStr = packet->address->toString();
        message->source = driver->getAddress(&addrStr);
    }

    // All packets already received; must be a duplicate.
    if (message->fullMessageReceived) {
        // drop packet
        driver->releasePackets(&packet, 1);
        return;
    }

    // Things that must be true (sanity check)
    assert(message->source->toString() == packet->address->toString());
    assert(message->message->rawLength() == header->totalLength);

    // Add the packet
    bool packetAdded = message->message->setPacket(header->index, packet);
    if (packetAdded) {
        // This value is technically sloppy since last packet of the message
        // which may not be a full packet. However, this should be fine since
        // receiving the last packet means we don't need the scheduler to GRANT
        // more packets anyway.
        uint32_t totalReceivedBytes = message->message->PACKET_DATA_LENGTH *
                                      message->message->getNumPackets();

        // Let the Scheduler know that we received a packet.
        scheduler->packetReceived(msgId, message->source,
                                  message->message->rawLength(),
                                  totalReceivedBytes);
        if (totalReceivedBytes >= message->message->rawLength()) {
            std::lock_guard<SpinLock> lock(receivedMessages.mutex);
            message->fullMessageReceived = true;
            receivedMessages.queue.push_back(op);
        }
    } else {
        // must be a duplicate packet; drop packet.
        driver->releasePackets(&packet, 1);
    }
}

/**
 * Return a fully received message if available.
 *
 * @return
 *      OpContext containing a fully received incomming Message if available;
 *      otherwise, nullptr.
 */
OpContext*
Receiver::receiveMessage()
{
    std::lock_guard<SpinLock> lock(receivedMessages.mutex);
    OpContext* op = nullptr;
    if (!receivedMessages.queue.empty()) {
        op = receivedMessages.queue.front();
        receivedMessages.queue.pop_front();
    }
    return op;
}

/**
 * Inform the Receiver that an incomming Message is expected and should be
 * associated with a particular OpContext.
 *
 * @param msgId
 *      Id of the Message that should be expected.
 * @param op
 *      OpContext where the expected Message should be accumulated.
 */
void
Receiver::registerMessage(Protocol::MessageId msgId, OpContext* op)
{
    std::lock_guard<SpinLock> lock(inboundMessages.mutex);
    std::lock_guard<SpinLock> lock_message(op->inMessage.mutex);
    op->inMessage.id = msgId;
    inboundMessages.message.insert({msgId, op});
}

/**
 * Inform the Receiver that a Message is no longer needed and the associated
 * OpContext should no longer be used.
 *
 * @param op
 *      The OpContext which contains the Message that is no longer needed.
 */
void
Receiver::dropMessage(OpContext* op)
{
    std::lock_guard<SpinLock> lock(inboundMessages.mutex);
    std::lock_guard<SpinLock> lock_message(op->inMessage.mutex);
    inboundMessages.message.erase(op->inMessage.id);
}

/**
 * Allow the Receiver to make incremental progress on background tasks.
 */
void
Receiver::poll()
{}

}  // namespace Core
}  // namespace Homa