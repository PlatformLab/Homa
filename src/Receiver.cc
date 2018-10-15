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

#include <mutex>

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
Receiver::Receiver(Scheduler* scheduler, MessagePool* messagePool)
    : scheduler(scheduler)
    , receiveMutex()
    , messageMap()
    , inboundPool()
    , contextPool(messagePool)
    , queueMutex()
    , messageQueue()
{}

/**
 * Receiver distructor.
 */
Receiver::~Receiver()
{
    std::lock_guard<SpinLock> lock(receiveMutex);
    for (auto it = messageMap.begin(); it != messageMap.end(); ++it) {
        it->second->context->release();
        inboundPool.destroy(it->second);
    }
}

/**
 * Process an incoming Data packet.
 *
 * @param packet
 *      The incoming packet to be processed.
 * @param driver
 *      The driver from which the packet was received.
 */
void
Receiver::handleDataPacket(Driver::Packet* packet, Driver* driver)
{
    Protocol::DataHeader* header =
        static_cast<Protocol::DataHeader*>(packet->payload);
    uint16_t dataHeaderLength = sizeof(Protocol::DataHeader);
    Protocol::MessageId msgId = header->common.msgId;
    InboundMessage* message = nullptr;

    // Find the InboundMessage for this packet.
    {
        // Only need to hold the lock while accessing the messageMap and
        // inboundPool structures.
        std::lock_guard<SpinLock> lock(receiveMutex);
        auto it = messageMap.find(msgId);
        if (it != messageMap.end()) {
            message = it->second;
        } else {
            MessageContext* context =
                contextPool->construct(msgId, dataHeaderLength, driver);
            message = inboundPool.construct(context);
            // Get an address pointer from the driver; the one in the packet
            // may disappear when the packet goes away.
            std::string addrStr = packet->address->toString();
            message->context->address = driver->getAddress(&addrStr);
            message->context->messageLength = header->totalLength;
            messageMap.insert({msgId, message});
        }
        // Take the message's lock while still holding the receiveMutex.
        message->mutex.lock();
    }
    std::lock_guard<SpinLock> messageLock(message->mutex, std::adopt_lock);

    // All packets already received; must be a duplicate.
    if (message->fullMessageReceived) {
        // drop packet
        driver->releasePackets(&packet, 1);
        return;
    }

    // Things that must be true (sanity check)
    assert(message->context->address->toString() ==
           packet->address->toString());
    assert(message->context->messageLength == header->totalLength);

    // Add the packet
    bool packetAdded = message->context->setPacket(header->index, packet);
    if (packetAdded) {
        // This value is technically sloppy since last packet of the message
        // which may not be a full packet. However, this should be fine since
        // receiving the last packet means we don't need the scheduler to GRANT
        // more packets anyway.
        uint32_t totalReceivedBytes = message->context->PACKET_DATA_LENGTH *
                                      message->context->getNumPackets();

        // Let the Scheduler know that we received a packet.
        scheduler->packetReceived(msgId, message->context->address,
                                  message->context->messageLength,
                                  totalReceivedBytes);
        if (totalReceivedBytes >= message->context->messageLength) {
            message->fullMessageReceived = true;
            std::lock_guard<SpinLock> lock(queueMutex);
            messageQueue.push_back(message->context);
        }
    } else {
        // must be a duplicate packet; drop packet.
        driver->releasePackets(&packet, 1);
    }
}

/**
 * Return a fully received message if available.
 *
 * Returned MessageContext are retained on behalf of the caller. The caller is
 * expected to call MessageContext::release() on the returned MessageContext
 * when it is no longer needed.
 *
 * @return
 *      The MessageContext for the complete message.
 */
MessageContext*
Receiver::receiveMessage()
{
    std::lock_guard<SpinLock> lock(queueMutex);
    MessageContext* message = nullptr;
    if (!messageQueue.empty()) {
        message = messageQueue.front();
        messageQueue.pop_front();
        // TODO(cstlee): Will need need to change this once we implement retries
        //               and acks.
        std::lock_guard<SpinLock> lock(receiveMutex);
        messageMap.erase(message->msgId);
    }
    return message;
}

/**
 * Allow the Receiver to make incremental progress on background tasks.
 */
void
Receiver::poll()
{}

}  // namespace Core
}  // namespace Homa