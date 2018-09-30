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

#include "Sender.h"

#include <algorithm>
#include <mutex>

namespace Homa {
namespace Core {

namespace {
const uint32_t RTT_TIME_US = 5;
}

/**
 * Sender Constructor.
 */
Sender::Sender()
    : sendMutex()
    , messageMap()
    , outboundPool()
    , queueMutex()
    , sendQueue()
{}

/**
 * Sender Destructor
 */
Sender::~Sender()
{
    std::lock_guard<SpinLock> lock(sendMutex);
    for (auto it = messageMap.begin(); it != messageMap.end(); ++it) {
        OutboundMessage* message = it->second;
        message->context->release();
        outboundPool.destroy(message);
    }
}

/**
 * Process an incoming GRANT packet.
 *
 * @param packet
 *      Incoming GRANT packet to be processed.
 * @param driver
 *      Driver from which the packet was received and to which it should be
 *      returned after the packet has been processed.
 */
void
Sender::handleGrantPacket(Driver::Packet* packet, Driver* driver)
{
    Protocol::GrantHeader* header =
        static_cast<Protocol::GrantHeader*>(packet->payload);
    Protocol::MessageId msgId = header->common.msgId;
    OutboundMessage* message = nullptr;

    // Find the OutboundMessage for this GRANT
    {
        // Only need to hold the lock while accessing the messageMap structure.
        std::lock_guard<SpinLock> lock(sendMutex);
        auto it = messageMap.find(msgId);
        if (it != messageMap.end()) {
            message = it->second;
        } else {
            // if we can't find the message, we should just drop the grant.
            driver->releasePackets(&packet, 1);
            return;
        }
        // Take the message's lock while still holding the sendMutex.
        message->mutex.lock();
    }
    std::lock_guard<SpinLock> messageLock(message->mutex, std::adopt_lock);
    message->grantOffset = std::max(message->grantOffset, header->offset);
    message->grantOffset =
        std::min(message->grantOffset, message->context->messageLength - 1);
    message->grantIndex =
        message->grantOffset / message->context->PACKET_DATA_LENGTH;
    driver->releasePackets(&packet, 1);
}

/**
 * Queue a message to be sent.
 *
 * @context
 *      MessageContext of the message to be sent.
 */
void
Sender::sendMessage(MessageContext* context)
{
    uint32_t unscheduledBytes =
        RTT_TIME_US * (context->driver->getBandwidth() / 8);

    uint32_t actualMessageLen = 0;
    // fill out headers.
    for (uint16_t i = 0; i < context->getNumPackets(); ++i) {
        Driver::Packet* packet = context->getPacket(i);
        if (packet == nullptr) {
            ERROR(
                "Incomplete message with id (%ul:%ul); missing packet at "
                "offset %u; send request dropped.",
                context->msgId.transportId, context->msgId.sequence,
                i * context->PACKET_DATA_LENGTH);
            return;
        }

        packet->address = context->address;
        packet->priority = 0;
        new (packet->payload)
            Protocol::DataHeader(context->msgId, context->messageLength, i);
        actualMessageLen += (packet->len - context->DATA_HEADER_LENGTH);
    }

    // perform sanity checks.
    assert(context->getNumPackets() ==
           1 + (context->messageLength / context->PACKET_DATA_LENGTH));
    assert(context->messageLength == actualMessageLen);
    assert(context->DATA_HEADER_LENGTH == sizeof(Protocol::DataHeader));

    OutboundMessage* message = nullptr;
    {
        // Only need to hold the lock while accessing the messageMap and
        // outboundPool structures.
        std::lock_guard<SpinLock> lock(sendMutex);
        auto it = messageMap.find(context->msgId);
        if (it != messageMap.end()) {
            // found message with the same msgId. Drop this request.
            WARNING(
                "Duplicate call to sendMessage for msgId (%ul:%ul); send "
                "request dropped.",
                context->msgId.transportId, context->msgId.sequence);
            return;
        }
        message = outboundPool.construct(context);
        message->context->retain();
        messageMap.insert({context->msgId, message});
        {
            std::lock_guard<SpinLock> lockQueue(queueMutex);
            sendQueue.push_back(message);
        }
        // Take the message's lock while still holding the sendMutex.
        message->mutex.lock();
    }
    // additional outbound message setup.
    std::lock_guard<SpinLock> messageLock(message->mutex, std::adopt_lock);
    message->grantOffset =
        std::min(unscheduledBytes, message->context->messageLength - 1);
    message->grantIndex =
        message->grantOffset / message->context->PACKET_DATA_LENGTH;
}

/**
 * Allow the Sender to make incremental progress on background tasks.
 */
void
Sender::poll()
{
    trySend();
    cleanup();
}

/**
 * Does most of the work of actually trying to send out packets for messages.
 *
 * Pulled out of poll() for clarity.
 */
void
Sender::trySend()
{
    // TODO(cstlee): improve concurrency
    if (!queueMutex.try_lock()) {
        // a different poller is already working on it.
        return;
    }
    std::lock_guard<SpinLock> lockQueue(queueMutex, std::adopt_lock);
    if (sendQueue.empty()) {
        // Nothing to send
        return;
    }
    OutboundMessage* message = nullptr;
    auto it = sendQueue.begin();
    while (it != sendQueue.end()) {
        message = *it;
        message->mutex.lock();
        if (message->sentIndex < message->context->getNumPackets() &&
            message->grantIndex > message->sentIndex) {
            // found a message to send.
            break;
        }
        message->mutex.unlock();
        message = nullptr;
        it++;
    }

    if (message == nullptr) {
        // nothing found to send
        return;
    }

    // otherwise; send the next packets.
    std::lock_guard<SpinLock> lockMessage(message->mutex, std::adopt_lock);
    assert(message->grantIndex < message->context->getNumPackets());
    int numPkts = message->grantIndex - message->sentIndex;
    for (int i = 1; i <= numPkts; ++i) {
        Driver::Packet* packet =
            message->context->getPacket(message->sentIndex + i);
        message->context->driver->sendPackets(&packet, 1);
    }
    message->sentIndex = message->grantIndex;
}

/**
 * Clean up the internal data structures and remove outgoing messages that
 * are done. This is seperated from sending becuase the locks needed for
 * cleanup are not held during sending.
 */
void
Sender::cleanup()
{
    // use std::lock to acquire two locks without worrying about deadlock
    std::lock(sendMutex, queueMutex);
    std::lock_guard<SpinLock> lock(sendMutex, std::adopt_lock);
    std::lock_guard<SpinLock> lockQueue(queueMutex, std::adopt_lock);
    while (!sendQueue.empty()) {
        OutboundMessage* message = sendQueue.front();
        if (message->sentIndex < message->context->getNumPackets()) {
            // Found an incomplete message, easier to just skip the reset of
            // cleanup ranther than dealing with erasing somewhere in the middle
            // of the sendQueue.
            break;
        }
        message->context->release();
        sendQueue.pop_front();
        messageMap.erase(message->context->msgId);
    }
}

}  // namespace Core
}  // namespace Homa