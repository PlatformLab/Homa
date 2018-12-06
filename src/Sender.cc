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

#include "OpContext.h"

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
    , queueMutex()
    , sendQueue()
{}

/**
 * Sender Destructor
 */
Sender::~Sender() {}

/**
 * Process an incoming GRANT packet.
 *
 * @param op
 *      OpContext containing the OutboundMessage that corresponds to the
 *      incomming GRANT packet.
 * @param packet
 *      Incoming GRANT packet to be processed.
 * @param driver
 *      Driver from which the packet was received and to which it should be
 *      returned after the packet has been processed.
 */
void
Sender::handleGrantPacket(OpContext* op, Driver::Packet* packet, Driver* driver)
{
    assert(op->outMessage);
    OutboundMessage* message = op->outMessage.get();
    std::lock_guard<SpinLock> messageLock(message->mutex);
    Protocol::GrantHeader* header =
        static_cast<Protocol::GrantHeader*>(packet->payload);
    message->grantOffset = std::max(message->grantOffset, header->offset);
    message->grantOffset =
        std::min(message->grantOffset, message->messageLength - 1);
    message->grantIndex = message->grantOffset / message->PACKET_DATA_LENGTH;
    driver->releasePackets(&packet, 1);
}

/**
 * Queue a message to be sent.
 *
 * @param op
 *      OpContext containing the OutboundMessage of the message to be sent.
 */
void
Sender::sendMessage(OpContext* op)
{
    assert(op->outMessage);
    OutboundMessage* message = op->outMessage.get();

    {
        std::lock_guard<SpinLock> messageLock(message->mutex);

        if (message->sending.test_and_set()) {
            // message already sending, drop the send request.
            WARNING(
                "Duplicate call to sendMessage for msgId (%lu:%lu); send "
                "request dropped.",
                message->msgId.transportId, message->msgId.sequence);
            return;
        }

        uint32_t unscheduledBytes =
            RTT_TIME_US * (message->driver->getBandwidth() / 8);

        uint32_t actualMessageLen = 0;
        // fill out headers.
        for (uint16_t i = 0; i < message->getNumPackets(); ++i) {
            Driver::Packet* packet = message->getPacket(i);
            if (packet == nullptr) {
                ERROR(
                    "Incomplete message with id (%lu:%lu); missing packet at "
                    "offset %d; send request dropped.",
                    message->msgId.transportId, message->msgId.sequence,
                    i * message->PACKET_DATA_LENGTH);
                return;
            }

            packet->address = message->address;
            packet->priority = 0;
            new (packet->payload)
                Protocol::DataHeader(message->msgId, message->messageLength, i);
            actualMessageLen += (packet->length - message->DATA_HEADER_LENGTH);
        }

        // perform sanity checks.
        assert(message->messageLength == actualMessageLen);
        assert(message->DATA_HEADER_LENGTH == sizeof(Protocol::DataHeader));

        message->grantOffset =
            std::min(unscheduledBytes - 1, message->messageLength - 1);
        message->grantIndex =
            message->grantOffset / message->PACKET_DATA_LENGTH;
    }

    {
        std::lock_guard<SpinLock> lockQueue(queueMutex);
        sendQueue.push_back(message);
    }
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
        if (message->sentIndex < message->getNumPackets() &&
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
    assert(message->grantIndex < message->getNumPackets());
    int numPkts = message->grantIndex - message->sentIndex;
    for (int i = 1; i <= numPkts; ++i) {
        Driver::Packet* packet = message->getPacket(message->sentIndex + i);
        message->driver->sendPackets(&packet, 1);
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
        if (message->sentIndex + 1 < message->getNumPackets()) {
            // Found an incomplete message, easier to just skip the reset of
            // cleanup ranther than dealing with erasing somewhere in the middle
            // of the sendQueue.
            break;
        }
        sendQueue.pop_front();
        message->sending.clear();
    }
}

}  // namespace Core
}  // namespace Homa