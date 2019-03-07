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
    , outboundMessages()
{}

/**
 * Sender Destructor
 */
Sender::~Sender() {}

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
    Protocol::Packet::GrantHeader* header =
        static_cast<Protocol::Packet::GrantHeader*>(packet->payload);
    Protocol::MessageId msgId = header->common.messageId;
    OpContext* op = nullptr;

    {
        std::lock_guard<SpinLock> lock(outboundMessages.mutex);
        auto it = outboundMessages.message.find(msgId);
        if (it != outboundMessages.message.end()) {
            op = it->second;
        } else {
            // No message for this grant; grant must be old; just drop it.
            driver->releasePackets(&packet, 1);
            return;
        }
        op->mutex.lock();
    }
    std::lock_guard<SpinLock> lock_op(op->mutex, std::adopt_lock);

    assert(op != nullptr);
    assert(op->outMessage);
    OutboundMessage* message = op->outMessage.get();
    message->grantOffset = std::max(message->grantOffset, header->offset);
    message->grantOffset =
        std::min(message->grantOffset, message->rawLength() - 1);
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
    {
        // Prepare the Message to be sent.  Lock the op the state is modified.
        std::lock_guard<SpinLock> lock(op->mutex);
        assert(op->outMessage);
        OutboundMessage* message = op->outMessage.get();

        if (message->sending) {
            // message already sending, drop the send request.
            WARNING(
                "Duplicate call to sendMessage for msgId (%lu:%lu:%u); send "
                "request dropped.",
                message->msgId.transportId, message->msgId.sequence,
                message->msgId.messageId);
            return;
        } else {
            message->sending = true;
        }

        uint32_t unscheduledBytes =
            RTT_TIME_US * (message->driver->getBandwidth() / 8);

        uint32_t actualMessageLen = 0;
        // fill out metadata.
        for (uint16_t i = 0; i < message->getNumPackets(); ++i) {
            Driver::Packet* packet = message->getPacket(i);
            if (packet == nullptr) {
                ERROR(
                    "Incomplete message with id (%lu:%lu:%u); missing packet "
                    "at offset %d; send request dropped.",
                    message->msgId.transportId, message->msgId.sequence,
                    message->msgId.messageId, i * message->PACKET_DATA_LENGTH);
                return;
            }

            packet->address = message->address;
            packet->priority = 0;
            new (packet->payload) Protocol::Packet::DataHeader(
                message->msgId, message->rawLength(), i);
            actualMessageLen +=
                (packet->length - message->PACKET_HEADER_LENGTH);
        }

        // perform sanity checks.
        assert(message->rawLength() == actualMessageLen);
        assert(message->PACKET_HEADER_LENGTH ==
               sizeof(Protocol::Packet::DataHeader));

        message->grantOffset =
            std::min(unscheduledBytes - 1, message->rawLength() - 1);
        message->grantIndex =
            message->grantOffset / message->PACKET_DATA_LENGTH;
    }  // Release the op mutex.

    // Re-acquire the locks to ensure a safe order.
    std::lock(outboundMessages.mutex, op->mutex);
    std::lock_guard<SpinLock> lock(outboundMessages.mutex, std::adopt_lock);
    std::lock_guard<SpinLock> lock_op(op->mutex, std::adopt_lock);
    // Re-check to make sure we still should be sending the message.
    if (op->outMessage) {
        OutboundMessage* message = op->outMessage.get();
        Protocol::MessageId msgId = message->msgId;

        outboundMessages.message.insert({msgId, op});
        outboundMessages.sendQueue.push_back(op);
    }
}

/**
 * Inform the Sender that a Message is no longer needed.
 *
 * @param msgId
 *      Id of the Message that is no longer needed.
 */
void
Sender::dropMessage(Protocol::MessageId msgId)
{
    std::lock_guard<SpinLock> lock(outboundMessages.mutex);
    auto it = outboundMessages.message.find(msgId);
    if (it != outboundMessages.message.end()) {
        OpContext* op = it->second;
        std::lock_guard<SpinLock> lock_op(op->mutex);
        op->outMessage->sending = false;
        outboundMessages.message.erase(it);
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
    if (!outboundMessages.mutex.try_lock()) {
        // a different poller is already working on it.
        return;
    }
    std::lock_guard<SpinLock> lock(outboundMessages.mutex, std::adopt_lock);
    OpContext* op = nullptr;
    auto it = outboundMessages.sendQueue.begin();
    while (it != outboundMessages.sendQueue.end()) {
        op = *it;
        op->mutex.lock();
        assert(op->outMessage);
        if (op->outMessage->sending &&
            op->outMessage->sentIndex < op->outMessage->getNumPackets() &&
            op->outMessage->grantIndex > op->outMessage->sentIndex) {
            // found a message to send.
            break;
        }
        op->mutex.unlock();
        op = nullptr;
        it++;
    }

    if (op == nullptr) {
        // nothing found to send
        return;
    }

    // otherwise; send the next packets.
    std::lock_guard<SpinLock> lock_op(op->mutex, std::adopt_lock);
    OutboundMessage* message = op->outMessage.get();
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
 * are done. This is seperated from sending because the locks needed for
 * cleanup are not held during sending.
 */
void
Sender::cleanup()
{
    std::lock_guard<SpinLock> lock(outboundMessages.mutex);
    while (!outboundMessages.sendQueue.empty()) {
        OpContext* op = outboundMessages.sendQueue.front();
        std::lock_guard<SpinLock> lock_op(op->mutex);
        if (op->outMessage->sending &&
            op->outMessage->sentIndex + 1 < op->outMessage->getNumPackets()) {
            // Found an incomplete message, easier to just skip the reset of
            // cleanup ranther than dealing with erasing somewhere in the middle
            // of the sendQueue.
            break;
        }
        outboundMessages.sendQueue.pop_front();
        op->outMessage->sending = false;
    }
}

}  // namespace Core
}  // namespace Homa