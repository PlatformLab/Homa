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
    OutboundMessage* message = nullptr;

    {
        std::lock_guard<SpinLock> lock(outboundMessages.mutex);
        auto it = outboundMessages.message.find(msgId);
        if (it != outboundMessages.message.end()) {
            message = &it->second->outMessage;
        } else {
            // No message for this grant; grant must be old; just drop it.
            driver->releasePackets(&packet, 1);
            return;
        }
        message->mutex.lock();
    }
    std::lock_guard<SpinLock> lock_op(message->mutex, std::adopt_lock);
    message->grantOffset = std::max(message->grantOffset, header->offset);
    message->grantOffset =
        std::min(message->grantOffset, message->message.rawLength() - 1);
    message->grantIndex =
        message->grantOffset / message->message.PACKET_DATA_LENGTH;
    driver->releasePackets(&packet, 1);
}

/**
 * Queue a message to be sent.
 *
 * @param id
 *      Unique identifier for this message.
 * @param destination
 *      Destination address for this message.
 * @param op
 *      OpContext containing the OutboundMessage to be sent.
 *
 * @sa dropMessage()
 */
void
Sender::sendMessage(Protocol::MessageId id, Driver::Address* destination,
                    OpContext* op)
{
    {
        std::lock_guard<SpinLock> lock(outboundMessages.mutex);
        if (outboundMessages.message.find(id) !=
            outboundMessages.message.end()) {
            // message already sending, drop the send request.
            WARNING(
                "Duplicate call to sendMessage for msgId (%lu:%lu:%u); send "
                "request dropped.",
                id.transportId, id.sequence, id.tag);
            return;
        } else {
            outboundMessages.message.insert({id, op});
            // Acquire this the outMessage lock with the top-level lock held
            // ensures we don't race with other calls involving this message.
            op->outMessage.mutex.lock();
        }
    }
    OutboundMessage* message = &op->outMessage;
    std::lock_guard<SpinLock> lock(message->mutex, std::adopt_lock);
    message->id = id;
    message->destination = destination;
    uint32_t unscheduledBytes =
        RTT_TIME_US * (message->message.driver->getBandwidth() / 8);

    uint32_t actualMessageLen = 0;
    // fill out metadata.
    for (uint16_t i = 0; i < message->message.getNumPackets(); ++i) {
        Driver::Packet* packet = message->message.getPacket(i);
        if (packet == nullptr) {
            PANIC(
                "Incomplete message with id (%lu:%lu:%u); missing packet "
                "at offset %d; this shouldn't happen.",
                message->id.transportId, message->id.sequence, message->id.tag,
                i * message->message.PACKET_DATA_LENGTH);
        }

        packet->address = message->destination;
        packet->priority = 0;
        new (packet->payload) Protocol::Packet::DataHeader(
            message->id, message->message.rawLength(), i);
        actualMessageLen +=
            (packet->length - message->message.PACKET_HEADER_LENGTH);
    }

    // perform sanity checks.
    assert(message->message.rawLength() == actualMessageLen);
    assert(message->message.PACKET_HEADER_LENGTH ==
           sizeof(Protocol::Packet::DataHeader));

    message->grantOffset =
        std::min(unscheduledBytes - 1, message->message.rawLength() - 1);
    message->grantIndex =
        message->grantOffset / message->message.PACKET_DATA_LENGTH;
}

/**
 * Inform the Sender that a Message is no longer needed and the associated
 * OpContext should no longer be used.
 *
 * @param op
 *      The OpContext which contains the Message that is no longer needed.
 */
void
Sender::dropMessage(OpContext* op)
{
    std::lock_guard<SpinLock> lock(outboundMessages.mutex);
    std::lock_guard<SpinLock> lock_message(op->outMessage.mutex);
    auto it = outboundMessages.message.find(op->outMessage.id);
    if (it != outboundMessages.message.end()) {
        assert(op == it->second);
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
    OutboundMessage* message = nullptr;
    auto it = outboundMessages.message.begin();
    while (it != outboundMessages.message.end()) {
        message = &it->second->outMessage;
        message->mutex.lock();
        if (message->sentIndex + 1 < message->message.getNumPackets() &&
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
    std::lock_guard<SpinLock> lock_op(message->mutex, std::adopt_lock);
    assert(message->grantIndex < message->message.getNumPackets());
    int numPkts = message->grantIndex - message->sentIndex;
    for (int i = 1; i <= numPkts; ++i) {
        Driver::Packet* packet =
            message->message.getPacket(message->sentIndex + i);
        message->message.driver->sendPackets(&packet, 1);
    }
    message->sentIndex = message->grantIndex;
    if (message->sentIndex + 1 >= message->message.getNumPackets()) {
        // We have finished sending the message.
        message->sent = true;
    }
}

}  // namespace Core
}  // namespace Homa