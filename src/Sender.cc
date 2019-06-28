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

#include <algorithm>

#include <Cycles.h>

#include "ControlPacket.h"
#include "Debug.h"
#include "Transport.h"

namespace Homa {
namespace Core {

namespace {
const uint32_t RTT_TIME_US = 5;
}

/**
 * Sender Constructor.
 *
 * @param transport
 *      The Tranport object that owns this Sender.
 * @param messageTimeoutCycles
 *      Number of cycles of inactivity to wait before this Sender declares an
 *      OutboundMessage send failure.
 * @param pingIntervalCycles
 *      Number of cycles of inactivity to wait between checking on the liveness
 *      of an OutboundMessage.
 */
Sender::Sender(Transport* transport, uint64_t messageTimeoutCycles,
               uint64_t pingIntervalCycles)
    : mutex()
    , transport(transport)
    , outboundMessages()
    , messageTimeouts(messageTimeoutCycles)
    , pingTimeouts(pingIntervalCycles)
    , sending()
{}

/**
 * Sender Destructor
 */
Sender::~Sender() {}

/**
 * Process an incoming DONE packet.
 *
 * @param packet
 *      Incoming DONE packet to be processed.
 * @param driver
 *      Driver from which the packet was received and to which it should be
 *      returned after the packet has been processed.
 */
void
Sender::handleDonePacket(Driver::Packet* packet, Driver* driver)
{
    SpinLock::UniqueLock lock(mutex);

    Protocol::Packet::DoneHeader* header =
        static_cast<Protocol::Packet::DoneHeader*>(packet->payload);
    Protocol::MessageId msgId = header->common.messageId;
    OutboundMessage* message = nullptr;

    auto it = outboundMessages.find(msgId);
    if (it != outboundMessages.end()) {
        message = it->second;
    } else {
        // No message for this DONE packet; must be old. Just drop it.
        driver->releasePackets(&packet, 1);
        return;
    }

    SpinLock::Lock lock_message(message->mutex);
    messageTimeouts.setTimeout(&message->messageTimeout);
    lock.unlock();  // End Sender critical section

    message->acknowledged = true;
    transport->hintUpdatedOp(message->op);
    driver->releasePackets(&packet, 1);
}

/**
 * Process an incoming RESEND packet.
 *
 * @param packet
 *      Incoming RESEND packet to be processed.
 * @param driver
 *      Driver from which the packet was received and to which it should be
 *      returned after the packet has been processed.
 */
void
Sender::handleResendPacket(Driver::Packet* packet, Driver* driver)
{
    SpinLock::UniqueLock lock(mutex);

    Protocol::Packet::ResendHeader* header =
        static_cast<Protocol::Packet::ResendHeader*>(packet->payload);
    Protocol::MessageId msgId = header->common.messageId;
    OutboundMessage* message = nullptr;

    auto it = outboundMessages.find(msgId);
    if (it != outboundMessages.end()) {
        message = it->second;
    } else {
        // No message for this RESEND; RESEND must be old. Just ignore it; this
        // case should be pretty rare and the Receiver will timeout eventually.
        driver->releasePackets(&packet, 1);
        return;
    }

    SpinLock::Lock lock_message(message->mutex);
    messageTimeouts.setTimeout(&message->messageTimeout);
    pingTimeouts.setTimeout(&message->pingTimeout);
    lock.unlock();  // End Sender critical section

    uint16_t index = header->index;
    uint16_t resendEnd = index + header->num;

    // In case a GRANT may have been lost, consider the RESEND a GRANT.
    assert(resendEnd <= message->message.getNumPackets());
    message->grantIndex = std::max(message->grantIndex, resendEnd);

    if (index >= message->sentIndex) {
        // If this RESEND is only requesting unsent packets, it must be that
        // this Sender has been busy and the Receiver is trying to ensure there
        // are no lost packets.  Reply BUSY and allow this Sender to send DATA
        // when it's ready.
        ControlPacket::send<Protocol::Packet::BusyHeader>(
            driver, message->destination, message->id);
    } else {
        // There are some packets to resend but only resend packets that have
        // already been sent.
        resendEnd = std::min(resendEnd, message->sentIndex);
        for (uint16_t i = index; i < resendEnd; ++i) {
            Driver::Packet* packet = message->message.getPacket(index++);
            message->message.driver->sendPackets(&packet, 1);
        }
    }

    driver->releasePackets(&packet, 1);
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
    SpinLock::UniqueLock lock(mutex);

    Protocol::Packet::GrantHeader* header =
        static_cast<Protocol::Packet::GrantHeader*>(packet->payload);
    Protocol::MessageId msgId = header->common.messageId;
    OutboundMessage* message = nullptr;

    auto it = outboundMessages.find(msgId);
    if (it != outboundMessages.end()) {
        message = it->second;
    } else {
        // No message for this grant; grant must be old. Just drop it.
        driver->releasePackets(&packet, 1);
        return;
    }

    SpinLock::Lock lock_message(message->mutex);
    messageTimeouts.setTimeout(&message->messageTimeout);
    pingTimeouts.setTimeout(&message->pingTimeout);
    lock.unlock();  // End Sender critical section

    assert(header->indexLimit <= message->message.getNumPackets());
    message->grantIndex = std::max(message->grantIndex, header->indexLimit);

    driver->releasePackets(&packet, 1);
}

/**
 * Process an incoming UNKNOWN packet.
 *
 * @param packet
 *      Incoming UNKNOWN packet to be processed.
 * @param driver
 *      Driver from which the packet was received and to which it should be
 *      returned after the packet has been processed.
 */
void
Sender::handleUnknownPacket(Driver::Packet* packet, Driver* driver)
{
    SpinLock::UniqueLock lock(mutex);

    Protocol::Packet::UnknownHeader* header =
        static_cast<Protocol::Packet::UnknownHeader*>(packet->payload);
    Protocol::MessageId msgId = header->common.messageId;
    OutboundMessage* message = nullptr;

    auto it = outboundMessages.find(msgId);
    if (it != outboundMessages.end()) {
        message = it->second;
    } else {
        // No message for this UNKNOWN packet; must be old. Just drop it.
        driver->releasePackets(&packet, 1);
        return;
    }

    // Lock handoff
    SpinLock::Lock lock_message(message->mutex);
    lock.unlock();

    if (!message->acknowledged) {
        message->sent = false;
        message->sentIndex = 0;
        // TODO(cstlee): May want to use the unscheduled-limit here instead of
        // just granting a single packet.
        message->grantIndex = 1;
        transport->hintUpdatedOp(message->op);
    } else {
        // The message is already considered "done" so the UNKNOWN packet must
        // be a stale response to a ping.
    }
    driver->releasePackets(&packet, 1);
}

/**
 * Process an incoming ERROR packet.
 *
 * @param packet
 *      Incoming ERROR packet to be processed.
 * @param driver
 *      Driver from which the packet was received and to which it should be
 *      returned after the packet has been processed.
 */
void
Sender::handleErrorPacket(Driver::Packet* packet, Driver* driver)
{
    SpinLock::UniqueLock lock(mutex);

    Protocol::Packet::ErrorHeader* header =
        static_cast<Protocol::Packet::ErrorHeader*>(packet->payload);
    Protocol::MessageId msgId = header->common.messageId;
    OutboundMessage* message = nullptr;

    auto it = outboundMessages.find(msgId);
    if (it != outboundMessages.end()) {
        message = it->second;
    } else {
        // No message for this ERROR packet; must be old. Just drop it.
        driver->releasePackets(&packet, 1);
        return;
    }

    SpinLock::Lock lock_message(message->mutex);
    lock.unlock();  // End Sender critical section

    message->failed = true;
    transport->hintUpdatedOp(message->op);
    driver->releasePackets(&packet, 1);
}

/**
 * Queue a message to be sent.
 *
 * @param id
 *      Unique identifier for this message.
 * @param destination
 *      Destination address for this message.
 * @param message
 *      OutboundMessage to be sent.
 *
 * @sa dropMessage()
 */
void
Sender::sendMessage(Protocol::MessageId id, Driver::Address* destination,
                    OutboundMessage* message)
{
    SpinLock::UniqueLock lock(mutex);
    SpinLock::Lock lock_message(message->mutex);

    if (outboundMessages.find(id) != outboundMessages.end()) {
        // message already sending, drop the send request.
        WARNING(
            "Duplicate call to sendMessage for msgId (%lu:%lu:%u); send "
            "request dropped.",
            id.transportId, id.sequence, id.tag);
        return;
    } else {
        outboundMessages.insert({id, message});
        messageTimeouts.setTimeout(&message->messageTimeout);
        pingTimeouts.setTimeout(&message->pingTimeout);
    }

    lock.unlock();  // End sender critical section.

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

    message->grantIndex =
        unscheduledBytes / message->message.PACKET_DATA_LENGTH;
    message->grantIndex =
        std::min(message->grantIndex, message->message.getNumPackets());
    // TODO(cstlee): handle case when unscheduledBytes is less than 1 packet.
    assert(message->grantIndex != 0);
}

/**
 * Inform the Sender that a Message is no longer needed.
 *
 * @param message
 *      The OutboundMessage that is no longer needed.
 */
void
Sender::dropMessage(OutboundMessage* message)
{
    SpinLock::Lock lock(mutex);
    SpinLock::Lock lock_message(message->mutex);
    auto it = outboundMessages.find(message->id);
    if (it != outboundMessages.end()) {
        assert(message == it->second);
        messageTimeouts.cancelTimeout(&message->messageTimeout);
        pingTimeouts.cancelTimeout(&message->pingTimeout);
        outboundMessages.erase(it);
    }
}

/**
 * Allow the Sender to make incremental progress on background tasks.
 */
void
Sender::poll()
{
    trySend();
    checkTimeouts();
}

/**
 * Does most of the work of actually trying to send out packets for messages.
 *
 * Pulled out of poll() for clarity.
 */
void
Sender::trySend()
{
    // Skip sending if another poller is already working on it.
    if (sending.test_and_set()) {
        return;
    }

    SpinLock::Lock lock(mutex);
    OutboundMessage* message = nullptr;
    auto it = outboundMessages.begin();
    while (it != outboundMessages.end()) {
        message = it->second;
        message->mutex.lock();
        if (message->sentIndex < message->message.getNumPackets() &&
            message->sentIndex < message->grantIndex) {
            // found a message to send.
            break;
        }
        message->mutex.unlock();
        message = nullptr;
        it++;
    }

    // If there is a message to send; send the next packets.
    if (message != nullptr) {
        SpinLock::Lock lock_message(message->mutex, std::adopt_lock);
        assert(message->grantIndex <= message->message.getNumPackets());
        assert(message->grantIndex >= message->sentIndex);
        uint16_t numPkts = message->grantIndex - message->sentIndex;
        for (uint16_t i = 0; i < numPkts; ++i) {
            Driver::Packet* packet =
                message->message.getPacket(message->sentIndex + i);
            assert(packet != nullptr);
            message->message.driver->sendPackets(&packet, 1);
        }
        message->sentIndex += numPkts;
        if (message->sentIndex >= message->message.getNumPackets()) {
            // We have finished sending the message.
            message->sent = true;
            transport->hintUpdatedOp(message->op);
        }
    }

    sending.clear();
}

/**
 * Process any outbound messages that have timed out.
 *
 * Pull out of poll() for ease of testing.
 */
void
Sender::checkTimeouts()
{
    while (true) {
        SpinLock::UniqueLock lock(mutex);
        // No remaining timeouts.
        if (pingTimeouts.list.empty()) {
            break;
        }
        OutboundMessage* message = &pingTimeouts.list.front();
        SpinLock::Lock lock_message(message->mutex);
        // No remaining expired timeouts.
        if (!message->pingTimeout.hasElapsed()) {
            break;
        }
        // Found expired timeout.
        pingTimeouts.setTimeout(&message->pingTimeout);
        lock.unlock();  // End Sender critical section.

        // Message is done or has failed; Signal the Transport and wait for the
        // message to be dropped.
        if (message->acknowledged || message->failed) {
            transport->hintUpdatedOp(message->op);
            continue;
        }

        // Have not heard from the Receiver in the last timeout period.  Ping
        // the receiver to ensure it still knows about this Message.
        ControlPacket::send<Protocol::Packet::PingHeader>(
            message->message.driver, message->destination, message->id);
    }
}

}  // namespace Core
}  // namespace Homa
