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
 *      The Transport object that owns this Sender.
 * @param transportId
 *      Unique identifier for the Transport that owns this Sender.
 * @param messageTimeoutCycles
 *      Number of cycles of inactivity to wait before this Sender declares an
 *      OutboundMessage send failure.
 * @param pingIntervalCycles
 *      Number of cycles of inactivity to wait between checking on the liveness
 *      of an OutboundMessage.
 */
Sender::Sender(Transport* transport, uint64_t transportId,
               uint64_t messageTimeoutCycles, uint64_t pingIntervalCycles)
    : mutex()
    , transport(transport)
    , transportId(transportId)
    , nextMessageSequenceNumber(1)
    , DRIVER_QUEUED_BYTE_LIMIT(2 * transport->driver->getMaxPayloadSize())
    , outboundMessages()
    , readyQueue()
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
    messageTimeouts.cancelTimeout(&message->messageTimeout);
    pingTimeouts.cancelTimeout(&message->pingTimeout);
    readyQueue.remove(&message->readyQueueNode);
    lock.unlock();  // End Sender critical section

    message->state.store(OutboundMessage::State::COMPLETED);
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
    uint16_t index = header->index;
    uint16_t resendEnd = index + header->num;

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
    // In case a GRANT may have been lost, consider the RESEND a GRANT.
    assert(resendEnd <= message->getNumPackets());
    if (message->grantIndex < resendEnd) {
        message->grantIndex = resendEnd;
        hintMessageReady(message, lock, lock_message);
    }
    lock.unlock();  // End Sender critical section

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
            Driver::Packet* packet = message->getPacket(index++);
            message->driver->sendPacket(packet);
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
    hintMessageReady(message, lock, lock_message);
    lock.unlock();  // End Sender critical section

    assert(header->indexLimit <= message->getNumPackets());
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

    // Lock handoff.
    SpinLock::Lock lock_message(message->mutex);
    if (message->state == OutboundMessage::State::IN_PROGRESS ||
        message->state == OutboundMessage::State::SENT) {
        // Restart sending the message from scratch.
        message->state.store(OutboundMessage::State::IN_PROGRESS);
        message->sentIndex = 0;
        // TODO(cstlee): May want to use the unscheduled-limit here instead of
        // just granting a single packet.
        message->grantIndex = 1;
        // Need to set the rawUnsentBytes before calling hintMessageReady(); the
        // member variable is used by the helper method.
        message->rawUnsentBytes =
            message->rawLength() +
            (message->PACKET_HEADER_LENGTH * message->getNumPackets());
        hintMessageReady(message, lock, lock_message);
    } else {
        // The message is already considered "done" so the UNKNOWN packet must
        // be a stale response to a ping.
    }
    lock.unlock();  // End Sender critical section.

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
    messageTimeouts.cancelTimeout(&message->messageTimeout);
    pingTimeouts.cancelTimeout(&message->pingTimeout);
    readyQueue.remove(&message->readyQueueNode);
    lock.unlock();  // End Sender critical section

    assert(message->state != OutboundMessage::State::COMPLETED);
    message->state.store(OutboundMessage::State::FAILED);
    transport->hintUpdatedOp(message->op);
    driver->releasePackets(&packet, 1);
}

/**
 * Queue a message to be sent.
 *
 * @param message
 *      OutboundMessage to be sent.
 * @param destination
 *      Destination address for this message.
 *
 * @sa dropMessage()
 */
void
Sender::sendMessage(OutboundMessage* message, Driver::Address destination)
{
    SpinLock::UniqueLock lock(mutex);
    SpinLock::Lock lock_message(message->mutex);

    assert(message->driver == transport->driver);

    Protocol::MessageId id(transportId, nextMessageSequenceNumber++);
    outboundMessages.insert({id, message});
    messageTimeouts.setTimeout(&message->messageTimeout);
    pingTimeouts.setTimeout(&message->pingTimeout);
    // Need to set the rawUnsentBytes before calling hintMessageReady(); the
    // member variable is used by the helper method.
    message->rawUnsentBytes =
        message->rawLength() +
        (message->PACKET_HEADER_LENGTH * message->getNumPackets());
    hintMessageReady(message, lock, lock_message);
    lock.unlock();  // End sender critical section.

    message->state.store(OutboundMessage::State::IN_PROGRESS);
    message->id = id;
    message->destination = destination;
    uint32_t unscheduledBytes =
        RTT_TIME_US * (message->driver->getBandwidth() / 8);

    uint32_t actualMessageLen = 0;
    // fill out metadata.
    for (uint16_t i = 0; i < message->getNumPackets(); ++i) {
        Driver::Packet* packet = message->getPacket(i);
        if (packet == nullptr) {
            PANIC(
                "Incomplete message with id (%lu:%lu); missing packet "
                "at offset %d; this shouldn't happen.",
                message->id.transportId, message->id.sequence,
                i * message->PACKET_DATA_LENGTH);
        }

        packet->address = message->destination;
        packet->priority = 0;
        new (packet->payload)
            Protocol::Packet::DataHeader(message->id, message->rawLength(), i);
        actualMessageLen += (packet->length - message->PACKET_HEADER_LENGTH);
    }

    // perform sanity checks.
    assert(message->rawLength() == actualMessageLen);
    assert(message->PACKET_HEADER_LENGTH ==
           sizeof(Protocol::Packet::DataHeader));

    message->grantIndex = unscheduledBytes / message->PACKET_DATA_LENGTH;
    message->grantIndex =
        std::min(message->grantIndex, message->getNumPackets());
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
        readyQueue.remove(&message->readyQueueNode);
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
    checkPingTimeouts();
    checkMessageTimeouts();
}

/**
 * Process any outbound messages that have timed out due to lack of activity
 * from the Receiver.
 *
 * Pulled out of poll() for ease of testing.
 */
void
Sender::checkMessageTimeouts()
{
    while (true) {
        SpinLock::Lock lock(mutex);
        // No remaining timeouts.
        if (messageTimeouts.list.empty()) {
            break;
        }
        OutboundMessage* message = &messageTimeouts.list.front();
        SpinLock::Lock lock_message(message->mutex);
        // No remaining expired timeouts.
        if (!message->messageTimeout.hasElapsed()) {
            break;
        }
        // Found expired timeout.
        if (message->state != OutboundMessage::State::COMPLETED) {
            message->state.store(OutboundMessage::State::FAILED);
        }
        messageTimeouts.cancelTimeout(&message->messageTimeout);
        pingTimeouts.cancelTimeout(&message->pingTimeout);
        readyQueue.remove(&message->readyQueueNode);
        transport->hintUpdatedOp(message->op);
    }
}

/**
 * Process any outbound messages that need to be pinged to ensure the message
 * is kept alive by the receiver.
 *
 * Pulled out of poll() for ease of testing.
 */
void
Sender::checkPingTimeouts()
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
        if (message->state == OutboundMessage::State::COMPLETED ||
            message->state == OutboundMessage::State::FAILED) {
            pingTimeouts.cancelTimeout(&message->pingTimeout);
            continue;
        } else {
            pingTimeouts.setTimeout(&message->pingTimeout);
        }
        lock.unlock();  // End Sender critical section.

        // Have not heard from the Receiver in the last timeout period. Ping
        // the receiver to ensure it still knows about this Message.
        ControlPacket::send<Protocol::Packet::PingHeader>(
            message->driver, message->destination, message->id);
    }
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
    uint32_t queuedBytesEstimate = transport->driver->getQueuedBytes();
    auto it = readyQueue.begin();
    while (it != readyQueue.end()) {
        OutboundMessage& message = *it;
        SpinLock::Lock lock_message(message.mutex);
        assert(message.driver == transport->driver);
        assert(message.grantIndex <= message.getNumPackets());
        while (message.sentIndex < message.grantIndex) {
            Driver::Packet* packet = message.getPacket(message.sentIndex);
            assert(packet != nullptr);
            queuedBytesEstimate += packet->length;
            // Check if the send limit would be reached...
            if (queuedBytesEstimate > DRIVER_QUEUED_BYTE_LIMIT) {
                break;
            }
            // ... if not, send away!
            message.driver->sendPacket(packet);
            assert(message.rawUnsentBytes >= packet->length);
            message.rawUnsentBytes -= packet->length;
            ++message.sentIndex;
        }
        if (message.sentIndex >= message.getNumPackets()) {
            // We have finished sending the message.
            message.state.store(OutboundMessage::State::SENT);
            transport->hintUpdatedOp(message.op);
            it = readyQueue.remove(it);
        } else if (message.sentIndex >= message.grantIndex) {
            // We have sent every granted packet.
            it = readyQueue.remove(it);
        } else {
            // We hit the DRIVER_QUEUED_BYTES_LIMIT; stop sending for now.
            break;
        }
    }

    sending.clear();
}

/**
 * Hint that the provided message has packet(s) that are/is ready to be sent.
 *
 * Note: Spurious calls to this method (i.e. call this method when the Message
 * is not actually ready) is allowed but can add a performance overhead.  This
 * behavior is allowed so that we can forgo an additional "ready check" in the
 * common case where we almost always know that it is ready.
 *
 * @param message
 *      The Message that is ready to be sent.
 * @param lock
 *      Ensures the Sender::mutex is held during this call.
 * @param lock_message
 *      Ensures OutboundMessage::mutex is held during this call.
 */
void
Sender::hintMessageReady(OutboundMessage* message,
                         const SpinLock::UniqueLock& lock,
                         const SpinLock::Lock& lock_message)
{
    // NOTICE: Holding the Sender::mutex (lock) is needed to prevent deadlock.
    // If this method were allowed to execute concurrently, two threads could
    // lock two messages (lock_message & lock_message_other) in different orders
    // resulting in deadlock.
    (void)lock;
    (void)lock_message;
    if (readyQueue.contains(&message->readyQueueNode)) {
        return;
    }
    auto it = readyQueue.begin();
    while (it != readyQueue.end()) {
        SpinLock::Lock lock_message_other(it->mutex);
        if (it->rawUnsentBytes > message->rawUnsentBytes) {
            break;
        }
        ++it;
    }
    readyQueue.insert(it, &message->readyQueueNode);
}

}  // namespace Core
}  // namespace Homa
