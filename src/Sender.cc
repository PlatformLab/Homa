/* Copyright (c) 2018-2020, Stanford University
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

#include <Cycles.h>

#include <algorithm>

#include "ControlPacket.h"
#include "Debug.h"
#include "Transport.h"

namespace Homa {
namespace Core {

/**
 * Sender Constructor.
 *
 * @param transport
 *      The Transport object that owns this Sender.
 * @param transportId
 *      Unique identifier for the Transport that owns this Sender.
 * @param policyManager
 *      Provides information about the network packet priority policies.
 * @param messageTimeoutCycles
 *      Number of cycles of inactivity to wait before this Sender declares an
 *      Sender::Message send failure.
 * @param pingIntervalCycles
 *      Number of cycles of inactivity to wait between checking on the liveness
 *      of an Sender::Message.
 */
Sender::Sender(Transport* transport, uint64_t transportId,
               Policy::Manager* policyManager, uint64_t messageTimeoutCycles,
               uint64_t pingIntervalCycles)
    : transport(transport)
    , transportId(transportId)
    , policyManager(policyManager)
    , nextMessageSequenceNumber(1)
    , DRIVER_QUEUED_BYTE_LIMIT(2 * transport->driver->getMaxPayloadSize())
    , messageBuckets(messageTimeoutCycles, pingIntervalCycles)
    , queueMutex()
    , sendQueue()
    , sending()
    , sendReady(false)
    , messageAllocator()
{}

/**
 * Sender Destructor
 */
Sender::~Sender() {}

/**
 * Allocate an OutMessage that can be sent with this Sender.
 */
Homa::OutMessage*
Sender::allocMessage()
{
    SpinLock::Lock lock_allocator(messageAllocator.mutex);
    return messageAllocator.pool.construct(this, transport->driver);
}

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
    Protocol::Packet::DoneHeader* header =
        static_cast<Protocol::Packet::DoneHeader*>(packet->payload);
    Protocol::MessageId msgId = header->common.messageId;

    MessageBucket* bucket = messageBuckets.getBucket(msgId);
    SpinLock::Lock lock(bucket->mutex);
    Message* message = bucket->findMessage(msgId, lock);

    if (message == nullptr) {
        // No message for this DONE packet; must be old. Just drop it.
        driver->releasePackets(&packet, 1);
        return;
    }

    // Process DONE packet
    OutMessage::Status status = message->getStatus();
    switch (status) {
        case OutMessage::Status::SENT:
            // Expected behavior
            bucket->messageTimeouts.cancelTimeout(&message->messageTimeout);
            bucket->pingTimeouts.cancelTimeout(&message->pingTimeout);
            message->state.store(OutMessage::Status::COMPLETED);
            break;
        case OutMessage::Status::CANCELED:
            // Canceled by the the application; just ignore the DONE.
            break;
        case OutMessage::Status::COMPLETED:
            // Message already DONE
            NOTICE("Message (%lu, %lu) received duplicate DONE confirmation",
                   msgId.transportId, msgId.sequence);
            break;
        case OutMessage::Status::FAILED:
            WARNING(
                "Message (%lu, %lu) received DONE confirmation after the "
                "message was already declared FAILED",
                msgId.transportId, msgId.sequence);
            break;
        case OutMessage::Status::NOT_STARTED:
            WARNING(
                "Message (%lu, %lu) received DONE confirmation but sending has "
                "NOT_STARTED (message not yet sent); DONE is ignored.",
                msgId.transportId, msgId.sequence);
            break;
        case OutMessage::Status::IN_PROGRESS:
            WARNING(
                "Message (%lu, %lu) received DONE confirmation while sending "
                "is still IN_PROGRESS (message not completely sent); DONE is "
                "ignored.",
                msgId.transportId, msgId.sequence);
            break;
        default:
            // Unexpected status
            ERROR(
                "Message (%lu, %lu) received DONE confirmation while in an "
                "unexpected state; DONE is ignored.",
                msgId.transportId, msgId.sequence);
            break;
    }

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
    Protocol::Packet::ResendHeader* header =
        static_cast<Protocol::Packet::ResendHeader*>(packet->payload);
    Protocol::MessageId msgId = header->common.messageId;
    int index = header->index;
    int resendEnd = index + header->num;

    MessageBucket* bucket = messageBuckets.getBucket(msgId);
    SpinLock::Lock lock(bucket->mutex);
    Message* message = bucket->findMessage(msgId, lock);

    // Check for unexpected conditions
    if (message == nullptr) {
        // No message for this RESEND; RESEND must be old. Just ignore it; this
        // case should be pretty rare and the Receiver will timeout eventually.
        driver->releasePackets(&packet, 1);
        return;
    } else if (message->getNumPackets() < 2) {
        // We should never get a RESEND for a single packet message.  Just
        // ignore this RESEND from a buggy Receiver.
        WARNING(
            "Message (%lu, %lu) with only 1 packet received unexpected RESEND "
            "request; peer Transport may be confused.",
            msgId.transportId, msgId.sequence);
        driver->releasePackets(&packet, 1);
        return;
    }

    bucket->messageTimeouts.setTimeout(&message->messageTimeout);
    bucket->pingTimeouts.setTimeout(&message->pingTimeout);

    SpinLock::Lock lock_queue(queueMutex);
    QueuedMessageInfo* info = &message->queuedMessageInfo;

    // Check if RESEND request is out of range.
    if (index >= info->packets->getNumPackets() ||
        resendEnd > info->packets->getNumPackets()) {
        WARNING(
            "Message (%lu, %lu) RESEND request range out of bounds: requested "
            "range [%d, %d); message only contains %d packets; peer Transport "
            "may be confused.",
            msgId.transportId, msgId.sequence, index, resendEnd,
            info->packets->getNumPackets());
        driver->releasePackets(&packet, 1);
        return;
    }

    // In case a GRANT may have been lost, consider the RESEND a GRANT.
    if (info->packetsGranted < resendEnd) {
        info->packetsGranted = resendEnd;
        // Note that the priority of messages under the unscheduled byte limit
        // will never be overridden since the resend index will not exceed the
        // preset packetsGranted.
        info->priority = header->priority;
        sendReady.store(true);
    }

    if (index >= info->packetsSent) {
        // If this RESEND is only requesting unsent packets, it must be that
        // this Sender has been busy and the Receiver is trying to ensure there
        // are no lost packets.  Reply BUSY and allow this Sender to send DATA
        // when it's ready.
        ControlPacket::send<Protocol::Packet::BusyHeader>(
            driver, info->destination, info->id);
    } else {
        // There are some packets to resend but only resend packets that have
        // already been sent.
        resendEnd = std::min(resendEnd, info->packetsSent);
        int resendPriority = policyManager->getResendPriority();
        for (uint16_t i = index; i < resendEnd; ++i) {
            Driver::Packet* packet = info->packets->getPacket(index++);
            packet->priority = resendPriority;
            // Packets will be sent at the priority their original priority.
            transport->driver->sendPacket(packet);
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
    Protocol::Packet::GrantHeader* header =
        static_cast<Protocol::Packet::GrantHeader*>(packet->payload);
    Protocol::MessageId msgId = header->common.messageId;

    MessageBucket* bucket = messageBuckets.getBucket(msgId);
    SpinLock::Lock lock(bucket->mutex);
    Message* message = bucket->findMessage(msgId, lock);
    if (message == nullptr) {
        // No message for this grant; grant must be old. Just drop it.
        driver->releasePackets(&packet, 1);
        return;
    }

    bucket->messageTimeouts.setTimeout(&message->messageTimeout);
    bucket->pingTimeouts.setTimeout(&message->pingTimeout);

    if (message->state.load() == OutMessage::Status::IN_PROGRESS) {
        SpinLock::Lock lock_queue(queueMutex);
        QueuedMessageInfo* info = &message->queuedMessageInfo;

        // Convert the byteLimit to a packet index limit such that the packet
        // that holds the last granted byte is also considered granted.  This
        // can cause at most 1 packet worth of data to be sent without a grant
        // but allows the sender to always send full packets.
        int incomingGrantIndex =
            (header->byteLimit + info->packets->PACKET_DATA_LENGTH - 1) /
            info->packets->PACKET_DATA_LENGTH;

        // Make that grants don't exceed the number of packets.  Internally,
        // the sender always assumes that packetsGranted <= numPackets.
        if (incomingGrantIndex > info->packets->getNumPackets()) {
            WARNING(
                "Message (%lu, %lu) GRANT exceeds message length; granted "
                "packets: %d, message packets %d; extra grants are ignored.",
                msgId.transportId, msgId.sequence, incomingGrantIndex,
                info->packets->getNumPackets());
            incomingGrantIndex = info->packets->getNumPackets();
        }

        if (info->packetsGranted < incomingGrantIndex) {
            info->packetsGranted = incomingGrantIndex;
            // Note that the priority of messages under the unscheduled byte
            // limit will never be overridden since the incomingGrantIndex will
            // not exceed the preset packetsGranted.
            info->priority = header->priority;
            sendReady.store(true);
        }
    }

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
    Protocol::Packet::UnknownHeader* header =
        static_cast<Protocol::Packet::UnknownHeader*>(packet->payload);
    Protocol::MessageId msgId = header->common.messageId;

    MessageBucket* bucket = messageBuckets.getBucket(msgId);
    SpinLock::Lock lock(bucket->mutex);
    Message* message = bucket->findMessage(msgId, lock);

    if (message == nullptr) {
        // No message was found. Just drop the packet.
        driver->releasePackets(&packet, 1);
        return;
    }

    OutMessage::Status status = message->getStatus();
    if (status == OutMessage::Status::IN_PROGRESS ||
        status == OutMessage::Status::SENT) {
        // Message isn't done yet so we will restart sending the message.

        // Make sure the message is not in the sendQueue before making any
        // changes to the message.
        if (message->getNumPackets() > 1) {
            SpinLock::Lock lock_queue(queueMutex);
            QueuedMessageInfo* info = &message->queuedMessageInfo;
            if (message->state == OutMessage::Status::IN_PROGRESS) {
                assert(sendQueue.contains(&info->sendQueueNode));
                sendQueue.remove(&info->sendQueueNode);
            }
            assert(!sendQueue.contains(&info->sendQueueNode));
        }

        message->state.store(OutMessage::Status::IN_PROGRESS);

        // Get the current policy for unscheduled bytes.
        Policy::Unscheduled policy = policyManager->getUnscheduledPolicy(
            message->destination, message->rawLength());
        int unscheduledIndexLimit =
            ((policy.unscheduledByteLimit + message->PACKET_DATA_LENGTH - 1) /
             message->PACKET_DATA_LENGTH);

        // Update the policy version for each packet
        for (uint16_t i = 0; i < message->getNumPackets(); ++i) {
            Driver::Packet* dataPacket = message->getPacket(i);
            assert(dataPacket != nullptr);
            Protocol::Packet::DataHeader* header =
                static_cast<Protocol::Packet::DataHeader*>(dataPacket->payload);
            header->policyVersion = policy.version;
            header->unscheduledIndexLimit =
                Util::downCast<uint16_t>(unscheduledIndexLimit);
        }

        // Reset the timeouts
        bucket->messageTimeouts.setTimeout(&message->messageTimeout);
        bucket->pingTimeouts.setTimeout(&message->pingTimeout);

        assert(message->getNumPackets() > 0);
        if (message->getNumPackets() == 1) {
            // If there is only one packet in the message, send it right away.
            Driver::Packet* dataPacket = message->getPacket(0);
            assert(dataPacket != nullptr);
            dataPacket->priority = policy.priority;
            transport->driver->sendPacket(dataPacket);
            message->state.store(OutMessage::Status::SENT);
        } else {
            // Otherwise, queue the message to be sent in SRPT order.
            SpinLock::Lock lock_queue(queueMutex);
            QueuedMessageInfo* info = &message->queuedMessageInfo;
            // Some of these values should still be set from when the message
            // was first queued.
            assert(info->id == message->id);
            assert(info->destination == message->destination);
            assert(info->packets == message);
            // Some values need to be updated
            info->unsentBytes = message->rawLength();
            info->packetsGranted =
                std::min(unscheduledIndexLimit, message->getNumPackets());
            info->priority = policy.priority;
            info->packetsSent = 0;
            // Insert and move message into the correct order in the priority
            // queue.
            sendQueue.push_front(&info->sendQueueNode);
            Intrusive::deprioritize<Message>(
                &sendQueue, &info->sendQueueNode,
                QueuedMessageInfo::ComparePriority());
            sendReady.store(true);
        }
    } else {
        // The message is already considered "done" so the UNKNOWN packet
        // must be a stale response to a ping.
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
    Protocol::Packet::ErrorHeader* header =
        static_cast<Protocol::Packet::ErrorHeader*>(packet->payload);
    Protocol::MessageId msgId = header->common.messageId;

    MessageBucket* bucket = messageBuckets.getBucket(msgId);
    SpinLock::Lock lock(bucket->mutex);
    Message* message = bucket->findMessage(msgId, lock);
    if (message == nullptr) {
        // No message for this ERROR packet; must be old. Just drop it.
        driver->releasePackets(&packet, 1);
        return;
    }

    OutMessage::Status status = message->getStatus();
    switch (status) {
        case OutMessage::Status::SENT:
            // Message was sent and a failure notification was received.
            bucket->messageTimeouts.cancelTimeout(&message->messageTimeout);
            bucket->pingTimeouts.cancelTimeout(&message->pingTimeout);
            message->state.store(OutMessage::Status::FAILED);
            break;
        case OutMessage::Status::CANCELED:
            // Canceled by the the application; just ignore the ERROR.
            break;
        case OutMessage::Status::NOT_STARTED:
            WARNING(
                "Message (%lu, %lu) received ERROR notification but sending "
                "has NOT_STARTED (message not yet sent); ERROR is ignored.",
                msgId.transportId, msgId.sequence);
            break;
        case OutMessage::Status::IN_PROGRESS:
            WARNING(
                "Message (%lu, %lu) received ERROR notification while sending "
                "is still IN_PROGRESS (message not completely sent); ERROR is "
                "ignored.",
                msgId.transportId, msgId.sequence);
            break;
        case OutMessage::Status::COMPLETED:
            // Message already DONE
            WARNING(
                "Message (%lu, %lu) received ERROR notification after the "
                "message was already declared COMPLETED; ERROR is ignored.",
                msgId.transportId, msgId.sequence);
            break;
        case OutMessage::Status::FAILED:
            NOTICE("Message (%lu, %lu) received duplicate ERROR notification.",
                   msgId.transportId, msgId.sequence);
            break;
        default:
            // Unexpected status
            ERROR(
                "Message (%lu, %lu) received ERROR notification while in an "
                "unexpected state; ERROR is ignored.",
                msgId.transportId, msgId.sequence);
            break;
    }

    driver->releasePackets(&packet, 1);
}

/**
 * Allow the Sender to make progress toward sending outgoing messages.
 *
 * This method must be called eagerly to ensure messages are sent.
 */
void
Sender::poll()
{
    trySend();
}

/**
 * Process any Sender timeouts that have expired.
 *
 * This method must be called periodically to ensure timely handling of
 * expired timeouts.
 *
 * @return
 *      The rdtsc cycle time when this method should be called again.
 */
uint64_t
Sender::checkTimeouts()
{
    uint64_t nextTimeout;

    // Ping Timeout
    nextTimeout = checkPingTimeouts();

    // Message Timeout
    uint64_t messageTimeout = checkMessageTimeouts();
    nextTimeout = nextTimeout < messageTimeout ? nextTimeout : messageTimeout;

    return nextTimeout;
}

/**
 * Queue a message to be sent.
 *
 * @param message
 *      Sender::Message to be sent.
 * @param destination
 *      Destination address for this message.
 *
 * @sa dropMessage()
 */
void
Sender::sendMessage(Sender::Message* message, Driver::Address destination)
{
    // Prepare the message
    assert(message->driver == transport->driver);
    // Allocate a new message id
    Protocol::MessageId id(transportId, nextMessageSequenceNumber++);

    Policy::Unscheduled policy =
        policyManager->getUnscheduledPolicy(destination, message->rawLength());
    int unscheduledPacketLimit =
        ((policy.unscheduledByteLimit + message->PACKET_DATA_LENGTH - 1) /
         message->PACKET_DATA_LENGTH);

    message->id = id;
    message->destination = destination;
    message->state.store(OutMessage::Status::IN_PROGRESS);

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
        new (packet->payload) Protocol::Packet::DataHeader(
            message->id, message->rawLength(), policy.version,
            Util::downCast<uint16_t>(unscheduledPacketLimit), i);
        actualMessageLen += (packet->length - message->TRANSPORT_HEADER_LENGTH);
    }

    // perform sanity checks.
    assert(message->driver == transport->driver);
    assert(message->rawLength() == actualMessageLen);
    assert(message->TRANSPORT_HEADER_LENGTH ==
           sizeof(Protocol::Packet::DataHeader));

    // Track message
    MessageBucket* bucket = messageBuckets.getBucket(message->id);
    SpinLock::Lock lock(bucket->mutex);
    assert(!bucket->messages.contains(&message->bucketNode));
    bucket->messages.push_back(&message->bucketNode);
    bucket->messageTimeouts.setTimeout(&message->messageTimeout);
    bucket->pingTimeouts.setTimeout(&message->pingTimeout);

    assert(message->getNumPackets() > 0);
    if (message->getNumPackets() == 1) {
        // If there is only one packet in the message, send it right away.
        Driver::Packet* packet = message->getPacket(0);
        assert(packet != nullptr);
        packet->priority = policy.priority;
        transport->driver->sendPacket(packet);
        message->state.store(OutMessage::Status::SENT);
    } else {
        // Otherwise, queue the message to be sent in SRPT order.
        SpinLock::Lock lock_queue(queueMutex);
        QueuedMessageInfo* info = &message->queuedMessageInfo;
        info->id = id;
        info->destination = message->destination;
        info->packets = message;
        info->unsentBytes = message->rawLength();
        info->packetsGranted =
            std::min(unscheduledPacketLimit, message->getNumPackets());
        info->priority = policy.priority;
        info->packetsSent = 0;
        // Insert and move message into the correct order in the priority queue.
        sendQueue.push_front(&info->sendQueueNode);
        Intrusive::deprioritize<Message>(&sendQueue, &info->sendQueueNode,
                                         QueuedMessageInfo::ComparePriority());
        sendReady.store(true);
    }
}

/**
 * Inform the Sender that a Message no longer needs to be sent.
 *
 * @param message
 *      The Sender::Message that is no longer needs to be sent.
 */
void
Sender::cancelMessage(Sender::Message* message)
{
    Protocol::MessageId msgId = message->id;
    MessageBucket* bucket = messageBuckets.getBucket(msgId);
    SpinLock::Lock lock(bucket->mutex);
    if (bucket->messages.contains(&message->bucketNode)) {
        bucket->messageTimeouts.cancelTimeout(&message->messageTimeout);
        bucket->pingTimeouts.cancelTimeout(&message->pingTimeout);
        if (message->getNumPackets() > 1 &&
            message->state == OutMessage::Status::IN_PROGRESS) {
            // Check to see if the message needs to be dequeued.
            SpinLock::Lock lock_queue(queueMutex);
            // Recheck state with lock in case it change right before this.
            if (message->state == OutMessage::Status::IN_PROGRESS) {
                QueuedMessageInfo* info = &message->queuedMessageInfo;
                assert(sendQueue.contains(&info->sendQueueNode));
                sendQueue.remove(&info->sendQueueNode);
            }
        }
        bucket->messages.remove(&message->bucketNode);
        message->state.store(OutMessage::Status::CANCELED);
    }
}

/**
 * Inform the Sender that a Message is no longer needed.
 *
 * @param message
 *      The Sender::Message that is no longer needed.
 */
void
Sender::dropMessage(Sender::Message* message)
{
    cancelMessage(message);
    SpinLock::Lock lock_allocator(messageAllocator.mutex);
    messageAllocator.pool.destroy(message);
}

/**
 * Process any outbound messages that have timed out due to lack of activity
 * from the Receiver.
 *
 * Pulled out of checkTimeouts() for ease of testing.
 *
 * @return
 *      The rdtsc cycle time when this method should be called again.
 */
uint64_t
Sender::checkMessageTimeouts()
{
    uint64_t globalNextTimeout = UINT64_MAX;
    assert(MessageBucketMap::NUM_BUCKETS > 0);
    for (int i = 0; i < MessageBucketMap::NUM_BUCKETS; ++i) {
        MessageBucket* bucket = messageBuckets.buckets.at(i);
        uint64_t nextTimeout = 0;
        while (true) {
            SpinLock::Lock lock(bucket->mutex);
            // No remaining timeouts.
            if (bucket->messageTimeouts.list.empty()) {
                nextTimeout = PerfUtils::Cycles::rdtsc() +
                              bucket->messageTimeouts.timeoutIntervalCycles;
                break;
            }
            Message* message = &bucket->messageTimeouts.list.front();
            // No remaining expired timeouts.
            if (!message->messageTimeout.hasElapsed()) {
                nextTimeout = message->messageTimeout.expirationCycleTime;
                break;
            }
            // Found expired timeout.
            if (message->state != OutMessage::Status::COMPLETED) {
                message->state.store(OutMessage::Status::FAILED);
            }
            bucket->messageTimeouts.cancelTimeout(&message->messageTimeout);
            bucket->pingTimeouts.cancelTimeout(&message->pingTimeout);
        }
        globalNextTimeout = std::min(globalNextTimeout, nextTimeout);
    }
    return globalNextTimeout;
}

/**
 * Process any outbound messages that need to be pinged to ensure the
 * message is kept alive by the receiver.
 *
 * Pulled out of checkTimeouts() for ease of testing.
 *
 * @return
 *      The rdtsc cycle time when this method should be called again.
 */
uint64_t
Sender::checkPingTimeouts()
{
    uint64_t globalNextTimeout = UINT64_MAX;
    assert(MessageBucketMap::NUM_BUCKETS > 0);
    for (int i = 0; i < MessageBucketMap::NUM_BUCKETS; ++i) {
        MessageBucket* bucket = messageBuckets.buckets.at(i);
        uint64_t nextTimeout = 0;
        while (true) {
            SpinLock::Lock lock(bucket->mutex);
            // No remaining timeouts.
            if (bucket->pingTimeouts.list.empty()) {
                nextTimeout = PerfUtils::Cycles::rdtsc() +
                              bucket->pingTimeouts.timeoutIntervalCycles;
                break;
            }
            Message* message = &bucket->pingTimeouts.list.front();
            // No remaining expired timeouts.
            if (!message->pingTimeout.hasElapsed()) {
                nextTimeout = message->pingTimeout.expirationCycleTime;
                break;
            }
            // Found expired timeout.
            if (message->state == OutMessage::Status::COMPLETED ||
                message->state == OutMessage::Status::FAILED) {
                bucket->pingTimeouts.cancelTimeout(&message->pingTimeout);
                continue;
            } else {
                bucket->pingTimeouts.setTimeout(&message->pingTimeout);
            }

            // Have not heard from the Receiver in the last timeout period. Ping
            // the receiver to ensure it still knows about this Message.
            ControlPacket::send<Protocol::Packet::PingHeader>(
                message->driver, message->destination, message->id);
        }
        globalNextTimeout = std::min(globalNextTimeout, nextTimeout);
    }
    return globalNextTimeout;
}

/**
 * Send out packets for any messages with unscheduled/granted bytes.
 */
void
Sender::trySend()
{
    // Skip when there are no messages to send.
    if (!sendReady) {
        return;
    }

    // Skip sending if another thread is already working on it.
    if (sending.test_and_set()) {
        return;
    }

    /* The goal is to send out packets for messages that have bytes that have
     * been "granted" (both scheduled and unscheduled grants).  Messages with
     * the fewest remaining bytes to send (unsentBytes) are sent first (SRPT).
     * Each time this method is called we will try to send enough packet to keep
     * the NIC busy but not too many as to cause excessive queue in the NIC.
     */
    SpinLock::UniqueLock lock_queue(queueMutex);
    uint32_t queuedBytesEstimate = transport->driver->getQueuedBytes();
    // Optimistically assume we will finish sending every granted packet this
    // round; we will set again sendReady if it turns out we don't finish.
    sendReady = false;
    auto it = sendQueue.begin();
    while (it != sendQueue.end()) {
        Message& message = *it;
        assert(message.state.load() == OutMessage::Status::IN_PROGRESS);
        QueuedMessageInfo* info = &message.queuedMessageInfo;
        assert(info->packetsGranted <= info->packets->getNumPackets());
        while (info->packetsSent < info->packetsGranted) {
            Driver::Packet* packet =
                info->packets->getPacket(info->packetsSent);
            assert(packet != nullptr);
            queuedBytesEstimate += packet->length;
            // Check if the send limit would be reached...
            if (queuedBytesEstimate > DRIVER_QUEUED_BYTE_LIMIT) {
                break;
            }
            // ... if not, send away!
            packet->priority = info->priority;
            transport->driver->sendPacket(packet);
            int packetDataBytes =
                packet->length - info->packets->TRANSPORT_HEADER_LENGTH;
            assert(info->unsentBytes >= packetDataBytes);
            info->unsentBytes -= packetDataBytes;
            // The Message's unsentBytes only ever decreases.  See if the
            // updated Message should move up in the queue.
            Intrusive::prioritize<Message>(
                &sendQueue, &info->sendQueueNode,
                QueuedMessageInfo::ComparePriority());
            ++info->packetsSent;
        }
        if (info->packetsSent >= info->packets->getNumPackets()) {
            // We have finished sending the message.
            message.state.store(OutMessage::Status::SENT);
            it = sendQueue.remove(it);
        } else if (info->packetsSent >= info->packetsGranted) {
            // We have sent every granted packet.
            ++it;
        } else {
            // We hit the DRIVER_QUEUED_BYTES_LIMIT; stop sending for now.
            // We didn't finish sending all granted packets.
            sendReady = true;
            break;
        }
    }

    sending.clear();
}

}  // namespace Core
}  // namespace Homa
