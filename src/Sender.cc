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
#include "Perf.h"

namespace Homa {
namespace Core {

/**
 * Sender Constructor.
 *
 * @param transportId
 *      Unique identifier for the Transport that owns this Sender.
 * @param driver
 *      The driver used to send and receive packets.
 * @param policyManager
 *      Provides information about the network packet priority policies.
 * @param messageTimeoutCycles
 *      Number of cycles of inactivity to wait before this Sender declares an
 *      Sender::Message send failure.
 * @param pingIntervalCycles
 *      Number of cycles of inactivity to wait between checking on the liveness
 *      of an Sender::Message.
 */
Sender::Sender(uint64_t transportId, Driver* driver,
               Policy::Manager* policyManager, uint64_t messageTimeoutCycles,
               uint64_t pingIntervalCycles)
    : transportId(transportId)
    , driver(driver)
    , policyManager(policyManager)
    , nextMessageSequenceNumber(1)
    , DRIVER_QUEUED_BYTE_LIMIT(2 * driver->getMaxPayloadSize())
    , messageBuckets(messageTimeoutCycles, pingIntervalCycles)
    , queueMutex()
    , sendQueue()
    , sending()
    , sendReady(false)
    , nextBucketIndex(0)
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
Sender::allocMessage(uint16_t sourcePort)
{
    SpinLock::Lock lock_allocator(messageAllocator.mutex);
    Perf::counters.allocated_tx_messages.add(1);
    return messageAllocator.pool.construct(this, sourcePort);
}

/**
 * Execute the common processing logic that is shared among all incoming control
 * packets.
 *
 * @param packet
 *      Incoming control packet to be processed.
 * @param resetTimeout
 *      True if we should update the timeouts in response to the packet.
 * @return
 *      Pointer to the message targeted by the incoming packet, or nullptr if no
 *      matching message can be found.
 */
Sender::Message*
Sender::handleIncomingPacket(Driver::Packet* packet, bool resetTimeout)
{
    Protocol::Packet::CommonHeader* commonHeader =
        static_cast<Protocol::Packet::CommonHeader*>(packet->payload);
    Protocol::MessageId msgId = commonHeader->messageId;
    MessageBucket* bucket = messageBuckets.getBucket(msgId);
    SpinLock::Lock lock(bucket->mutex);
    Message* message = bucket->findMessage(msgId, lock);
    if (resetTimeout) {
        message->resetTimeout(lock);
    }
    return message;
}

/**
 * Process an incoming DONE packet.
 *
 * @param packet
 *      Incoming DONE packet to be processed.
 */
void
Sender::handleDonePacket(Driver::Packet* packet)
{
    Message* message = handleIncomingPacket(packet, false);
    if (message == nullptr) {
        // No message for this DONE packet; must be old.
        return;
    }

    // Process DONE packet
    Protocol::MessageId msgId = message->id;
    OutMessage::Status status = message->getStatus();
    switch (status) {
        case OutMessage::Status::SENT:
            // Expected behavior
            message->setStatus(OutMessage::Status::COMPLETED);
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
}

/**
 * Process an incoming RESEND packet.
 *
 * @param packet
 *      Incoming RESEND packet to be processed.
 */
void
Sender::handleResendPacket(Driver::Packet* packet)
{
    Message* message = handleIncomingPacket(packet, true);
    // FIXME: with handleIncomingPacket, the bucket mutex no longer covers the entire method; need to double-check if this is OK in all methods
    // FIXME: in particular, what message states are protected by the bucket lock? do we need a per-message lock?

    // Check for unexpected conditions
    if (message == nullptr) {
        // No message for this RESEND; RESEND must be old. Just ignore it; this
        // case should be pretty rare and the Receiver will timeout eventually.
        return;
    } else if (message->numPackets < 2) {
        // We should never get a RESEND for a single packet message.  Just
        // ignore this RESEND from a buggy Receiver.
        WARNING(
            "Message (%lu, %lu) with only 1 packet received unexpected RESEND "
            "request; peer Transport may be confused.",
            message->id.transportId, message->id.sequence);
        return;
    }

    Protocol::Packet::ResendHeader* resendHeader =
        static_cast<Protocol::Packet::ResendHeader*>(packet->payload);
    int index = resendHeader->index;
    int resendEnd = index + resendHeader->num;

    SpinLock::Lock lock_queue(queueMutex);
    QueuedMessageInfo* info = &message->queuedMessageInfo;

    // Check if RESEND request is out of range.
    if (index >= info->packets->numPackets ||
        resendEnd > info->packets->numPackets) {
        WARNING(
            "Message (%lu, %lu) RESEND request range out of bounds: requested "
            "range [%d, %d); message only contains %d packets; peer Transport "
            "may be confused.",
            message->id.transportId, message->id.sequence, index, resendEnd,
            info->packets->numPackets);
        return;
    }

    // In case a GRANT may have been lost, consider the RESEND a GRANT.
    if (info->packetsGranted < resendEnd) {
        info->packetsGranted = resendEnd;
        // Note that the priority of messages under the unscheduled byte limit
        // will never be overridden since the resend index will not exceed the
        // preset packetsGranted.
        info->priority = resendHeader->priority;
        sendReady.store(true);
    }

    if (index >= info->packetsSent) {
        // If this RESEND is only requesting unsent packets, it must be that
        // this Sender has been busy and the Receiver is trying to ensure there
        // are no lost packets.  Reply BUSY and allow this Sender to send DATA
        // when it's ready.
        Perf::counters.tx_busy_pkts.add(1);
        ControlPacket::send<Protocol::Packet::BusyHeader>(
            driver, info->destination.ip, info->id);
    } else {
        // There are some packets to resend but only resend packets that have
        // already been sent.
        resendEnd = std::min(resendEnd, info->packetsSent);
        int resendPriority = policyManager->getResendPriority();
        for (uint16_t i = index; i < resendEnd; ++i) {
            Driver::Packet* packet = info->packets->getPacket(i);
            // Packets will be sent at the priority their original priority.
            Perf::counters.tx_data_pkts.add(1);
            Perf::counters.tx_bytes.add(packet->length);
            driver->sendPacket(packet, message->destination.ip, resendPriority);
        }
    }
}

/**
 * Process an incoming GRANT packet.
 *
 * @param packet
 *      Incoming GRANT packet to be processed.
 */
void
Sender::handleGrantPacket(Driver::Packet* packet)
{
    Message* message = handleIncomingPacket(packet, true);
    if (message == nullptr) {
        // No message for this grant; grant must be old.
        return;
    }

    Protocol::Packet::GrantHeader* grantHeader =
        static_cast<Protocol::Packet::GrantHeader*>(packet->payload);
    if (message->getStatus() == OutMessage::Status::IN_PROGRESS) {
        SpinLock::Lock lock_queue(queueMutex);
        QueuedMessageInfo* info = &message->queuedMessageInfo;

        // Convert the byteLimit to a packet index limit such that the packet
        // that holds the last granted byte is also considered granted.  This
        // can cause at most 1 packet worth of data to be sent without a grant
        // but allows the sender to always send full packets.
        int incomingGrantIndex =
            (grantHeader->byteLimit + info->packets->PACKET_DATA_LENGTH - 1) /
            info->packets->PACKET_DATA_LENGTH;

        // Make that grants don't exceed the number of packets.  Internally,
        // the sender always assumes that packetsGranted <= numPackets.
        if (incomingGrantIndex > info->packets->numPackets) {
            WARNING(
                "Message (%lu, %lu) GRANT exceeds message length; granted "
                "packets: %d, message packets %d; extra grants are ignored.",
                message->id.transportId, message->id.sequence,
                incomingGrantIndex, info->packets->numPackets);
            incomingGrantIndex = info->packets->numPackets;
        }

        if (info->packetsGranted < incomingGrantIndex) {
            info->packetsGranted = incomingGrantIndex;
            // Note that the priority of messages under the unscheduled byte
            // limit will never be overridden since the incomingGrantIndex will
            // not exceed the preset packetsGranted.
            info->priority = grantHeader->priority;
            sendReady.store(true);
        }
    }
}

/**
 * Process an incoming UNKNOWN packet.
 *
 * @param packet
 *      Incoming UNKNOWN packet to be processed.
 */
void
Sender::handleUnknownPacket(Driver::Packet* packet)
{
    Message* message = handleIncomingPacket(packet, false);
    if (message == nullptr) {
        // No message was found.
        return;
    }

    OutMessage::Status status = message->getStatus();
    assert(status != OutMessage::Status::NOT_STARTED);
    if (status != OutMessage::Status::IN_PROGRESS &&
        status != OutMessage::Status::SENT) {
        // The message is already considered "done" so the UNKNOWN packet
        // must be a stale response to a ping.
    } else if (message->options & OutMessage::Options::NO_RETRY) {
        // Option: NO_RETRY

        // Either the Message or the DONE packet was lost; consider the message
        // failed since the application asked for the message not to be retried.

        // Remove Message from sendQueue.
        // FIXME: move the following block into setStatus?
//        if (message->numPackets > 1) {
//            SpinLock::Lock lock_queue(queueMutex);
//            QueuedMessageInfo* info = &message->queuedMessageInfo;
//            if (message->getStatus() == OutMessage::Status::IN_PROGRESS) {
//                assert(sendQueue.contains(&info->sendQueueNode));
//                sendQueue.remove(&info->sendQueueNode);
//            }
//            assert(!sendQueue.contains(&info->sendQueueNode));
//        }
        message->deschedule();
        message->setStatus(OutMessage::Status::FAILED);
    } else {
        // Message isn't done yet so we will restart sending the message.

        // Make sure the message is not in the sendQueue before making any
        // changes to the message.
//        if (message->numPackets > 1) {
//            SpinLock::Lock lock_queue(queueMutex);
//            QueuedMessageInfo* info = &message->queuedMessageInfo;
//            if (message->getStatus() == OutMessage::Status::IN_PROGRESS) {
//                assert(sendQueue.contains(&info->sendQueueNode));
//                sendQueue.remove(&info->sendQueueNode);
//            }
//            assert(!sendQueue.contains(&info->sendQueueNode));
//        }
        message->deschedule();
        message->setStatus(OutMessage::Status::IN_PROGRESS);

        // Get the current policy for unscheduled bytes.
        Policy::Unscheduled policy = policyManager->getUnscheduledPolicy(
            message->destination.ip, message->messageLength);
        int unscheduledIndexLimit =
            ((policy.unscheduledByteLimit + message->PACKET_DATA_LENGTH - 1) /
             message->PACKET_DATA_LENGTH);

        // Update the policy version for each packet
        for (uint16_t i = 0; i < message->numPackets; ++i) {
            Driver::Packet* dataPacket = message->getPacket(i);
            assert(dataPacket != nullptr);
            Protocol::Packet::DataHeader* header =
                static_cast<Protocol::Packet::DataHeader*>(dataPacket->payload);
            header->policyVersion = policy.version;
            header->unscheduledIndexLimit =
                Util::downCast<uint16_t>(unscheduledIndexLimit);
        }

        assert(message->numPackets > 0);
        bool needTimeouts = true;
        if (message->numPackets == 1) {
            // If there is only one packet in the message, send it right away.
            Driver::Packet* dataPacket = message->getPacket(0);
            assert(dataPacket != nullptr);
            Perf::counters.tx_data_pkts.add(1);
            Perf::counters.tx_bytes.add(dataPacket->length);
            driver->sendPacket(dataPacket, message->destination.ip,
                               policy.priority);
            message->setStatus(OutMessage::Status::SENT);
            // This message must be still be held by the application since the
            // message still exists (it would have been removed when dropped
            // because single packet messages are never IN_PROGRESS). Assuming
            // the message is still held, we can skip the auto removal of SENT
            // and !held messages.
            assert(message->held);
            // FIXME: wait... this whole chunk of code is copied from sendMessage???
            if (message->options & OutMessage::Options::NO_KEEP_ALIVE) {
                // No timeouts need to be checked after sending the message when
                // the NO_KEEP_ALIVE option is enabled.
                needTimeouts = false;
            }
        } else {
            // Otherwise, queue the message to be sent in SRPT order.
            SpinLock::Lock lock_queue(queueMutex);
            QueuedMessageInfo* info = &message->queuedMessageInfo;
            // Some of these values should still be set from when the message
            // was first queued.
            assert(info->id == message->id);
            assert(!memcmp(&info->destination, &message->destination,
                           sizeof(info->destination)));
            assert(info->packets == message);
            // Some values need to be updated
            info->unsentBytes = message->messageLength;
            info->packetsGranted =
                std::min(unscheduledIndexLimit, message->numPackets);
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

        // Initialize the timeouts
        if (needTimeouts) {
            SpinLock::Lock bucket_lock(message->bucket->mutex);
            message->resetTimeout(bucket_lock);
        }
    }
}

/**
 * Process an incoming ERROR packet.
 *
 * @param packet
 *      Incoming ERROR packet to be processed.
 */
void
Sender::handleErrorPacket(Driver::Packet* packet)
{
    Message* message = handleIncomingPacket(packet, false);
    if (message == nullptr) {
        // No message for this ERROR packet; must be old.
        return;
    }

    Protocol::MessageId msgId = message->id;
    OutMessage::Status status = message->getStatus();
    switch (status) {
        case OutMessage::Status::SENT:
            // Message was sent and a failure notification was received.
            message->setStatus(OutMessage::Status::FAILED);
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
    checkTimeouts();
}

/**
 * Make incremental progress processing expired Sender timeouts.
 *
 * Pulled out of poll() for ease of testing.
 */
void
Sender::checkTimeouts()
{
    uint index = nextBucketIndex.fetch_add(1, std::memory_order_relaxed) &
                 MessageBucketMap::HASH_KEY_MASK;
    MessageBucket* bucket = &messageBuckets.buckets[index];
    uint64_t now = PerfUtils::Cycles::rdtsc();
    checkPingTimeouts(now, bucket);
    checkMessageTimeouts(now, bucket);
}

/**
 * Destruct a Message. Will release all contained Packet objects.
 */
Sender::Message::~Message()
{
    // Sender message must be contiguous
    driver->releasePackets(packets, numPackets);
}

/**
 * @copydoc Homa::OutMessage::append()
 */
void
Sender::Message::append(const void* source, size_t count)
{
    int _count = Util::downCast<int>(count);
    int packetIndex = messageLength / PACKET_DATA_LENGTH;
    int packetOffset = messageLength % PACKET_DATA_LENGTH;
    int bytesCopied = 0;
    int maxMessageLength = PACKET_DATA_LENGTH * MAX_MESSAGE_PACKETS;

    if (messageLength + _count > maxMessageLength) {
        WARNING("Max message size limit (%dB) reached; %d of %d bytes appended",
                maxMessageLength, maxMessageLength - messageLength, _count);
        _count = maxMessageLength - messageLength;
    }

    while (bytesCopied < _count) {
        int bytesToCopy =
            std::min(_count - bytesCopied, PACKET_DATA_LENGTH - packetOffset);
        Driver::Packet* packet = getOrAllocPacket(packetIndex);
        char* destination = static_cast<char*>(packet->payload);
        destination += packetOffset + TRANSPORT_HEADER_LENGTH;
        std::memcpy(destination, static_cast<const char*>(source) + bytesCopied,
                    bytesToCopy);
        // TODO(cstlee): A Message probably shouldn't be in charge of setting
        //               the packet length.
        packet->length += bytesToCopy;
        assert(packet->length <= TRANSPORT_HEADER_LENGTH + PACKET_DATA_LENGTH);
        bytesCopied += bytesToCopy;
        packetIndex++;
        packetOffset = 0;
    }

    messageLength += _count;
}

/**
 * @copydoc Homa::OutMessage::cancel()
 */
void
Sender::Message::cancel()
{
    sender->cancelMessage(this);
}


// FIXME
void
Sender::Message::destroy(const SpinLock::Lock& bucketMutex)
{
    // TODO: we assume that the message has been unlinked from the sendQueue
    // Remove this message from all global data structures of the Sender.
    cancelTimeout(bucketMutex);
    bucket->messages.remove(&bucketNode);

    // Destruct the Message object.
    SpinLock::Lock lock_allocator(sender->messageAllocator.mutex);
    sender->messageAllocator.pool.destroy(this);
    Perf::counters.destroyed_tx_messages.add(1);
}

/**
 * @copydoc Homa::OutMessage::getStatus()
 */
OutMessage::Status
Sender::Message::getStatus() const
{
    return state.load(std::memory_order_acquire);
}

/**
 * Change the status of this message.
 *
 * TODO:
 */
void
Sender::Message::setStatus(Status newStatus)
{
    // FIXME: this extra lock argument is ugly and quite confusing for this method
    state.store(newStatus, std::memory_order_release);

    // Clean up its state if the scheduler doesn't concern ???
    // FIXME
    switch (newStatus) {
        case OutMessage::Status::CANCELED:
        case OutMessage::Status::COMPLETED:
        case OutMessage::Status::FAILED: {
            SpinLock::Lock lock(bucket->mutex);
            cancelTimeout(lock);
        }
        default:
            break;
    }

    // FIXME: why cancel timeouts only? why not also remove itself from the buckets and the SRPT queue?
}

/**
 * Remove this Message from Sender::sendQueue.
 */
void
Sender::Message::deschedule()
{
    // FIXME: I don't think this optimization is correct; it relies on the assumption
    // that all single-packet messages will bypass the throttling mechanism; this
    // definitely doesn't make sense for jumbo packets...
    if (numPackets <= 1) {
        return;
    }

    // TODO: well, if deschedule is so simple; no need to use a separate method!
    SpinLock::Lock lock_queue(sender->queueMutex);
    sender->sendQueue.remove(&queuedMessageInfo.sendQueueNode);
    // FIXME: why so complicated?
//    QueuedMessageInfo* info = &queuedMessageInfo;
//    if (getStatus() == OutMessage::Status::IN_PROGRESS) {
//        assert(sender->sendQueue.contains(&info->sendQueueNode));
//        sender->sendQueue.remove(&info->sendQueueNode);
//    }
//    assert(!sender->sendQueue.contains(&info->sendQueueNode));
}

void
Sender::Message::resetTimeout(const SpinLock::Lock& lock)
{
    (void)lock;
    bucket->messageTimeouts.setTimeout(&messageTimeout);
    bucket->pingTimeouts.setTimeout(&pingTimeout);
}

void
Sender::Message::cancelTimeout(const SpinLock::Lock& lock)
{
    (void)lock;
    bucket->messageTimeouts.cancelTimeout(&messageTimeout);
    bucket->pingTimeouts.cancelTimeout(&pingTimeout);
}

/**
 * @copydoc Homa::OutMessage::length()
 */
size_t
Sender::Message::length() const
{
    return Util::downCast<size_t>(messageLength - start);
}

/**
 * @copydoc Homa::OutMessage::prepend()
 */
void
Sender::Message::prepend(const void* source, size_t count)
{
    int _count = Util::downCast<int>(count);
    // Make sure there is enough space reserved.
    assert(_count <= start);
    start -= _count;

    int packetIndex = start / PACKET_DATA_LENGTH;
    int packetOffset = start % PACKET_DATA_LENGTH;
    int bytesCopied = 0;

    while (bytesCopied < _count) {
        int bytesToCopy =
            std::min(_count - bytesCopied, PACKET_DATA_LENGTH - packetOffset);
        Driver::Packet* packet = getPacket(packetIndex);
        assert(packet != nullptr);
        char* destination = static_cast<char*>(packet->payload);
        destination += packetOffset + TRANSPORT_HEADER_LENGTH;
        std::memcpy(destination, static_cast<const char*>(source) + bytesCopied,
                    bytesToCopy);
        bytesCopied += bytesToCopy;
        packetIndex++;
        packetOffset = 0;
    }
}

/**
 * @copydoc Homa::OutMessage::release()
 */
void
Sender::Message::release()
{
    sender->dropMessage(this);
}

/**
 * @copydoc Homa::OutMessage::reserve()
 */
void
Sender::Message::reserve(size_t count)
{
    int _count = Util::downCast<int>(count);

    // Make sure there have been no prior calls to append or prepend.
    assert(start == messageLength);

    int packetIndex = start / PACKET_DATA_LENGTH;
    int packetOffset = start % PACKET_DATA_LENGTH;
    int bytesReserved = 0;
    int maxMessageLength = PACKET_DATA_LENGTH * MAX_MESSAGE_PACKETS;

    if (start + _count > maxMessageLength) {
        WARNING("Max message size limit (%uB) reached; %u of %u bytes reserved",
                maxMessageLength, maxMessageLength - start, _count);
        _count = maxMessageLength - start;
    }

    while (bytesReserved < _count) {
        int bytesToReserve =
            std::min(_count - bytesReserved, PACKET_DATA_LENGTH - packetOffset);
        Driver::Packet* packet = getOrAllocPacket(packetIndex);
        // TODO(cstlee): A Message probably shouldn't be in charge of setting
        //               the packet length.
        packet->length += bytesToReserve;
        assert(packet->length <= TRANSPORT_HEADER_LENGTH + PACKET_DATA_LENGTH);
        bytesReserved += bytesToReserve;
        packetIndex++;
        packetOffset = 0;
    }

    start += _count;
    messageLength += _count;
}

/**
 * @copydoc Homa::OutMessage::send()
 */
void
Sender::Message::send(SocketAddress destination,
                      Sender::Message::Options options)
{
    sender->sendMessage(this, destination, options);
}

/**
 * Return the Packet with the given index.
 *
 * @param index
 *      A Packet's index in the array of packets that form the message.
 *      "packet index = "packet message offset" / PACKET_DATA_LENGTH
 * @return
 *      Pointer to a Packet at the given index if it exists; nullptr otherwise.
 */
Driver::Packet*
Sender::Message::getPacket(size_t index) const
{
    if (occupied.test(index)) {
        return packets[index];
    }
    return nullptr;
}

/**
 * Return the Packet with the given index.  If the Packet does yet exist,
 * allocate a new Packet.
 *
 * @param index
 *      A Packet's index in the array of packets that form the message.
 *      "packet index = "packet message offset" / PACKET_DATA_LENGTH
 * @return
 *      Pointer to a Packet at the given index.
 */
Driver::Packet*
Sender::Message::getOrAllocPacket(size_t index)
{
    if (!occupied.test(index)) {
        packets[index] = driver->allocPacket();
        occupied.set(index);
        numPackets++;
        // TODO(cstlee): A Message probably shouldn't be in charge of setting
        //               the packet length.
        packets[index]->length = TRANSPORT_HEADER_LENGTH;
    }
    return packets[index];
}

/**
 * Queue a message to be sent.
 *
 * @param message
 *      Sender::Message to be sent.
 * @param destination
 *      Destination address for this message.
 * @param options
 *      Flags indicating requested non-default send behavior.
 *
 * @sa dropMessage()
 */
void
Sender::sendMessage(Sender::Message* message, SocketAddress destination,
                    Sender::Message::Options options)
{
    // Prepare the message
    assert(message->driver == driver);

    Policy::Unscheduled policy = policyManager->getUnscheduledPolicy(
        destination.ip, message->messageLength);
    int unscheduledPacketLimit =
        ((policy.unscheduledByteLimit + message->PACKET_DATA_LENGTH - 1) /
         message->PACKET_DATA_LENGTH);

    message->destination = destination;
    message->options = options;
    message->setStatus(OutMessage::Status::IN_PROGRESS);

    int actualMessageLen = 0;
    // fill out metadata.
    for (int i = 0; i < message->numPackets; ++i) {
        Driver::Packet* packet = message->getPacket(i);
        if (packet == nullptr) {
            PANIC(
                "Incomplete message with id (%lu:%lu); missing packet "
                "at offset %d; this shouldn't happen.",
                message->id.transportId, message->id.sequence,
                i * message->PACKET_DATA_LENGTH);
        }

        new (packet->payload) Protocol::Packet::DataHeader(
            message->source.port, destination.port, message->id,
            Util::downCast<uint32_t>(message->messageLength), policy.version,
            Util::downCast<uint16_t>(unscheduledPacketLimit),
            Util::downCast<uint16_t>(i));
        actualMessageLen += (packet->length - message->TRANSPORT_HEADER_LENGTH);
    }

    // perform sanity checks.
    assert(message->driver == driver);
    assert(message->messageLength == actualMessageLen);
    assert(message->TRANSPORT_HEADER_LENGTH ==
           sizeof(Protocol::Packet::DataHeader));

    // Track message
    MessageBucket* bucket = message->bucket;
    {
        SpinLock::Lock lock(bucket->mutex);
        assert(!bucket->messages.contains(&message->bucketNode));
        bucket->messages.push_back(&message->bucketNode);
    }

    assert(message->numPackets > 0);
    bool needTimeouts = true;
    if (message->numPackets == 1) {
        // If there is only one packet in the message, send it right away.
        Driver::Packet* packet = message->getPacket(0);
        assert(packet != nullptr);
        Perf::counters.tx_data_pkts.add(1);
        Perf::counters.tx_bytes.add(packet->length);
        driver->sendPacket(packet, message->destination.ip, policy.priority);
        message->setStatus(OutMessage::Status::SENT);
        // By definition, this message must be still be held by the application
        // the send() call is since the progress. Assuming the message is still
        // held, we can skip the auto removal of SENT and !held messages.
        assert(message->held);
        if (message->options & OutMessage::Options::NO_KEEP_ALIVE) {
            // No timeouts need to be checked after sending the message when
            // the NO_KEEP_ALIVE option is enabled.
            needTimeouts = false;
        }
    } else {
        // Otherwise, queue the message to be sent in SRPT order.
        SpinLock::Lock lock_queue(queueMutex);
        QueuedMessageInfo* info = &message->queuedMessageInfo;
        info->id = message->id;
        info->destination = message->destination;
        info->packets = message;
        info->unsentBytes = message->messageLength;
        info->packetsGranted =
            std::min(unscheduledPacketLimit, message->numPackets);
        info->priority = policy.priority;
        info->packetsSent = 0;
        // Insert and move message into the correct order in the priority queue.
        sendQueue.push_front(&info->sendQueueNode);
        Intrusive::deprioritize<Message>(&sendQueue, &info->sendQueueNode,
                                         QueuedMessageInfo::ComparePriority());
        sendReady.store(true);
    }

    if (needTimeouts) {
        SpinLock::Lock lock(bucket->mutex);
        message->resetTimeout(lock);
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
    MessageBucket* bucket = message->bucket;
    SpinLock::UniqueLock bucket_lock(bucket->mutex);

    // FIXME: why should we even bother to do the following test? why not just remove it from the bucket, the timeout list, and the SRPT queue?
    // TODO: the remove method of an intrusive list should be idempotent, right?
    if (bucket->messages.contains(&message->bucketNode)) {
        if (message->numPackets > 1 &&
            message->getStatus() == OutMessage::Status::IN_PROGRESS) {
            // Check to see if the message needs to be dequeued.
            SpinLock::Lock lock_queue(queueMutex);
            // Recheck state with lock in case it change right before this.
            // FIXME: somehow I feel like I have seen the following code snippet a million times
            // FIXME: why is this sendQueue stuff so complicated?
            if (message->getStatus() == OutMessage::Status::IN_PROGRESS) {
                QueuedMessageInfo* info = &message->queuedMessageInfo;
                assert(sendQueue.contains(&info->sendQueueNode));
                sendQueue.remove(&info->sendQueueNode);
            }
        }

        bucket_lock.unlock();
        message->setStatus(OutMessage::Status::CANCELED);
        // FIXME: who is responsible for removing this message from the bucket?
    }

    // FIXME: why not change the entire method to the following:
//    message->deschedule();
//    message->setStatus(OutMessage::Status::CANCELED);
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
    MessageBucket* bucket = message->bucket;
    SpinLock::Lock lock(bucket->mutex);
    message->held = false;
    Perf::counters.released_tx_messages.add(1);
    if (message->getStatus() != OutMessage::Status::IN_PROGRESS) {
        // Ok to delete immediately since we don't have to wait for the message
        // to be sent.
        message->destroy(lock);
    } else {
        // Defer deletion and wait for the message to be SENT.
    }
}

/**
 * Process any outbound messages in a given bucket that have timed out due to
 * lack of activity from the Receiver.
 *
 * Pulled out of checkTimeouts() for ease of testing.
 *
 * @param now
 *      The rdtsc cycle that should be considered the "current" time.
 * @param bucket
 *      The bucket whose message timeouts should be checked.
 */
void
Sender::checkMessageTimeouts(uint64_t now, MessageBucket* bucket)
{
    if (!bucket->messageTimeouts.anyElapsed(now)) {
        return;
    }

    while (true) {
        SpinLock::UniqueLock bucket_lock(bucket->mutex);
        // No remaining timeouts.
        if (bucket->messageTimeouts.empty()) {
            break;
        }
        Message* message = &bucket->messageTimeouts.front();
        // No remaining expired timeouts.
        if (!message->messageTimeout.hasElapsed(now)) {
            break;
        }

        // Release the bucket mutex to avoid deadlock inside setStatus().
        bucket_lock.unlock();

        // Found expired timeout.
        if (message->getStatus() != OutMessage::Status::COMPLETED) {
            if (message->getStatus() == OutMessage::Status::IN_PROGRESS) {
                // Check to see if the message needs to be dequeued.
                SpinLock::Lock lock_queue(queueMutex);
                // FIXME: why double-check? why does it even matter?
                // Recheck state with lock in case it change right before this.
                if (message->getStatus() == OutMessage::Status::IN_PROGRESS) {
                    QueuedMessageInfo* info = &message->queuedMessageInfo;
                    assert(sendQueue.contains(&info->sendQueueNode));
                    sendQueue.remove(&info->sendQueueNode);
                }
            }
            message->setStatus(OutMessage::Status::FAILED);
        } else {
            // TODO: double-check with Collin
            SpinLock::Lock lock(bucket->mutex);
            message->cancelTimeout(lock);
            WARNING("SHOULDN'T BE HERE?");
        }
        // FIXME: I don't understand this; if the message is completed, its
        // timeouts should've been cancelled already, no?
//        bucket->messageTimeouts.cancelTimeout(&message->messageTimeout);
//        bucket->pingTimeouts.cancelTimeout(&message->pingTimeout);
    }
}

/**
 * Process any outbound messages in a given bucket that need to be pinged to
 * ensure the message is kept alive by the receiver.
 *
 * Pulled out of checkTimeouts() for ease of testing.
 *
 * @param now
 *      The rdtsc cycle that should be considered the "current" time.
 * @param bucket
 *      The bucket whose ping timeouts should be checked.
 */
void
Sender::checkPingTimeouts(uint64_t now, MessageBucket* bucket)
{
    if (!bucket->pingTimeouts.anyElapsed(now)) {
        return;
    }

    while (true) {
        SpinLock::Lock lock(bucket->mutex);
        // No remaining timeouts.
        if (bucket->pingTimeouts.empty()) {
            break;
        }
        Message* message = &bucket->pingTimeouts.front();
        // No remaining expired timeouts.
        if (!message->pingTimeout.hasElapsed(now)) {
            break;
        }
        // Found expired timeout.
        if (message->getStatus() == OutMessage::Status::COMPLETED ||
            message->getStatus() == OutMessage::Status::FAILED) {
            // FIXME: how is this possible? setStatus ensures that all timeouts
            // will be cancelled when the status enters an end state
            bucket->pingTimeouts.cancelTimeout(&message->pingTimeout);
            continue;
        } else if (message->options & OutMessage::Options::NO_KEEP_ALIVE &&
                   message->getStatus() == OutMessage::Status::SENT) {
            message->cancelTimeout(lock);
            continue;
        } else {
            // TODO: can be change to the following to avoid calling setTimeout directly?
            //message->resetTimeout(lock);
            bucket->pingTimeouts.setTimeout(&message->pingTimeout);
        }

        // Check if sender still has packets to send
        if (message->getStatus() == OutMessage::Status::IN_PROGRESS) {
            SpinLock::Lock lock_queue(queueMutex);
            QueuedMessageInfo* info = &message->queuedMessageInfo;
            if (info->packetsSent < info->packetsGranted) {
                // Sender is blocked on itself, no need to send ping
                continue;
            }
        }

        // Have not heard from the Receiver in the last timeout period. Ping
        // the receiver to ensure it still knows about this Message.
        Perf::counters.tx_ping_pkts.add(1);
        ControlPacket::send<Protocol::Packet::PingHeader>(
            message->driver, message->destination.ip, message->id);
    }
}

/**
 * Send out packets for any messages with unscheduled/granted bytes.
 *
 * Pulled out of poll() for ease of testing.
 */
void
Sender::trySend()
{
    Perf::Timer timer;
    bool idle = true;

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
    uint32_t queuedBytesEstimate = driver->getQueuedBytes();
    std::vector<Protocol::MessageId> sentMessageIds;
    sentMessageIds.reserve(32);
    // Optimistically assume we will finish sending every granted packet this
    // round; we will set again sendReady if it turns out we don't finish.
    sendReady = false;
    auto it = sendQueue.begin();
    while (it != sendQueue.end()) {
        Message& message = *it;
        assert(message.getStatus() == OutMessage::Status::IN_PROGRESS);
        QueuedMessageInfo* info = &message.queuedMessageInfo;
        assert(info->packetsGranted <= info->packets->numPackets);
        while (info->packetsSent < info->packetsGranted) {
            // There are packets to send
            idle = false;
            Driver::Packet* packet =
                info->packets->getPacket(info->packetsSent);
            assert(packet != nullptr);
            queuedBytesEstimate += packet->length;
            // Check if the send limit would be reached...
            if (queuedBytesEstimate > DRIVER_QUEUED_BYTE_LIMIT) {
                break;
            }
            // ... if not, send away!
            Perf::counters.tx_data_pkts.add(1);
            Perf::counters.tx_bytes.add(packet->length);
            driver->sendPacket(packet, message.destination.ip, info->priority);
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
        if (info->packetsSent >= info->packets->numPackets) {
            // We have finished sending the message.
            sentMessageIds.push_back(info->id);
            message.setStatus(OutMessage::Status::SENT);
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

    // Unlock the queueMutex to process any SENT messages to ensure any bucket
    // mutex is always acquired before the send queueMutex.
    lock_queue.unlock();
    for (Protocol::MessageId& msgId : sentMessageIds) {
        MessageBucket* bucket = messageBuckets.getBucket(msgId);
        SpinLock::Lock lock(bucket->mutex);
        Message* message = bucket->findMessage(msgId, lock);
        if (message == nullptr) {
            // Message must have already been deleted.
            continue;
        }

        if (!message->held) {
            // Ok to delete now that the message has been sent.
            message->destroy(lock);
        } else if (message->options & OutMessage::Options::NO_KEEP_ALIVE) {
            // No timeouts need to be checked after sending the message when
            // the NO_KEEP_ALIVE option is enabled.
            message->cancelTimeout(lock);
        }
    }

    if (!idle) {
        Perf::counters.active_cycles.add(timer.split());
    }
}

}  // namespace Core
}  // namespace Homa
