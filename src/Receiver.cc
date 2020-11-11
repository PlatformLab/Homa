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

#include "Receiver.h"

#include <Cycles.h>

#include "Perf.h"

namespace Homa {
namespace Core {

/**
 * Receiver constructor.
 *
 * @param driver
 *      The driver used to send and receive packets.
 * @param policyManager
 *      Provides information about the grant and network priority policies.
 * @param messageTimeoutCycles
 *      Number of cycles of inactivity to wait before this Receiver declares an
 *      Receiver::Message receive failure.
 * @param resendIntervalCycles
 *      Number of cycles of inactivity to wait between requesting retransmission
 *      of un-received parts of a message.
 */
Receiver::Receiver(Driver* driver, Policy::Manager* policyManager,
                   uint64_t messageTimeoutCycles, uint64_t resendIntervalCycles)
    : driver(driver)
    , policyManager(policyManager)
    , MESSAGE_TIMEOUT_INTERVALS(
          Util::roundUpIntDiv(messageTimeoutCycles, resendIntervalCycles))
    , TRANSPORT_HEADER_LENGTH(sizeof(Protocol::Packet::DataHeader))
    , PACKET_DATA_LENGTH(driver->getMaxPayloadSize() - TRANSPORT_HEADER_LENGTH)
    , messageBuckets(resendIntervalCycles)
    , schedulerMutex()
    , scheduledPeers()
    , receivedMessages()
    , granting()
    , nextBucketIndex(0)
    , messageAllocator()
    , externalBuffers()
{}

/**
 * Receiver destructor.
 */
Receiver::~Receiver()
{
    // To ensure that all resources of a Receiver can be freed correctly, it's
    // the user's responsibility to ensure the following before destructing the
    // Receiver:
    //  - The transport must have been taken "offline" so that no more incoming
    //    packets will arrive.
    //  - All completed incoming messages that are delivered to the application
    //    must have been returned back to the Receiver (so that they don't hold
    //    dangling pointers to the destructed Receiver afterwards).
    //  - There must be only one thread left that can hold a reference to the
    //    transport (the destructor is designed to run exactly once).

    // Technically speaking, the Receiver is designed in a way that a default
    // destructor should be sufficient. However, for clarity and debugging
    // purpose, we decided to write the cleanup procedure explicitly anyway.

    // Remove all completed Messages that are still inside the receive queue.
    receivedMessages.queue.clear();

    // Destruct all MessageBucket's and the Messages within.
    for (auto& bucket : messageBuckets.buckets) {
        // Intrusive::List is not responsible for destructing its elements;
        // it must be done manually.
        for (auto& message : bucket.messages) {
            dropMessage(&message);
        }
        assert(bucket.resendTimeouts.empty());
    }
    messageBuckets.buckets.clear();

    // Destruct all Peer's. Peer's must be removed from scheduledPeers first.
    scheduledPeers.clear();
    peerTable.clear();
}

/**
 * Process an incoming DATA packet.
 *
 * @param packet
 *      The incoming packet to be processed.
 * @param sourceIp
 *      Source IP address of the packet.
 */
void
Receiver::handleDataPacket(Driver::Packet* packet, IpAddress sourceIp)
{
    Protocol::Packet::DataHeader* header =
        static_cast<Protocol::Packet::DataHeader*>(packet->payload);
    Protocol::MessageId id = header->common.messageId;

    MessageBucket* bucket = messageBuckets.getBucket(id);
    SpinLock::UniqueLock lock_bucket(bucket->mutex);
    Message* message = bucket->findMessage(id, lock_bucket);
    if (message == nullptr) {
        // New message
        int messageLength = header->totalLength;
        int numUnscheduledPackets = header->unscheduledIndexLimit;
        SocketAddress srcAddress = {
            .ip = sourceIp, .port = be16toh(header->common.prefix.sport)};
        message = messageAllocator.construct(this, driver, messageLength, id,
                                             srcAddress, numUnscheduledPackets);
        Perf::counters.allocated_rx_messages.add(1);

        // Start tracking the message.
        bucket->messages.push_back(&message->bucketNode);
        policyManager->signalNewMessage(
            message->source.ip, header->policyVersion, header->totalLength);
    }

    // Sanity checks
    assert(message->source.ip == sourceIp);
    assert(message->source.port == be16toh(header->common.prefix.sport));
    assert(message->messageLength == Util::downCast<int>(header->totalLength));

    if (message->received.test(header->index)) {
        // Must be a duplicate packet; drop it.
        return;
    } else {
        // Add the packet and copy the payload.
        message->received.set(header->index);
        message->numPackets++;
        std::memcpy(
            message->buffer + header->index * PACKET_DATA_LENGTH,
            static_cast<char*>(packet->payload) + TRANSPORT_HEADER_LENGTH,
            packet->length - TRANSPORT_HEADER_LENGTH);
    }

    if (message->scheduled) {
        // A new Message needs to be entered into the scheduler.
        SpinLock::Lock lock_scheduler(schedulerMutex);
        schedule(message, lock_scheduler);
    } else if (message->scheduled) {
        // Update schedule for an existing scheduled message.
        SpinLock::Lock lock_scheduler(schedulerMutex);
        ScheduledMessageInfo* info = &message->scheduledMessageInfo;
        // Update the schedule if the message is still being scheduled
        // (i.e. still linked to a scheduled peer).
        if (info->peer != nullptr) {
            int packetDataBytes = packet->length - TRANSPORT_HEADER_LENGTH;
            assert(info->bytesRemaining >= packetDataBytes);
            info->bytesRemaining -= packetDataBytes;
            updateSchedule(message, lock_scheduler);
        }
    }

    if (message->numPackets == message->numExpectedPackets) {
        // All message packets have been received.
        message->completed.store(true, std::memory_order_release);
        if (message->needTimeout) {
            bucket->resendTimeouts.cancelTimeout(&message->resendTimeout);
        }
        lock_bucket.unlock();

        // Deliver the message to the user of the transport.
        SpinLock::Lock lock_received_messages(receivedMessages.mutex);
        receivedMessages.queue.push_back(&message->receivedMessageNode);
        Perf::counters.received_rx_messages.add(1);
    } else if (message->needTimeout) {
        // Receiving a new packet means the message is still active so it
        // shouldn't time out until a while later.
        message->numResendTimeouts = 0;
        bucket->resendTimeouts.setTimeout(&message->resendTimeout);
    }
}

/**
 * Process an incoming BUSY packet.
 *
 * @param packet
 *      The incoming BUSY packet to be processed.
 */
void
Receiver::handleBusyPacket(Driver::Packet* packet)
{
    Protocol::Packet::BusyHeader* header =
        static_cast<Protocol::Packet::BusyHeader*>(packet->payload);
    Protocol::MessageId id = header->common.messageId;

    MessageBucket* bucket = messageBuckets.getBucket(id);
    SpinLock::UniqueLock lock_bucket(bucket->mutex);
    Message* message = bucket->findMessage(id, lock_bucket);
    if (message != nullptr) {
        // Sender has replied BUSY to our RESEND request; consider this message
        // still active.
        if (message->needTimeout && !message->completed) {
            message->numResendTimeouts = 0;
            bucket->resendTimeouts.setTimeout(&message->resendTimeout);
        }
    }
}

/**
 * Process an incoming PING packet.
 *
 * @param packet
 *      The incoming PING packet to be processed.
 * @param sourceIp
 *      Source IP address of the packet.
 */
void
Receiver::handlePingPacket(Driver::Packet* packet, IpAddress sourceIp)
{
    Protocol::Packet::PingHeader* header =
        static_cast<Protocol::Packet::PingHeader*>(packet->payload);
    Protocol::MessageId id = header->common.messageId;

    // FIXME(Yilong): after making the transport purely message-based, we need
    // to send back an ACK packet here if this message is complete

    MessageBucket* bucket = messageBuckets.getBucket(id);
    SpinLock::UniqueLock lock_bucket(bucket->mutex);
    Message* message = bucket->findMessage(id, lock_bucket);
    if (message != nullptr) {
        // Don't (re-)insert a timeout unless necessary.
        if (message->needTimeout && !message->completed) {
            // Sender is checking on this message; consider it still active.
            message->numResendTimeouts = 0;
            bucket->resendTimeouts.setTimeout(&message->resendTimeout);
        }

        // We are here either because a GRANT got lost, or we haven't issued a
        // GRANT in along time.  Send out the latest GRANT if one exists or just
        // an "empty" GRANT to let the Sender know we are aware of the message.

        // Default to an empty GRANT.  Sending an empty GRANT will not reset the
        // priority of a Message that has not yet received a GRANT.
        int bytesGranted = 0;
        int priority = 0;

        if (message->scheduled) {
            // Use the scheduled GRANT information for scheduled messages.
            // This may still contain the default values (i.e. an empty GRANT)
            // if no GRANTs have been issued yet.
            SpinLock::Lock lock_scheduler(schedulerMutex);
            ScheduledMessageInfo* info = &message->scheduledMessageInfo;
            bytesGranted = info->bytesGranted;
            priority = info->priority;
        }

        lock_bucket.unlock();
        Perf::counters.tx_grant_pkts.add(1);
        ControlPacket::send<Protocol::Packet::GrantHeader>(
            driver, sourceIp, id, bytesGranted, priority);
    } else {
        // We are here because we have no knowledge of the message the Sender is
        // asking about.  Reply UNKNOWN so the Sender can react accordingly.
        lock_bucket.unlock();
        Perf::counters.tx_unknown_pkts.add(1);
        ControlPacket::send<Protocol::Packet::UnknownHeader>(driver, sourceIp,
                                                             id);
    }
}

/**
 * Return a handle to a new received Message.
 *
 * The Transport should regularly call this method to insure incoming messages
 * are processed.
 *
 * @return
 *      A new Message which has been received, if available; otherwise, nullptr.
 */
Homa::InMessage*
Receiver::receiveMessage()
{
    SpinLock::Lock lock_received_messages(receivedMessages.mutex);
    Message* message = nullptr;
    if (!receivedMessages.queue.empty()) {
        message = &receivedMessages.queue.front();
        receivedMessages.queue.pop_front();
        Perf::counters.delivered_rx_messages.add(1);
    }
    return message;
}

/**
 * Allow the Receiver to make progress toward receiving incoming messages.
 *
 * This method must be called eagerly to ensure messages are received.
 */
void
Receiver::poll()
{
    trySendGrants();
    checkTimeouts();
}

/**
 * Make incremental progress processing expired Receiver timeouts.
 *
 * Pulled out of poll() for ease of testing.
 */
void
Receiver::checkTimeouts()
{
    uint index = nextBucketIndex.fetch_add(1, std::memory_order_relaxed) &
                 MessageBucketMap::HASH_KEY_MASK;
    MessageBucket* bucket = &messageBuckets.buckets[index];
    uint64_t now = PerfUtils::Cycles::rdtsc();
    checkResendTimeouts(now, bucket);
}

/**
 * Destruct a Message.
 */
Receiver::Message::~Message()
{
    // Release the external buffer, if any.
    if (buffer != internalBuffer) {
        MessageBuffer<MAX_MESSAGE_LENGTH>* externalBuf =
            (MessageBuffer<MAX_MESSAGE_LENGTH>*)buffer;
        bucket->receiver->externalBuffers.destroy(externalBuf);
    }
}

/**
 * @copydoc Homa::InMessage::acknowledge()
 */
void
Receiver::Message::acknowledge() const
{
    Perf::counters.tx_done_pkts.add(1);
    ControlPacket::send<Protocol::Packet::DoneHeader>(driver, source.ip, id);
}

/**
 * @copydoc Homa::InMessage::data()
 */
void*
Receiver::Message::data() const
{
    return buffer;
}

/**
 * @copydoc Homa::InMessage::length()
 */
size_t
Receiver::Message::length() const
{
    return Util::downCast<size_t>(messageLength);
}

/**
 * @copydoc Homa::InMessage::release()
 */
void
Receiver::Message::release()
{
    bucket->receiver->dropMessage(this);
}

/**
 * Drop a message because it's no longer needed (either the application released
 * the message or a timeout occurred).
 *
 * @param message
 *      Message which will be detached from the transport and destroyed.
 */
void
Receiver::dropMessage(Receiver::Message* message)
{
    // Unschedule the message if it is still scheduled (i.e. still linked to a
    // scheduled peer).
    if (message->scheduled) {
        SpinLock::Lock lock_scheduler(schedulerMutex);
        ScheduledMessageInfo* info = &message->scheduledMessageInfo;
        if (info->peer != nullptr) {
            unschedule(message, lock_scheduler);
        }
    }

    // Remove this message from the other data structures of the Receiver.
    MessageBucket* bucket = message->bucket;
    {
        SpinLock::Lock bucket_lock(bucket->mutex);
        bucket->resendTimeouts.cancelTimeout(&message->resendTimeout);
        bucket->messages.remove(&message->bucketNode);
    }

    // Destroy the message.
    messageAllocator.destroy(message);
    Perf::counters.destroyed_rx_messages.add(1);
}

/**
 * Process any inbound messages that may need to issue resends.
 *
 * Pulled out of checkTimeouts() for ease of testing.
 *
 * @param now
 *      The rdtsc cycle that should be considered the "current" time.
 * @param bucket
 *      The bucket whose resend timeouts should be checked.
 */
void
Receiver::checkResendTimeouts(uint64_t now, MessageBucket* bucket)
{
    if (!bucket->resendTimeouts.anyElapsed(now)) {
        return;
    }

    while (true) {
        SpinLock::UniqueLock lock_bucket(bucket->mutex);

        // No remaining timeouts.
        if (bucket->resendTimeouts.empty()) {
            break;
        }

        // No remaining expired timeouts.
        Message* message = &bucket->resendTimeouts.front();
        if (!message->resendTimeout.hasElapsed(now)) {
            break;
        }

        // Found expired timeout.
        assert(!message->completed);
        message->numResendTimeouts++;
        if (message->numResendTimeouts >= MESSAGE_TIMEOUT_INTERVALS) {
            // Message timed out before being fully received; drop the message.
            lock_bucket.unlock();
            dropMessage(message);
            continue;
        } else {
            bucket->resendTimeouts.setTimeout(&message->resendTimeout);
        }

        // This Receiver expected to have heard from the Sender within the
        // last timeout period but it didn't.  Request a resend of granted
        // packets in case DATA packets got lost.
        uint16_t index = 0;
        uint16_t num = 0;
        int grantIndexLimit = message->numUnscheduledPackets;

        // The RESEND also includes the current granted priority so that it
        // can act as a GRANT in case a GRANT was lost.  If this message
        // hasn't been scheduled (i.e. no grants have been sent) then the
        // priority will hold the default value; this is ok since the Sender
        // will ignore the priority field for resends of purely unscheduled
        // packets (see Sender::handleResendPacket()).
        int resendPriority = 0;
        if (message->scheduled) {
            SpinLock::Lock lock_scheduler(schedulerMutex);
            ScheduledMessageInfo* info = &message->scheduledMessageInfo;
            int receivedBytes = info->messageLength - info->bytesRemaining;
            if (receivedBytes >= info->bytesGranted) {
                // Sender is blocked on this Receiver; all granted packets
                // have already been received.  No need to check for resend.
                continue;
            } else if (grantIndexLimit * PACKET_DATA_LENGTH <
                       info->bytesGranted) {
                grantIndexLimit =
                    Util::roundUpIntDiv(info->bytesGranted, PACKET_DATA_LENGTH);
            }
            resendPriority = info->priority;
        }

        for (int i = 0; i < grantIndexLimit; ++i) {
            if (!message->received.test(i)) {
                // Unreceived packet
                if (num == 0) {
                    // First unreceived packet
                    index = i;
                }
                ++num;
            } else {
                // Received packet
                if (num != 0) {
                    // Send out the range of packets found so far.
                    Perf::counters.tx_resend_pkts.add(1);
                    ControlPacket::send<Protocol::Packet::ResendHeader>(
                        message->driver, message->source.ip, message->id, index,
                        num, resendPriority);
                    num = 0;
                }
            }
        }
        if (num != 0) {
            // Send out the last range of packets found.
            Perf::counters.tx_resend_pkts.add(1);
            ControlPacket::send<Protocol::Packet::ResendHeader>(
                message->driver, message->source.ip, message->id, index, num,
                resendPriority);
        }
    }
}

/**
 * Send GRANTs to incoming Message according to the Receiver's policy.
 */
void
Receiver::trySendGrants()
{
    Perf::Timer timer;

    // Skip scheduling if another poller is already working on it.
    if (granting.test_and_set()) {
        return;
    }

    SpinLock::Lock lock(schedulerMutex);
    if (scheduledPeers.empty()) {
        granting.clear();
        return;
    }

    /* The overall goal is to grant up to policy.degreeOvercommitment number of
     * scheduled messages simultaneously.  Each of these messages should always
     * have at least policy.minScheduledBytes number of bytes granted.  Ideally,
     * each message will be assigned a different network priority based on a
     * message's number of bytesRemaining.  The message with the fewest
     * bytesRemaining (SRPT) will be assigned the highest priority.  If the
     * number of messages to grant exceeds the number of available priorities,
     * the lowest priority is shared by multiple messages.  If the number of
     * messages to grant is fewer than the available priorities, than the
     * messages are assigned to the lowest available priority.
     */
    Policy::Scheduled policy = policyManager->getScheduledPolicy();
    assert(policy.degreeOvercommitment > policy.maxScheduledPriority);
    assert(policy.minScheduledBytes <= policy.minScheduledBytes);
    int unusedPriorities =
        std::max(0, (policy.maxScheduledPriority + 1) -
                        Util::downCast<int>(scheduledPeers.size()));

    auto it = scheduledPeers.begin();
    int slot = 0;
    while (it != scheduledPeers.end() && slot < policy.degreeOvercommitment) {
        assert(!it->scheduledMessages.empty());
        // No need to acquire the bucket mutex here because we are only going to
        // access the const members of a Message; besides, the message can't get
        // destroyed while we are holding the schedulerMutex.
        Message* message = &it->scheduledMessages.front();
        ScheduledMessageInfo* info = &message->scheduledMessageInfo;

        // Recalculate message priority
        info->priority =
            std::max(0, policy.maxScheduledPriority - slot - unusedPriorities);

        // Send a GRANT if there are too few bytes granted and unreceived.
        int receivedBytes = info->messageLength - info->bytesRemaining;
        if (info->bytesGranted - receivedBytes < policy.minScheduledBytes) {
            // Calculate new grant limit
            int newGrantLimit = std::min(
                receivedBytes + policy.maxScheduledBytes, info->messageLength);
            assert(newGrantLimit >= info->bytesGranted);
            info->bytesGranted = newGrantLimit;
            Perf::counters.tx_grant_pkts.add(1);
            ControlPacket::send<Protocol::Packet::GrantHeader>(
                driver, message->source.ip, message->id,
                Util::downCast<uint32_t>(info->bytesGranted), info->priority);
            Perf::counters.active_cycles.add(timer.split());
        }

        // Update the iterator first since calling unschedule() may cause the
        // iterator to become invalid.
        ++it;

        if (info->messageLength <= info->bytesGranted) {
            // All packets granted, unschedule the message.
            unschedule(message, lock);
            Perf::counters.active_cycles.add(timer.split());
        }

        ++slot;
    }

    granting.clear();
}

/**
 * Add a Message to the schedule.
 *
 * Helper function separated mostly for ease of testing.
 *
 * @param message
 *      Message to be added.
 * @param lock
 *      Reminder to hold the Receiver::schedulerMutex during this call.
 */
void
Receiver::schedule(Receiver::Message* message, const SpinLock::Lock& lock)
{
    (void)lock;
    ScheduledMessageInfo* info = &message->scheduledMessageInfo;
    Peer* peer = &peerTable[message->source.ip];
    // Insert the Message
    peer->scheduledMessages.push_front(&info->scheduledMessageNode);
    Intrusive::deprioritize<Message>(&peer->scheduledMessages,
                                     &info->scheduledMessageNode);
    info->peer = peer;
    if (!scheduledPeers.contains(&peer->scheduledPeerNode)) {
        // Must be the only message of this peer; push the peer to the front of
        // list to be moved later.
        assert(peer->scheduledMessages.size() == 1);
        scheduledPeers.push_front(&peer->scheduledPeerNode);
        Intrusive::deprioritize<Peer>(&scheduledPeers,
                                      &peer->scheduledPeerNode);
    } else if (&info->peer->scheduledMessages.front() == message) {
        // Update the Peer's position in the queue since the new message is the
        // peer's first scheduled message.
        Intrusive::prioritize<Peer>(&scheduledPeers, &peer->scheduledPeerNode);
    } else {
        // The peer's first scheduled message did not change.  Nothing to do.
    }
}

/**
 * Remove a Message from the schedule.
 *
 * Helper function separated mostly for ease of testing.
 *
 * @param message
 *      Message to be removed.
 * @param lock
 *      Reminder to hold the Receiver::schedulerMutex during this call.
 */
void
Receiver::unschedule(Receiver::Message* message, const SpinLock::Lock& lock)
{
    (void)lock;
    ScheduledMessageInfo* info = &message->scheduledMessageInfo;
    assert(info->peer != nullptr);
    Peer* peer = info->peer;
    Intrusive::List<Peer>::Iterator it =
        scheduledPeers.get(&peer->scheduledPeerNode);
    Peer::ComparePriority comp;

    // Remove message.
    assert(peer->scheduledMessages.contains(&info->scheduledMessageNode));
    peer->scheduledMessages.remove(&info->scheduledMessageNode);
    info->peer = nullptr;

    // Cleanup the schedule
    if (peer->scheduledMessages.empty()) {
        // Remove the empty peer from the schedule (the peer object is still
        // alive).
        scheduledPeers.remove(it);
    } else if (std::next(it) == scheduledPeers.end() ||
               !comp(*std::next(it), *it)) {
        // Peer already in the right place (peer incremented as part of the
        // check).  Note that only "next" needs be checked (and not "prev")
        // since removing a message cannot increase the peer's priority.
    } else {
        // Peer needs to be moved.
        Intrusive::deprioritize<Peer>(&scheduledPeers,
                                      &peer->scheduledPeerNode);
    }
}

/**
 * Update Message's position in the schedule.
 *
 * Called when new data has arrived for the Message.
 *
 * Helper function separated mostly for ease of testing.
 *
 * @param message
 *      Message whose position should be updated.
 * @param lock
 *      Reminder to hold the Receiver::schedulerMutex during this call.
 */
void
Receiver::updateSchedule(Receiver::Message* message, const SpinLock::Lock& lock)
{
    (void)lock;
    ScheduledMessageInfo* info = &message->scheduledMessageInfo;
    assert(info->peer != nullptr);
    assert(info->peer->scheduledMessages.contains(&info->scheduledMessageNode));

    // Update the message's position within its Peer scheduled message queue.
    Intrusive::prioritize<Message>(&info->peer->scheduledMessages,
                                   &info->scheduledMessageNode);

    // Update the Peer's position in the queue if this message is now the first
    // scheduled message.
    if (&info->peer->scheduledMessages.front() == message) {
        Intrusive::prioritize<Peer>(&scheduledPeers,
                                    &info->peer->scheduledPeerNode);
    }
}

}  // namespace Core
}  // namespace Homa
