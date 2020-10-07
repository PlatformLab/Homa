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
    , messageBuckets(messageTimeoutCycles, resendIntervalCycles)
    , schedulerMutex()
    , scheduledPeers()
    , receivedMessages()
    , granting()
    , nextBucketIndex(0)
    , messageAllocator()
{}

/**
 * Receiver destructor.
 */
Receiver::~Receiver()
{
    schedulerMutex.lock();
    scheduledPeers.clear();
    peerTable.clear();
    receivedMessages.mutex.lock();
    receivedMessages.queue.clear();
    for (auto it = messageBuckets.buckets.begin();
         it != messageBuckets.buckets.end(); ++it) {
        MessageBucket* bucket = *it;
        bucket->mutex.lock();
        auto iit = bucket->messages.begin();
        while (iit != bucket->messages.end()) {
            Message* message = &(*iit);
            bucket->messageTimeouts.cancelTimeout(&message->messageTimeout);
            bucket->resendTimeouts.cancelTimeout(&message->resendTimeout);
            iit = bucket->messages.remove(iit);
            {
                SpinLock::Lock lock_allocator(messageAllocator.mutex);
                messageAllocator.pool.destroy(message);
            }
        }
    }
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
    uint16_t dataHeaderLength = sizeof(Protocol::Packet::DataHeader);
    Protocol::MessageId id = header->common.messageId;

    MessageBucket* bucket = messageBuckets.getBucket(id);
    SpinLock::Lock lock_bucket(bucket->mutex);
    Message* message = bucket->findMessage(id, lock_bucket);
    if (message == nullptr) {
        // New message
        int messageLength = header->totalLength;
        int numUnscheduledPackets = header->unscheduledIndexLimit;
        {
            SpinLock::Lock lock_allocator(messageAllocator.mutex);
            SocketAddress srcAddress = {
                .ip = sourceIp, .port = be16toh(header->common.prefix.sport)};
            message = messageAllocator.pool.construct(
                this, driver, dataHeaderLength, messageLength, id, srcAddress,
                numUnscheduledPackets);
            Perf::counters.allocated_rx_messages.add(1);
        }

        bucket->messages.push_back(&message->bucketNode);
        policyManager->signalNewMessage(
            message->source.ip, header->policyVersion, header->totalLength);

        if (message->scheduled) {
            // Message needs to be scheduled.
            SpinLock::Lock lock_scheduler(schedulerMutex);
            schedule(message, lock_scheduler);
        }
    }

    // Things that must be true (sanity check)
    assert(id == message->id);
    assert(message->driver == driver);
    assert(message->source.ip == sourceIp);
    assert(message->source.port == be16toh(header->common.prefix.sport));
    assert(message->messageLength == Util::downCast<int>(header->totalLength));

    // Add the packet
    bool packetAdded = message->setPacket(header->index, packet);
    if (packetAdded) {
        // Update schedule for scheduled messages.
        if (message->scheduled) {
            SpinLock::Lock lock_scheduler(schedulerMutex);
            ScheduledMessageInfo* info = &message->scheduledMessageInfo;
            // Update the schedule if the message is still being scheduled
            // (i.e. still linked to a scheduled peer).
            if (info->peer != nullptr) {
                int packetDataBytes =
                    packet->length - message->TRANSPORT_HEADER_LENGTH;
                assert(info->bytesRemaining >= packetDataBytes);
                info->bytesRemaining -= packetDataBytes;
                updateSchedule(message, lock_scheduler);
            }
        }

        // Receiving a new packet means the message is still active so it
        // shouldn't time out until a while later.
        bucket->messageTimeouts.setTimeout(&message->messageTimeout);
        if (message->numPackets < message->numExpectedPackets) {
            // Still waiting for more packets to arrive but the arrival of a
            // new packet means we should wait a while longer before requesting
            // RESENDs of the missing packets.
            bucket->resendTimeouts.setTimeout(&message->resendTimeout);
        } else {
            // All message packets have been received.
            message->state.store(Message::State::COMPLETED);
            bucket->resendTimeouts.cancelTimeout(&message->resendTimeout);
            SpinLock::Lock lock_received_messages(receivedMessages.mutex);
            receivedMessages.queue.push_back(&message->receivedMessageNode);
            Perf::counters.received_rx_messages.add(1);
        }
    } else {
        // must be a duplicate packet; drop packet.
        driver->releasePackets(&packet, 1);
    }
    return;
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
    SpinLock::Lock lock_bucket(bucket->mutex);
    Message* message = bucket->findMessage(id, lock_bucket);
    if (message != nullptr) {
        // Sender has replied BUSY to our RESEND request; consider this message
        // still active.
        bucket->messageTimeouts.setTimeout(&message->messageTimeout);
        if (message->state == Message::State::IN_PROGRESS) {
            bucket->resendTimeouts.setTimeout(&message->resendTimeout);
        }
    }
    driver->releasePackets(&packet, 1);
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

    MessageBucket* bucket = messageBuckets.getBucket(id);
    SpinLock::Lock lock_bucket(bucket->mutex);
    Message* message = bucket->findMessage(id, lock_bucket);
    if (message != nullptr) {
        // Sender is checking on this message; consider it still active.
        bucket->messageTimeouts.setTimeout(&message->messageTimeout);

        // We are here either because a GRANT  got lost, or we haven't issued a
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

        Perf::counters.tx_grant_pkts.add(1);
        ControlPacket::send<Protocol::Packet::GrantHeader>(
            driver, message->source.ip, message->id, bytesGranted, priority);
    } else {
        // We are here because we have no knowledge of the message the Sender is
        // asking about.  Reply UNKNOWN so the Sender can react accordingly.
        Perf::counters.tx_unknown_pkts.add(1);
        ControlPacket::send<Protocol::Packet::UnknownHeader>(driver, sourceIp,
                                                             id);
    }
    driver->releasePackets(&packet, 1);
}

/**
 * Return a handle to a new received Message.
 *
 * The Transport should regularly call this method to insure incoming messages
 * are processed.
 *
 * @return
 *      A new Message which has been received, if available; otherwise, nullptr.
 *
 * @sa dropMessage()
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
    MessageBucket* bucket = messageBuckets.buckets.at(index);
    uint64_t now = PerfUtils::Cycles::rdtsc();
    checkResendTimeouts(now, bucket);
    checkMessageTimeouts(now, bucket);
}

/**
 * Destruct a Message. Will release all contained Packet objects.
 */
Receiver::Message::~Message()
{
    // Find contiguous ranges of packets and release them back to the
    // driver.
    int num = 0;
    int index = 0;
    int packetsFound = 0;
    for (int i = 0; i < MAX_MESSAGE_PACKETS && packetsFound < numPackets; ++i) {
        if (occupied.test(i)) {
            if (num == 0) {
                // First packet in new region.
                index = i;
            }
            ++num;
            ++packetsFound;
        } else {
            if (num != 0) {
                // End of region; release the last region.
                driver->releasePackets(&packets[index], num);
                num = 0;
            }
        }
    }
    if (num != 0) {
        // Release the last region (if any).
        driver->releasePackets(&packets[index], num);
    }
}

/**
 * @copydoc Homa::InMessage::acknowledge()
 */
void
Receiver::Message::acknowledge() const
{
    MessageBucket* bucket = receiver->messageBuckets.getBucket(id);
    SpinLock::Lock lock(bucket->mutex);
    Perf::counters.tx_done_pkts.add(1);
    ControlPacket::send<Protocol::Packet::DoneHeader>(driver, source.ip, id);
}

/**
 * @copydoc Homa::InMessage::dropped()
 */
bool
Receiver::Message::dropped() const
{
    return state.load() == State::DROPPED;
}

/**
 * @copydoc See Homa::InMessage::fail()
 */
void
Receiver::Message::fail() const
{
    MessageBucket* bucket = receiver->messageBuckets.getBucket(id);
    SpinLock::Lock lock(bucket->mutex);
    Perf::counters.tx_error_pkts.add(1);
    ControlPacket::send<Protocol::Packet::ErrorHeader>(driver, source.ip, id);
}

/**
 * @copydoc Homa::InMessage::get()
 */
size_t
Receiver::Message::get(size_t offset, void* destination, size_t count) const
{
    // This operation should be performed with the offset relative to the
    // logical beginning of the Message.
    int _offset = Util::downCast<int>(offset);
    int _count = Util::downCast<int>(count);
    int realOffset = _offset + start;
    int packetIndex = realOffset / PACKET_DATA_LENGTH;
    int packetOffset = realOffset % PACKET_DATA_LENGTH;
    int bytesCopied = 0;

    // Offset is passed the end of the message.
    if (realOffset >= messageLength) {
        return 0;
    }

    if (realOffset + _count > messageLength) {
        _count = messageLength - realOffset;
    }

    while (bytesCopied < _count) {
        uint32_t bytesToCopy =
            std::min(_count - bytesCopied, PACKET_DATA_LENGTH - packetOffset);
        Driver::Packet* packet = getPacket(packetIndex);
        if (packet != nullptr) {
            char* source = static_cast<char*>(packet->payload);
            source += packetOffset + TRANSPORT_HEADER_LENGTH;
            std::memcpy(static_cast<char*>(destination) + bytesCopied, source,
                        bytesToCopy);
        } else {
            ERROR("Message is missing data starting at packet index %u",
                  packetIndex);
            break;
        }
        bytesCopied += bytesToCopy;
        packetIndex++;
        packetOffset = 0;
    }
    return bytesCopied;
}

/**
 * @copydoc Homa::InMessage::length()
 */
size_t
Receiver::Message::length() const
{
    return Util::downCast<size_t>(messageLength - start);
}

/**
 * @copydoc Homa::InMessage::strip()
 */
void
Receiver::Message::strip(size_t count)
{
    start = std::min(start + Util::downCast<int>(count), messageLength);
}

/**
 * @copydoc Homa::InMessage::release()
 */
void
Receiver::Message::release()
{
    receiver->dropMessage(this);
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
Receiver::Message::getPacket(size_t index) const
{
    if (occupied.test(index)) {
        return packets[index];
    }
    return nullptr;
}

/**
 * Store the given packet as the Packet of the given index if one does not
 * already exist.
 *
 * Responsibly for releasing the given Packet is passed to this context if the
 * Packet is stored (returns true).
 *
 * @param index
 *      The Packet's index in the array of packets that form the message.
 *      "packet index = "packet message offset" / PACKET_DATA_LENGTH
 * @param packet
 *      The packet pointer that should be stored.
 * @return
 *      True if the packet was stored; false if a packet already exists (the new
 *      packet is not stored).
 */
bool
Receiver::Message::setPacket(size_t index, Driver::Packet* packet)
{
    if (occupied.test(index)) {
        return false;
    }
    packets[index] = packet;
    occupied.set(index);
    numPackets++;
    return true;
}

/**
 * Inform the Receiver that an Message returned by receiveMessage() is not
 * needed and can be dropped.
 *
 * @param message
 *      Message which will be dropped.
 */
void
Receiver::dropMessage(Receiver::Message* message)
{
    Protocol::MessageId msgId = message->id;
    MessageBucket* bucket = messageBuckets.getBucket(msgId);
    SpinLock::Lock lock_bucket(bucket->mutex);
    Message* foundMessage = bucket->findMessage(msgId, lock_bucket);
    if (foundMessage != nullptr) {
        assert(message == foundMessage);
        bucket->messageTimeouts.cancelTimeout(&message->messageTimeout);
        bucket->resendTimeouts.cancelTimeout(&message->resendTimeout);
        if (message->scheduled) {
            // Unschedule the message if it is still scheduled (i.e. still
            // linked to a scheduled peer).
            SpinLock::Lock lock_scheduler(schedulerMutex);
            ScheduledMessageInfo* info = &message->scheduledMessageInfo;
            if (info->peer != nullptr) {
                unschedule(message, lock_scheduler);
            }
        }
        bucket->messages.remove(&message->bucketNode);
        {
            SpinLock::Lock lock_allocator(messageAllocator.mutex);
            messageAllocator.pool.destroy(message);
            Perf::counters.destroyed_rx_messages.add(1);
        }
    }
}

/**
 * Process any inbound messages that have timed out due to lack of activity from
 * the Sender.
 *
 *
 * Pulled out of checkTimeouts() for ease of testing.
 *
 * @param now
 *      The rdtsc cycle that should be considered the "current" time.
 * @param bucket
 *      The bucket whose message timeouts should be checked.
 */
void
Receiver::checkMessageTimeouts(uint64_t now, MessageBucket* bucket)
{
    if (!bucket->messageTimeouts.anyElapsed(now)) {
        return;
    }

    while (true) {
        SpinLock::Lock lock_bucket(bucket->mutex);

        // No remaining timeouts.
        if (bucket->messageTimeouts.empty()) {
            break;
        }

        Message* message = &bucket->messageTimeouts.front();

        // No remaining expired timeouts.
        if (!message->messageTimeout.hasElapsed(now)) {
            break;
        }

        // Found expired timeout.

        // Cancel timeouts
        bucket->messageTimeouts.cancelTimeout(&message->messageTimeout);
        bucket->resendTimeouts.cancelTimeout(&message->resendTimeout);

        if (message->state == Message::State::IN_PROGRESS) {
            // Message timed out before being fully received; drop the
            // message.

            // Unschedule the message
            if (message->scheduled) {
                // Unschedule the message if it is still scheduled (i.e.
                // still linked to a scheduled peer).
                SpinLock::Lock lock_scheduler(schedulerMutex);
                ScheduledMessageInfo* info = &message->scheduledMessageInfo;
                if (info->peer != nullptr) {
                    unschedule(message, lock_scheduler);
                }
            }

            bucket->messages.remove(&message->bucketNode);
            {
                SpinLock::Lock lock_allocator(messageAllocator.mutex);
                messageAllocator.pool.destroy(message);
            }
        } else {
            // Message timed out but we already made it available to the
            // Transport; let the Transport know.
            message->state.store(Message::State::DROPPED);
        }
    }
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
        SpinLock::Lock lock_bucket(bucket->mutex);

        // No remaining timeouts.
        if (bucket->resendTimeouts.empty()) {
            break;
        }

        Message* message = &bucket->resendTimeouts.front();

        // No remaining expired timeouts.
        if (!message->resendTimeout.hasElapsed(now)) {
            break;
        }

        // Found expired timeout.
        assert(message->state == Message::State::IN_PROGRESS);
        bucket->resendTimeouts.setTimeout(&message->resendTimeout);

        // This Receiver expected to have heard from the Sender within the
        // last timeout period but it didn't.  Request a resend of granted
        // packets in case DATA packets got lost.
        int index = 0;
        int num = 0;
        int grantIndexLimit = message->numUnscheduledPackets;

        if (message->scheduled) {
            SpinLock::Lock lock_scheduler(schedulerMutex);
            ScheduledMessageInfo* info = &message->scheduledMessageInfo;
            int receivedBytes = info->messageLength - info->bytesRemaining;
            if (receivedBytes >= info->bytesGranted) {
                // Sender is blocked on this Receiver; all granted packets
                // have already been received.  No need to check for resend.
                continue;
            } else if (grantIndexLimit * message->PACKET_DATA_LENGTH <
                       info->bytesGranted) {
                grantIndexLimit =
                    (info->bytesGranted + message->PACKET_DATA_LENGTH - 1) /
                    message->PACKET_DATA_LENGTH;
            }
        }

        for (int i = 0; i < grantIndexLimit; ++i) {
            if (message->getPacket(i) == nullptr) {
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
                    //
                    // The RESEND also includes the current granted priority
                    // so that it can act as a GRANT in case a GRANT was
                    // lost.  If this message hasn't been scheduled (i.e. no
                    // grants have been sent) then the priority will hold
                    // the default value; this is ok since the Sender will
                    // ignore the priority field for resends of purely
                    // unscheduled packets (see
                    // Sender::handleResendPacket()).
                    SpinLock::Lock lock_scheduler(schedulerMutex);
                    Perf::counters.tx_resend_pkts.add(1);
                    ControlPacket::send<Protocol::Packet::ResendHeader>(
                        message->driver, message->source.ip, message->id,
                        Util::downCast<uint16_t>(index),
                        Util::downCast<uint16_t>(num),
                        message->scheduledMessageInfo.priority);
                    num = 0;
                }
            }
        }
        if (num != 0) {
            // Send out the last range of packets found.
            SpinLock::Lock lock_scheduler(schedulerMutex);
            Perf::counters.tx_resend_pkts.add(1);
            ControlPacket::send<Protocol::Packet::ResendHeader>(
                message->driver, message->source.ip, message->id,
                Util::downCast<uint16_t>(index), Util::downCast<uint16_t>(num),
                message->scheduledMessageInfo.priority);
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
        Message* message = &it->scheduledMessages.front();
        ScheduledMessageInfo* info = &message->scheduledMessageInfo;
        // Access message const variables without message mutex.
        const Protocol::MessageId id = message->id;
        const IpAddress sourceIp = message->source.ip;

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
                driver, sourceIp, id,
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
                                     &info->scheduledMessageNode,
                                     ScheduledMessageInfo::ComparePriority());
    info->peer = peer;
    if (!scheduledPeers.contains(&peer->scheduledPeerNode)) {
        // Must be the only message of this peer; push the peer to the
        // end of list to be moved later.
        assert(peer->scheduledMessages.size() == 1);
        scheduledPeers.push_front(&peer->scheduledPeerNode);
        Intrusive::deprioritize<Peer>(&scheduledPeers, &peer->scheduledPeerNode,
                                      Peer::ComparePriority());
    } else if (&info->peer->scheduledMessages.front() == message) {
        // Update the Peer's position in the queue since the new message is the
        // peer's first scheduled message.
        Intrusive::prioritize<Peer>(&scheduledPeers,
                                    &info->peer->scheduledPeerNode,
                                    Peer::ComparePriority());
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
        // Remove the empty peer.
        scheduledPeers.remove(it);
    } else if (std::next(it) == scheduledPeers.end() ||
               !comp(*std::next(it), *it)) {
        // Peer already in the right place (peer incremented as part of the
        // check).  Note that only "next" needs be checked (and not "prev")
        // since removing a message cannot increase the peer's priority.
    } else {
        // Peer needs to be moved.
        Intrusive::deprioritize<Peer>(&scheduledPeers, &peer->scheduledPeerNode,
                                      comp);
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
                                   &info->scheduledMessageNode,
                                   ScheduledMessageInfo::ComparePriority());

    // Update the Peer's position in the queue if this message is now the first
    // scheduled message.
    if (&info->peer->scheduledMessages.front() == message) {
        Intrusive::prioritize<Peer>(&scheduledPeers,
                                    &info->peer->scheduledPeerNode,
                                    Peer::ComparePriority());
    }
}

}  // namespace Core
}  // namespace Homa
