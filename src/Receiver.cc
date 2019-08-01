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

#include "Receiver.h"

#include <Cycles.h>

#include "Transport.h"

namespace Homa {
namespace Core {

/**
 * Receiver constructor.
 *
 * @param transport
 *      The Transport object that owns this Receiver.
 * @param policyManager
 *      Provides information about the grant and network priority policies.
 * @param messageTimeoutCycles
 *      Number of cycles of inactivity to wait before this Receiver declares an
 *      Receiver::Message receive failure.
 * @param resendIntervalCycles
 *      Number of cycles of inactivity to wait between requesting retransmission
 *      of un-received parts of a message.
 */
Receiver::Receiver(Transport* transport, Policy::Manager* policyManager,
                   uint64_t messageTimeoutCycles, uint64_t resendIntervalCycles)
    : mutex()
    , transport(transport)
    , policyManager(policyManager)
    , inboundMessages()
    , scheduledPeers()
    , receivedMessages()
    , messagePool()
    , messageTimeouts(messageTimeoutCycles)
    , resendTimeouts(resendIntervalCycles)
    , scheduling()
{}

/**
 * Receiver destructor.
 */
Receiver::~Receiver()
{
    mutex.lock();
    scheduledPeers.clear();
    peerTable.clear();
    receivedMessages.mutex.lock();
    receivedMessages.queue.clear();
    messageTimeouts.list.clear();
    resendTimeouts.list.clear();
    for (auto it = inboundMessages.begin(); it != inboundMessages.end(); ++it) {
        Message* message = it->second;
        messagePool.destroy(message);
    }
}

/**
 * Process an incoming DATA packet.
 *
 * @param packet
 *      The incoming packet to be processed.
 * @param driver
 *      The driver from which the packet was received.
 */
void
Receiver::handleDataPacket(Driver::Packet* packet, Driver* driver)
{
    SpinLock::UniqueLock lock(mutex);

    Protocol::Packet::DataHeader* header =
        static_cast<Protocol::Packet::DataHeader*>(packet->payload);
    uint16_t dataHeaderLength = sizeof(Protocol::Packet::DataHeader);
    Protocol::MessageId id = header->common.messageId;

    Message* message = nullptr;

    auto it = inboundMessages.find(id);
    if (it != inboundMessages.end()) {
        // Existing message
        message = it->second;
    } else {
        // New message
        uint32_t messageLength = header->totalLength;
        message =
            messagePool.construct(driver, dataHeaderLength, messageLength);
        message->id = id;
        message->source = packet->address;
        message->numExpectedPackets =
            messageLength / message->PACKET_DATA_LENGTH;
        message->numExpectedPackets +=
            messageLength % message->PACKET_DATA_LENGTH ? 1 : 0;
        message->grantIndexLimit = header->unscheduledIndexLimit;

        inboundMessages.insert(it, {id, message});
        policyManager->signalNewMessage(message->source, header->policyVersion,
                                        header->totalLength);

        if (message->numExpectedPackets > message->grantIndexLimit) {
            // Message needs to be scheduled.
            message->peer = schedule(message, &peerTable, &scheduledPeers);
        }
    }

    SpinLock::Lock lock_message(message->mutex);
    messageTimeouts.setTimeout(&message->messageTimeout);
    resendTimeouts.setTimeout(&message->resendTimeout);

    assert(id == message->id);

    // All packets already received; must be a duplicate.
    if (message->state == Message::State::COMPLETED) {
        lock.unlock();  // End Receiver critical section
        // drop packet
        driver->releasePackets(&packet, 1);
        return;
    }

    // Things that must be true (sanity check)
    assert(message->driver == driver);
    assert(message->source == packet->address);
    assert(message->rawLength() == header->totalLength);

    // Add the packet
    bool packetAdded = message->setPacket(header->index, packet);
    if (packetAdded) {
        uint32_t packetDataBytes =
            packet->length - message->PACKET_HEADER_LENGTH;
        assert(message->unreceivedBytes >= packetDataBytes);
        message->unreceivedBytes -= packetDataBytes;
        if (message->unreceivedBytes > 0) {
            // Message incomplete. Update the schedule.
            if (message->peer != nullptr) {
                updateSchedule(message, message->peer, &scheduledPeers);
            }
        } else {
            // Message received
            lock.unlock();  // End Receiver critical section
            message->state.store(Message::State::COMPLETED);
            SpinLock::Lock lock_received_messages(receivedMessages.mutex);
            receivedMessages.queue.push_back(&message->receivedMessageNode);
        }
    } else {
        lock.unlock();  // End Receiver critical section
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
 * @param driver
 *      The driver from which the BUSY packet was received.
 */
void
Receiver::handleBusyPacket(Driver::Packet* packet, Driver* driver)
{
    SpinLock::UniqueLock lock(mutex);

    Protocol::Packet::BusyHeader* header =
        static_cast<Protocol::Packet::BusyHeader*>(packet->payload);
    Protocol::MessageId id = header->common.messageId;

    auto it = inboundMessages.find(id);
    if (it != inboundMessages.end()) {
        Message* message = it->second;

        SpinLock::Lock lock_message(message->mutex);
        // Sender has replied BUSY to our RESEND request; consider this message
        // still active.
        messageTimeouts.setTimeout(&message->messageTimeout);
        resendTimeouts.setTimeout(&message->resendTimeout);
        lock.unlock();  // End Receiver critical section
    }
    driver->releasePackets(&packet, 1);
}

/**
 * Process an incoming PING packet.
 *
 * @param packet
 *      The incoming PING packet to be processed.
 * @param driver
 *      The driver from which the PING packet was received.
 */
void
Receiver::handlePingPacket(Driver::Packet* packet, Driver* driver)
{
    SpinLock::UniqueLock lock(mutex);

    Protocol::Packet::PingHeader* header =
        static_cast<Protocol::Packet::PingHeader*>(packet->payload);
    Protocol::MessageId id = header->common.messageId;

    auto it = inboundMessages.find(id);
    if (it != inboundMessages.end()) {
        Message* message = it->second;

        SpinLock::Lock lock_message(message->mutex);
        // Sender is checking on this message; consider it still active.
        messageTimeouts.setTimeout(&message->messageTimeout);
        lock.unlock();  // End Receiver critical section

        // We are here either because a GRANT got lost, or we haven't issued
        // a GRANT in along time.  In either case, resend the latest GRANT so
        // the Sender knows we are still working on the message.
        ControlPacket::send<Protocol::Packet::GrantHeader>(
            driver, message->source, message->id, message->grantIndexLimit,
            message->priority);
    } else {
        lock.unlock();
        // We are here because we have no knowledge of the message the Sender is
        // asking about.  Reply UNKNOWN so the Sender can react accordingly.
        ControlPacket::send<Protocol::Packet::UnknownHeader>(
            driver, packet->address, id);
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
Receiver::Message*
Receiver::receiveMessage()
{
    SpinLock::Lock lock_received_messages(receivedMessages.mutex);
    Message* message = nullptr;
    if (!receivedMessages.queue.empty()) {
        message = &receivedMessages.queue.front();
        receivedMessages.queue.pop_front();
    }
    return message;
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
    SpinLock::Lock lock(mutex);
    message->mutex.lock();
    if (inboundMessages.erase(message->id) > 0) {
        assert(message->peer == nullptr);
        messageTimeouts.cancelTimeout(&message->messageTimeout);
        resendTimeouts.cancelTimeout(&message->resendTimeout);
        messagePool.destroy(message);
    }
}

/**
 * Allow the Receiver to make incremental progress on background tasks.
 */
void
Receiver::poll()
{
    runScheduler();
    checkResendTimeouts();
    checkMessageTimeouts();
}

/**
 * Process any inbound messages that have timed out due to lack of activity from
 * the Sender.
 *
 * Pulled out of poll() for ease of testing.
 */
void
Receiver::checkMessageTimeouts()
{
    while (true) {
        SpinLock::Lock lock(mutex);
        // No remaining timeouts.
        if (messageTimeouts.list.empty()) {
            break;
        }
        Message* message = &messageTimeouts.list.front();
        SpinLock::UniqueLock lock_message(message->mutex);
        // No remaining expired timeouts.
        if (!message->messageTimeout.hasElapsed()) {
            break;
        }
        // Found expired timeout.
        // Unschedule the message
        if (message->peer != nullptr) {
            unschedule(message, message->peer, &scheduledPeers);
            message->peer = nullptr;
        }
        messageTimeouts.cancelTimeout(&message->messageTimeout);
        resendTimeouts.cancelTimeout(&message->resendTimeout);
        if (message->state == Message::State::IN_PROGRESS) {
            // Message timed out before being fully received; drop the message.
            // Unschedule the message
            if (message->peer != nullptr) {
                unschedule(message, message->peer, &scheduledPeers);
                message->peer = nullptr;
            }
            lock_message.release();
            if (inboundMessages.erase(message->id) > 0) {
                messagePool.destroy(message);
            }
        } else {
            // Message timed out but we already made it available to the
            // Transport; let the Transport know.
            assert(message->peer == nullptr);
            message->state.store(Message::State::DROPPED);
            transport->hintUpdatedOp(message->op);
        }
    }
}

/**
 * Process any inbound messages that may need to issue resends.
 *
 * Pulled out of poll() fro ease of testing.
 */
void
Receiver::checkResendTimeouts()
{
    while (true) {
        SpinLock::UniqueLock lock(mutex);
        // No remaining timeouts.
        if (resendTimeouts.list.empty()) {
            break;
        }
        Message* message = &resendTimeouts.list.front();
        SpinLock::Lock lock_message(message->mutex);
        // No remaining expired timeouts.
        if (!message->resendTimeout.hasElapsed()) {
            break;
        }
        // Found expired timeout.
        if (message->state == Message::State::IN_PROGRESS) {
            resendTimeouts.setTimeout(&message->resendTimeout);
        } else {
            resendTimeouts.cancelTimeout(&message->resendTimeout);
            continue;
        }
        lock.unlock();  // End Sender critical section.

        // Sender is blocked on this Receiver; all granted packets have already
        // been received.
        if (message->getNumPackets() >= message->grantIndexLimit) {
            continue;
        }

        // This Receiver expected to have heard from the Sender within the last
        // timeout period but it didn't.  Request a resend of granted packets
        // in case DATA packets got lost.
        uint16_t index = 0;
        uint16_t num = 0;
        for (uint16_t i = 0; i < message->grantIndexLimit; ++i) {
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
                    // The RESEND also includes the current granted priority so
                    // that it can act as a GRANT in case a GRANT was lost.  If
                    // this message hasn't been scheduled (i.e. no grants have
                    // been sent) then the priority will hold the default value;
                    // this is ok since the Sender will ignore the priority
                    // field for resends of purely unscheduled packets (see
                    // Sender::handleResendPacket()).
                    ControlPacket::send<Protocol::Packet::ResendHeader>(
                        message->driver, message->source, message->id, index,
                        num, message->priority);
                    num = 0;
                }
            }
        }
        if (num != 0) {
            // Send out the last range of packets found.
            ControlPacket::send<Protocol::Packet::ResendHeader>(
                message->driver, message->source, message->id, index, num,
                message->priority);
        }
    }
}

/**
 * Schedule incoming messages by sending GRANTs.
 */
void
Receiver::runScheduler()
{
    // Skip scheduling if another poller is already working on it.
    if (scheduling.test_and_set()) {
        return;
    }

    /* The overall goal is to grant up to policy.degreeOvercommitment number of
     * scheduled messages simultaneously.  Each of these messages should always
     * have policy.scheduledBytesLimit number of bytes granted.  Ideally, each
     * message will be assign a different network priority based on a message's
     * number of unreceivedBytes.  The message with the fewest unreceivedBytes
     * (SRPT) will be assigned the highest priority.  If the number of messages
     * to grant exceeds the number of available priorities, the lowest priority
     * is shared by multiple messages.  If the number of messages to grant is
     * fewer than the the available priority, than the messages are assigned to
     * the lowest available priority.
     */
    SpinLock::UniqueLock lock(mutex);
    Policy::Scheduled policy = policyManager->getScheduledPolicy();
    assert(policy.degreeOvercommitment > policy.maxScheduledPriority);
    int unusedPriorities =
        std::max(0, (policy.maxScheduledPriority + 1) -
                        Util::downCast<int>(scheduledPeers.size()));

    auto it = scheduledPeers.begin();
    int slot = 0;
    while (it != scheduledPeers.end() && slot < policy.degreeOvercommitment) {
        assert(!it->scheduledMessages.empty());
        Message* message = &it->scheduledMessages.front();
        SpinLock::Lock lock_message(message->mutex);
        message->priority =
            std::max(0, policy.maxScheduledPriority - slot - unusedPriorities);
        uint16_t newGrantLimit = std::min(
            Util::downCast<uint16_t>(
                message->getNumPackets() +
                ((policy.scheduledByteLimit + message->PACKET_DATA_LENGTH - 1) /
                 message->PACKET_DATA_LENGTH)),
            message->numExpectedPackets);
        if (newGrantLimit > message->grantIndexLimit) {
            message->grantIndexLimit = newGrantLimit;
            ControlPacket::send<Protocol::Packet::GrantHeader>(
                message->driver, message->source, message->id,
                message->grantIndexLimit, message->priority);
        }
        if (message->numExpectedPackets > message->grantIndexLimit) {
            // Continue to schedule this message.
            ++it;
        } else {
            // All packets granted, unschedule the message.
            it = unschedule(message, message->peer, &scheduledPeers);
            message->peer = nullptr;
        }
        ++slot;
    }

    scheduling.clear();
}

/**
 * Add a Message to the schedule.
 *
 * Helper function separated mostly for ease of testing.
 *
 * @param message
 *      Message to be added.
 * @param peerTable
 *      Allocates and holds Peer objects.
 * @param scheduledPeers
 *      List that holds the schedule to which the message will be added.
 * @return
 *      The Peer object that holds the newly scheduled message.
 */
Receiver::Peer*
Receiver::schedule(
    Receiver::Message* message,
    std::unordered_map<Driver::Address, Receiver::Peer>* peerTable,
    Intrusive::List<Peer>* scheduledPeers)

{
    // Push the message to the back of the scheduledMessage list; it will be
    // moved to the correct position during the schedule update.
    Peer* peer = &(*peerTable)[message->source];
    peer->scheduledMessages.push_back(&message->scheduledMessageNode);
    if (!scheduledPeers->contains(&peer->scheduledPeerNode)) {
        // Must be the only message of this peer; push the peer to the
        // end of list to be moved later.
        assert(peer->scheduledMessages.size() == 1);
        scheduledPeers->push_back(&peer->scheduledPeerNode);
    }
    return peer;
}

/**
 * Remove a Message from the schedule.
 *
 * Helper function separated mostly for ease of testing.
 *
 * @param message
 *      Message to be removed.
 * @param peer
 *      Peer to which the Message belongs.
 * @param scheduledPeers
 *      List that holds the schedule from which the message should be removed.
 * @return
 *      Iterator to the Peer following the removed Message's Peer.
 */
Intrusive::List<Receiver::Peer>::Iterator
Receiver::unschedule(Receiver::Message* message, Receiver::Peer* peer,
                     Intrusive::List<Peer>* scheduledPeers)

{
    Intrusive::List<Peer>::Iterator it =
        scheduledPeers->get(&peer->scheduledPeerNode);
    Peer::ComparePriority comp;

    // Remove message.
    assert(peer->scheduledMessages.contains(&message->scheduledMessageNode));
    peer->scheduledMessages.remove(&message->scheduledMessageNode);

    // Cleanup the schedule
    if (peer->scheduledMessages.empty()) {
        // Remove the empty peer.
        it = scheduledPeers->remove(it);
    } else if (std::next(it) == scheduledPeers->end() ||
               !comp(*std::next(it), *it)) {
        // Peer already in the right place (peer incremented as part
        // of the check).
        ++it;
    } else {
        // Peer needs to be moved.
        it = scheduledPeers->remove(it);
        scheduledPeers->push_back(&peer->scheduledPeerNode);
        prioritize<Peer>(scheduledPeers, &peer->scheduledPeerNode, comp);
    }
    return it;
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
 * @param peer
 *      Peer to which the Message belongs.
 * @param scheduledPeers
 *      List that holds the schedule to be updated.
 */
void
Receiver::updateSchedule(Receiver::Message* message, Receiver::Peer* peer,
                         Intrusive::List<Peer>* scheduledPeers)
{
    // Update the message's position within its Peer scheduled message queue.
    prioritize<Message>(&peer->scheduledMessages,
                        &message->scheduledMessageNode,
                        Message::ComparePriority());

    // Update the Peer's position in the queue if this message is now the first
    // scheduled message.
    if (&peer->scheduledMessages.front() == message) {
        prioritize<Peer>(scheduledPeers, &peer->scheduledPeerNode,
                         Peer::ComparePriority());
    }
}

}  // namespace Core
}  // namespace Homa
