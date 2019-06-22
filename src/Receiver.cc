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

namespace Homa {
namespace Core {

namespace {
const uint32_t RTT_TIME_US = 5;
}

/**
 * Receiver constructor.
 *
 * @param transport
 *      The Tranport object that owns this Receiver.
 */
Receiver::Receiver(Transport* transport)
    : mutex()
    , transport(transport)
    , inboundMessages()
    , receivedMessages()
    , messagePool()
    , scheduling()
{}

/**
 * Receiver distructor.
 */
Receiver::~Receiver()
{
    mutex.lock();
    for (auto it = inboundMessages.begin(); it != inboundMessages.end(); ++it) {
        InboundMessage* message = it->second;
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

    InboundMessage* message = nullptr;

    auto it = inboundMessages.find(id);
    if (it != inboundMessages.end()) {
        // Existing message
        message = it->second;
    } else {
        // New message
        message = messagePool.construct();
        // Touch OK w/o lock before externalizing.
        message->id = id;
        inboundMessages.insert(it, {id, message});
        receivedMessages.push_back(message);
    }

    // Lock handoff
    SpinLock::Lock lock_message(message->mutex);
    lock.unlock();

    assert(id == message->id);
    if (!message->message) {
        uint32_t messageLength = header->totalLength;
        message->message.construct(driver, dataHeaderLength, messageLength);
        // Get an address pointer from the driver; the one in the packet
        // may disappear when the packet goes away.
        std::string addrStr = packet->address->toString();
        message->source = driver->getAddress(&addrStr);
        message->numExpectedPackets =
            messageLength / message->message->PACKET_DATA_LENGTH;
        message->numExpectedPackets +=
            messageLength % message->message->PACKET_DATA_LENGTH ? 1 : 0;
    }

    // Sender is still sending; consider this message active.
    message->active = true;

    // All packets already received; must be a duplicate.
    if (message->fullMessageReceived) {
        // drop packet
        driver->releasePackets(&packet, 1);
        return;
    }

    // Things that must be true (sanity check)
    assert(message->source->toString() == packet->address->toString());
    assert(message->message->rawLength() == header->totalLength);

    // Add the packet
    bool packetAdded = message->message->setPacket(header->index, packet);
    if (packetAdded) {
        // This value is technically sloppy since last packet of the message
        // which may not be a full packet. However, this should be fine since
        // receiving the last packet means we don't need the scheduler to GRANT
        // more packets anyway.
        uint32_t totalReceivedBytes = message->message->PACKET_DATA_LENGTH *
                                      message->message->getNumPackets();
        message->newPacket = true;
        if (totalReceivedBytes >= message->message->rawLength()) {
            message->fullMessageReceived = true;
            if (message->op != nullptr) {
                transport->hintUpdatedOp(message->op);
            }
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
        InboundMessage* message = it->second;
        // Lock handoff
        SpinLock::Lock lock_message(message->mutex);
        lock.unlock();

        // Sender has replied BUSY to our RESEND request; consider this message
        // still active.
        message->active = true;
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
        InboundMessage* message = it->second;
        // Lock handoff
        SpinLock::Lock lock_message(message->mutex);
        lock.unlock();

        // Sender is checking on this message; consider it still active.
        message->active = true;

        // We are here either because a GRANT got lost, or we haven't issued
        // a GRANT in along time.  In either case, resend the latest GRANT so
        // the Sender knows we are still working on the message.
        ControlPacket::send<Protocol::Packet::GrantHeader>(
            driver, message->source, message->id, message->grantIndexLimit);
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
 * Return a handle to a new (partially) received InboundMessage.  If the message
 * is only partially received when returned; the Receiver will continue to
 * proceesing incoming packets for the InboundMessage.
 *
 * The Transport should regularly call this method to insure incoming messages
 * are processed.
 *
 * @return
 *      A new InboundMessage which has been at least partially received, if
 *      available; otherwise, nullptr.
 *
 * @sa dropMessage()
 */
InboundMessage*
Receiver::receiveMessage()
{
    SpinLock::Lock lock(mutex);
    InboundMessage* message = nullptr;
    if (!receivedMessages.empty()) {
        message = receivedMessages.front();
        receivedMessages.pop_front();
    }
    return message;
}

/**
 * Inform the Receiver that an InboundMessage returned by receiveMessage() is
 * not needed and can be dropped.
 *
 * @param message
 *      InboundMessage which will be dropped.
 */
void
Receiver::dropMessage(InboundMessage* message)
{
    SpinLock::Lock lock(mutex);
    message->mutex.lock();
    if (inboundMessages.erase(message->id) > 0) {
        messagePool.destroy(message);
    }
}

/**
 * Allow the Receiver to make incremental progress on background tasks.
 */
void
Receiver::poll()
{
    schedule();
}

/**
 * Send a GRANT packet to the Sender of an incoming Message.
 *
 * @param message
 *      InboundMessage for which to send a GRANT.
 * @param driver
 *      Driver with which the GRANT packet should be sent.
 * @param lock_message
 *      Used to remind the caller to hold the message's mutex while calling
 *      this method.
 */
void
Receiver::sendGrantPacket(InboundMessage* message, Driver* driver,
                          const SpinLock::Lock& lock_message)
{
    (void)lock_message;
    // TODO(cstlee): Implement Homa's grant policy.
    // Implements a very simple grant policy which tries to maintain RTT bytes
    // granted for every Message.
    // TODO(cstlee): Add safe guards to prevent RTT_BYTES from being less than
    //               a single packet length. The sender might get stuck if the
    //               grants are smaller than a single packet.
    uint32_t RTT_BYTES = RTT_TIME_US * (driver->getBandwidth() / 8);
    uint32_t RTT_PACKETS = RTT_BYTES / message->message->PACKET_DATA_LENGTH;
    uint16_t indexLimit =
        std::min(Util::downCast<uint16_t>(message->message->getNumPackets() +
                                          RTT_PACKETS),
                 message->numExpectedPackets);
    message->grantIndexLimit = indexLimit;

    ControlPacket::send<Protocol::Packet::GrantHeader>(driver, message->source,
                                                       message->id, indexLimit);
}

/**
 * Schedule incoming messages by sending GRANTs.
 */
void
Receiver::schedule()
{
    // Skip scheduling if another poller is already working on it.
    if (scheduling.test_and_set()) {
        return;
    }

    SpinLock::UniqueLock lock(mutex);

    auto it = inboundMessages.begin();
    while (it != inboundMessages.end()) {
        InboundMessage* message = it->second;
        SpinLock::Lock lock_message(message->mutex);
        if (message->newPacket) {
            // found a message to grant.
            lock.unlock();
            sendGrantPacket(message, message->message->driver, lock_message);
            message->newPacket = false;
            break;
        }
        it++;
    }

    scheduling.clear();
}

}  // namespace Core
}  // namespace Homa
