/* Copyright (c) 2018-2019, Stanford University
    Lock
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
 * @param scheduler
 *      Scheduler that should be informed when message packets are received.
 */
Receiver::Receiver()
    : mutex()
    , registeredOps()
    , unregisteredMessages()
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
    for (auto it = unregisteredMessages.begin();
         it != unregisteredMessages.end(); ++it) {
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
    Tub<SpinLock::Lock> lock_op;

    Protocol::Packet::DataHeader* header =
        static_cast<Protocol::Packet::DataHeader*>(packet->payload);
    uint16_t dataHeaderLength = sizeof(Protocol::Packet::DataHeader);
    Protocol::MessageId id = header->common.messageId;

    Transport::Op* op = nullptr;
    InboundMessage* message = nullptr;

    auto it = registeredOps.find(id);
    if (it != registeredOps.end()) {
        // Registered Op
        op = it->second;
        assert(op->inMessage != nullptr);
        message = op->inMessage;
    } else {
        // Unregistered Message
        auto it = unregisteredMessages.find(id);
        if (it != unregisteredMessages.end()) {
            // Existing unregistered message
            message = it->second;
        } else {
            // New unregistered message
            message = messagePool.construct();
            // Touch OK w/o lock before externalizing.
            message->id = id;
            unregisteredMessages.insert(it, {id, message});
            receivedMessages.push_back(message);
        }
    }

    // Lock handoff
    if (op != nullptr) {
        lock_op.construct(op->mutex);
    }
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
            if (op != nullptr) {
                op->hintUpdate();
            }
        }
    } else {
        // must be a duplicate packet; drop packet.
        driver->releasePackets(&packet, 1);
    }
    return;
}

/**
 * Return an InboundMessage that has not been registered with an Transport::Op.
 *
 * The Transport should regularly call this method to insure incomming messages
 * are processed.  The Transport can choose to register the InboundMessage with
 * an Transport::Op or drop the message if it is not of interest.
 *
 * Returned message may not be fully received.  The Receiver will continue to
 * process packets into the returned InboundMessage until it is dropped.
 *
 * @return
 *      A new InboundMessage which has been at least partially received but not
 *      register, if available; otherwise, nullptr.
 *
 * @sa registerOp(), dropMessage()
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
    if (unregisteredMessages.erase(message->id) > 0) {
        messagePool.destroy(message);
    }
}

/**
 * Inform the Receiver that an incomming Message is expected and should be
 * associated with a particular Transport::Op.
 *
 * @param id
 *      Id of the Message that should be expected.
 * @param op
 *      Transport::Op where the expected Message should be accumulated.
 */
void
Receiver::registerOp(Protocol::MessageId id, Transport::Op* op)
{
    SpinLock::Lock lock(mutex);
    SpinLock::Lock lock_op(op->mutex);
    InboundMessage* message;
    auto it = unregisteredMessages.find(id);
    if (it != unregisteredMessages.end()) {
        // Existing message
        message = it->second;
        unregisteredMessages.erase(it);
        op->hintUpdate();
    } else {
        // New message
        message = messagePool.construct();
        // Touch OK w/o lock before externalizing.
        message->id = id;
    }
    op->inMessage = message;
    registeredOps.insert({id, op});
}

/**
 * Inform the Receiver that a Message is no longer needed and the associated
 * Transport::Op should no longer be used.
 *
 * @param op
 *      The Transport::Op which contains the Message that is no longer needed.
 */
void
Receiver::dropOp(Transport::Op* op)
{
    SpinLock::Lock lock(mutex);
    SpinLock::Lock lock_op(op->mutex);
    if (op->inMessage != nullptr) {
        InboundMessage* message = op->inMessage;
        message->mutex.lock();
        op->inMessage = nullptr;
        registeredOps.erase(message->id);
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
 * Send a GRANT packet to the Sender of an incomming Message.
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

    ControlPacket::send<Protocol::Packet::GrantHeader>(driver, message->source,
                                                       message->id, indexLimit);
}

/**
 * Schedule incomming messages by sending GRANTs.
 */
void
Receiver::schedule()
{
    // Skip scheduling if another poller is already working on it.
    if (scheduling.test_and_set()) {
        return;
    }

    SpinLock::UniqueLock lock(mutex);
    Tub<SpinLock::Lock> lock_op;
    Tub<SpinLock::Lock> lock_message;

    Transport::Op* op = nullptr;
    InboundMessage* message = nullptr;

    // First look in registered ops
    auto it = registeredOps.begin();
    while (it != registeredOps.end()) {
        op = it->second;
        lock_op.construct(op->mutex);
        message = op->inMessage;
        lock_message.construct(message->mutex);
        if (message->newPacket) {
            // found a message to send.
            break;
        }
        lock_message.destroy();
        message = nullptr;
        lock_op.destroy();
        op = nullptr;
        it++;
    }

    // Look in unregisteredMessages if we still don't have one.
    if (message == nullptr) {
        auto it = unregisteredMessages.begin();
        while (it != unregisteredMessages.end()) {
            message = it->second;
            lock_message.construct(message->mutex);
            if (message->newPacket) {
                // found a message to send.
                break;
            }
            lock_message.destroy();
            message = nullptr;
            it++;
        }
    }

    if (message != nullptr) {
        sendGrantPacket(message, message->message->driver, *lock_message);
        message->newPacket = false;
    }

    scheduling.clear();
}

}  // namespace Core
}  // namespace Homa
