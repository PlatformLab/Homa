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

#include "Transport.h"

#include <algorithm>
#include <memory>
#include <utility>

#include "Cycles.h"

#include "Protocol.h"
#include "Receiver.h"
#include "Sender.h"

namespace Homa {
namespace Core {

// Basic timeout unit.
const uint64_t BASE_TIMEOUT_US = 2000;
/// Microseconds to wait before timeout out and failing a message.
const uint64_t MESSAGE_TIMEOUT_US = 40 * BASE_TIMEOUT_US;
/// Microseconds to wait before pinging to check on outbound messages.
const uint64_t PING_INTERVAL_US = 3 * BASE_TIMEOUT_US;
/// Microseconds to wait before performing retires on inbound messages.
const uint64_t RESEND_INTERVAL_US = BASE_TIMEOUT_US;

/**
 * Check for any state changes and perform any necessary actions.
 *
 * @param lock
 *      Used to remind the caller to hold the Op's mutex while calling
 *      this method.
 */
void
Transport::Op::processUpdates(const SpinLock::Lock& lock)
{
    (void)lock;
    if (destroy) {
        return;
    }

    State copyOfState = state.load();
    OutboundMessage::State outState = outMessage.getState();
    InboundMessage::State inState = InboundMessage::State::NOT_STARTED;
    if (inMessage != nullptr) {
        inState = inMessage->getState();
    }

    if (isServerOp) {
        if (copyOfState == State::NOT_STARTED) {
            assert(inMessage != nullptr);
            if (inState == InboundMessage::State::COMPLETED) {
                // Strip-off the Message::Header.
                inMessage->get()->defineHeader<Protocol::Message::Header>();
                SpinLock::Lock lock_queue(transport->pendingServerOps.mutex);
                transport->pendingServerOps.queue.push_back(this);
                state.store(State::IN_PROGRESS);
            }
        } else if (copyOfState == State::IN_PROGRESS) {
            if ((outState == OutboundMessage::State::COMPLETED) ||
                (outboundTag == Protocol::Message::ULTIMATE_RESPONSE_TAG &&
                 outState == OutboundMessage::State::SENT)) {
                state.store(State::COMPLETED);
                if (inboundTag != Protocol::Message::INITIAL_REQUEST_TAG) {
                    Receiver::sendDonePacket(inMessage, transport->driver);
                }
                transport->hintUpdatedOp(this);
            }
        } else if (copyOfState == State::COMPLETED) {
            if (!retained) {
                drop(lock);
            }
        } else if (copyOfState == State::FAILED) {
            if (!retained) {
                drop(lock);
            }
        } else {
            PANIC("Unknown ServerOp state.");
        }
    } else {
        if (!retained) {
            // If the client is no longer interested we can just remove the Op.
            drop(lock);
        } else if (copyOfState == State::NOT_STARTED) {
            // Nothing to do.
        } else if (copyOfState == State::IN_PROGRESS) {
            if (inState == InboundMessage::State::COMPLETED) {
                // Strip-off the Message::Header.
                inMessage->get()->defineHeader<Protocol::Message::Header>();
                state.store(State::COMPLETED);
                transport->hintUpdatedOp(this);
            }
        } else if (copyOfState == State::COMPLETED) {
            // Nothing to do.
        } else if (copyOfState == State::FAILED) {
            // Nothing to do.
        } else {
            PANIC("Unknown RemoteOp state.");
        }
    }
}

/**
 * Construct an instances of a Homa-based transport.
 *
 * @param driver
 *      Driver with which this transport should send and receive packets.
 * @param transportId
 *      This transport's unique identifier in the group of transports among
 *      which this transport will communicate.
 */
Transport::Transport(Driver* driver, uint64_t transportId)
    : driver(driver)
    , transportId(transportId)
    , nextOpSequenceNumber(1)
    , sender(new Sender(this, transportId,
                        PerfUtils::Cycles::fromMicroseconds(MESSAGE_TIMEOUT_US),
                        PerfUtils::Cycles::fromMicroseconds(PING_INTERVAL_US)))
    , receiver(new Receiver(
          this, PerfUtils::Cycles::fromMicroseconds(MESSAGE_TIMEOUT_US),
          PerfUtils::Cycles::fromMicroseconds(RESEND_INTERVAL_US)))
    , mutex()
    , opPool()
    , activeOps()
    , remoteOps()
    , updateHints()
    , unusedOps()
    , pendingServerOps()
{}

/**
 * Transport Destructor.
 */
Transport::~Transport()
{
    mutex.lock();
    for (auto it = activeOps.begin(); it != activeOps.end(); ++it) {
        Op* op = *it;
        sender->dropMessage(&op->outMessage);
        if (op->inMessage != nullptr) {
            receiver->dropMessage(op->inMessage);
        }
        op->mutex.lock();
        opPool.destroy(op);
    }
};

/**
 * Return a new OpContext which can be used to hold a client's RemoteOp.
 */
OpContext*
Transport::allocOp()
{
    SpinLock::UniqueLock lock(mutex);
    Protocol::OpId opId(transportId, nextOpSequenceNumber++);
    Op* op = opPool.construct(this, driver, opId, false);
    activeOps.insert(op);
    remoteOps.insert({opId, op});

    // Lock handoff
    SpinLock::Lock lock_op(op->mutex);
    lock.unlock();

    Protocol::Message::Header* header =
        op->outMessage.defineHeader<Protocol::Message::Header>();
    new (header) Protocol::Message::Header(opId);
    driver->getLocalAddress()->toRaw(&header->replyAddress);
    op->outboundTag = Protocol::Message::INITIAL_REQUEST_TAG;
    op->retained.store(true);
    return op;
}

/**
 * Return an OpContext for an incoming request (ServerOp) if one exists.
 * Otherwise, return a nullptr;
 */
OpContext*
Transport::receiveOp()
{
    SpinLock::UniqueLock lock_queue(pendingServerOps.mutex);
    Op* op = nullptr;
    if (!pendingServerOps.queue.empty()) {
        op = pendingServerOps.queue.front();
        pendingServerOps.queue.pop_front();
        lock_queue.unlock();

        SpinLock::Lock lock_op(op->mutex);
        Protocol::Message::Header* header =
            op->outMessage.defineHeader<Protocol::Message::Header>();
        new (header) Protocol::Message::Header(op->opId);
        assert(op->inMessage != nullptr);
        assert(op->inMessage->get() != nullptr);
        header->replyAddress = op->inMessage->get()
                                   ->getHeader<Protocol::Message::Header>()
                                   ->replyAddress;
        op->retained.store(true);
    }
    return op;
}

/**
 * Signal that a previously returned OpContext from either Transport::allocOp()
 * or Transport::receiveOp() is no longer needed by the application.  The
 * OpContext should not be used by higher-level software after this call.
 *
 * @param context
 *      OpContext which is no longer needed.
 *
 * @sa Homa::Core::Transport; no support for concurrent calls to same OpContext.
 */
void
Transport::releaseOp(OpContext* context)
{
    Op* op = static_cast<Op*>(context);
    op->retained.store(false);
    hintUpdatedOp(op);
}

/**
 * Signal that the Outbound Message should be sent as a request.
 *
 * @param context
 *      OpContext that contains the request Message to be sent.
 * @param destination
 *      Network address to which the request should be sent.

 * @sa Homa::Core::Transport; no support for concurrent calls to same OpContext.
 */
void
Transport::sendRequest(OpContext* context, Driver::Address* destination)
{
    Op* op = static_cast<Op*>(context);
    SpinLock::Lock lock_op(op->mutex);
    Protocol::Message::Header* outboundHeader =
        op->outMessage.getHeader<Protocol::Message::Header>();
    if (op->isServerOp) {
        op->outboundTag = op->inboundTag + 1;
        outboundHeader->tag = op->outboundTag;
    } else {
        op->state.store(OpContext::State::IN_PROGRESS);
        op->outboundTag = Protocol::Message::INITIAL_REQUEST_TAG;
        outboundHeader->tag = op->outboundTag;
    }
    sender->sendMessage(&op->outMessage, destination);
}

/**
 * Signal that the outbound Message should be sent as a reply.
 *
 * @param context
 *      OpContext that contains the reply Message to be sent.
 *
 * @sa Homa::Core::Transport; no support for concurrent calls to same OpContext.
 */
void
Transport::sendReply(OpContext* context)
{
    Op* op = static_cast<Op*>(context);
    SpinLock::Lock lock_op(op->mutex);
    assert(op->isServerOp);
    Driver::Address* replyAddress =
        driver->getAddress(&op->inMessage->get()
                                ->getHeader<Protocol::Message::Header>()
                                ->replyAddress);
    op->state.store(OpContext::State::IN_PROGRESS);
    op->outboundTag = Protocol::Message::ULTIMATE_RESPONSE_TAG;
    op->outMessage.getHeader<Protocol::Message::Header>()->tag =
        op->outboundTag;
    sender->sendMessage(&op->outMessage, replyAddress);
}

/// See Homa::Transport::poll()
void
Transport::poll()
{
    // Receive and dispatch incoming packets.
    processPackets();

    // Allow sender and receiver to make incremental progress.
    sender->poll();
    receiver->poll();

    processInboundMessages();
    checkForUpdates();
    cleanupOps();
}

/**
 * Helper method which receives a burst of incoming packets and process them
 * through the transport protocol.  Pulled out of Transport::poll() to simplify
 * unit testing.
 */
void
Transport::processPackets()
{
    const int MAX_BURST = 32;
    Driver::Packet* packets[MAX_BURST];
    int numPackets = driver->receivePackets(MAX_BURST, packets);
    for (int i = 0; i < numPackets; ++i) {
        Driver::Packet* packet = packets[i];
        assert(packet->length >= sizeof(Protocol::Packet::CommonHeader));
        Protocol::Packet::CommonHeader* header =
            static_cast<Protocol::Packet::CommonHeader*>(packet->payload);
        switch (header->opcode) {
            case Protocol::Packet::DATA:
                receiver->handleDataPacket(packet, driver);
                break;
            case Protocol::Packet::GRANT:
                sender->handleGrantPacket(packet, driver);
                break;
            case Protocol::Packet::DONE:
                sender->handleDonePacket(packet, driver);
                break;
            case Protocol::Packet::RESEND:
                sender->handleResendPacket(packet, driver);
                break;
            case Protocol::Packet::BUSY:
                receiver->handleBusyPacket(packet, driver);
                break;
            case Protocol::Packet::PING:
                receiver->handlePingPacket(packet, driver);
                break;
            case Protocol::Packet::UNKNOWN:
                sender->handleUnknownPacket(packet, driver);
                break;
            case Protocol::Packet::ERROR:
                sender->handleErrorPacket(packet, driver);
                break;
        }
    }
}

/**
 * Helper method to process any incoming messages.
 */
void
Transport::processInboundMessages()
{
    for (InboundMessage* message = receiver->receiveMessage();
         message != nullptr; message = receiver->receiveMessage()) {
        Protocol::Message::Header* header =
            message->get()->getHeader<Protocol::Message::Header>();
        if (header->tag == Protocol::Message::ULTIMATE_RESPONSE_TAG) {
            // Incoming message is a response.
            auto it = remoteOps.find(header->opId);
            if (it != remoteOps.end()) {
                Op* op = it->second;
                SpinLock::Lock lock_op(op->mutex);
                message->registerOp(op);
                op->inMessage = message;
                op->inboundTag = Protocol::Message::ULTIMATE_RESPONSE_TAG;
                hintUpdatedOp(op);
            } else {
                // There is no RemoteOp waiting for this message; Drop it.
                receiver->dropMessage(message);
            }
        } else {
            // Incoming message is a request.
            SpinLock::UniqueLock lock(mutex);
            Op* op = opPool.construct(this, driver, header->opId, true);
            activeOps.insert(op);

            // Lock handoff
            SpinLock::Lock lock_op(op->mutex);
            lock.unlock();

            message->registerOp(op);
            op->inMessage = message;
            op->inboundTag = header->tag;
            hintUpdatedOp(op);
        }
    }
}

/**
 * Helper method to check on any updated Op objects and trigger any necessary
 * actions.
 */
void
Transport::checkForUpdates()
{
    // Limit the number of hints to check this round.
    uint hints = 0;
    {
        SpinLock::Lock lock(updateHints.mutex);
        hints = updateHints.ops.size();
        assert(updateHints.order.size() == hints);
    }

    for (uint i = 0; i < hints; ++i) {
        void* hint = nullptr;
        // Take a hint.
        {
            SpinLock::Lock lock(updateHints.mutex);
            if (updateHints.order.empty()) {
                break;
            } else {
                hint = updateHints.order.front();
                updateHints.order.pop_front();
                updateHints.ops.erase(hint);
            }
        }
        // Check that the hinted Op is still active.
        SpinLock::UniqueLock lock(mutex);
        if (activeOps.count(static_cast<Op*>(hint)) == 0) {
            continue;
        }

        // Lock handoff
        Op* op = static_cast<Op*>(hint);
        SpinLock::Lock lock_op(op->mutex);
        lock.unlock();

        // Trigger any necessary actions.
        op->processUpdates(lock_op);
    }
}

/**
 * Helper method to garbage collect any unused Op objects.
 */
void
Transport::cleanupOps()
{
    // Limit the number of Op objects to garbage collect this round.
    uint count = 0;
    {
        SpinLock::Lock lock(unusedOps.mutex);
        count = unusedOps.queue.size();
    }

    for (uint i = 0; i < count; ++i) {
        Op* op = nullptr;
        {
            SpinLock::Lock lock(unusedOps.mutex);
            if (unusedOps.queue.empty()) {
                break;
            } else {
                op = unusedOps.queue.front();
                unusedOps.queue.pop_front();
            }
        }

        SpinLock::Lock lock(mutex);
        if (activeOps.count(op) == 0) {
            continue;
        }

        assert(op->destroy);

        sender->dropMessage(&op->outMessage);
        if (op->inMessage != nullptr) {
            receiver->dropMessage(op->inMessage);
        }

        op->mutex.lock();
        if (!op->isServerOp) {
            remoteOps.erase(op->opId);
        }
        activeOps.erase(op);
        opPool.destroy(op);
    }
}

}  // namespace Core
}  // namespace Homa
