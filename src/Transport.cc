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

#include "Protocol.h"
#include "Receiver.h"
#include "Sender.h"

namespace Homa {
namespace Core {

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

    if (isServerOp) {
        if (copyOfState == State::NOT_STARTED) {
            if (inMessage->isReady()) {
                SpinLock::Lock lock_queue(transport->pendingServerOps.mutex);
                transport->pendingServerOps.queue.push_back(this);
                state.store(State::IN_PROGRESS);
            }
        } else if (copyOfState == State::IN_PROGRESS) {
            if (outMessage.isDone()) {
                state.store(State::COMPLETED);
                hintUpdate();
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
            if (inMessage->isReady()) {
                state.store(State::COMPLETED);
                hintUpdate();
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
    , sender(new Sender())
    , scheduler(new Scheduler(driver))
    , receiver(new Receiver(scheduler.get()))
    , mutex()
    , opPool()
    , activeOps()
    , updateHints()
    , unusedOps()
    , pendingServerOps()
{}

/**
 * Transport Destructor.
 */
Transport::~Transport() = default;

/**
 * Return a new OpContext which can be used to hold a client's RemoteOp.
 */
OpContext*
Transport::allocOp()
{
    SpinLock::UniqueLock lock(mutex);
    Op* op = opPool.construct(this, driver, false);
    activeOps.insert(op);

    // Lock handoff
    SpinLock::Lock lock_op(op->mutex);
    lock.unlock();

    op->outMessage.get()->defineHeader<Protocol::Message::Header>();
    op->retained.store(true);
    return op;
}

/**
 * Return an OpContext for an incomming request (ServerOp) if one exists.
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
        op->outMessage.get()->defineHeader<Protocol::Message::Header>();
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
    op->hintUpdate();
}

/**
 * Signal that the outbound Message should be sent as a request.
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
    SpinLock::UniqueLock lock_op(op->mutex);
    if (op->isServerOp) {
        Protocol::MessageId requestId(op->inMessage->getId());
        Protocol::MessageId delegationId(Protocol::OpId(requestId),
                                         requestId.tag + 1);
        lock_op.unlock();  // Allow Sender to take the lock.
        sender->sendMessage(delegationId, destination, op, true);
    } else {
        Protocol::OpId opId(transportId, nextOpSequenceNumber++);
        op->state.store(OpContext::State::IN_PROGRESS);
        lock_op.unlock();  // Allow Sender/Receiver to take the lock.
        receiver->registerOp({opId, Protocol::MessageId::ULTIMATE_RESPONSE_TAG},
                             op);
        sender->sendMessage({opId, Protocol::MessageId::INITIAL_REQUEST_TAG},
                            destination, op);
    }
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
    SpinLock::UniqueLock lock_op(op->mutex);
    assert(op->isServerOp);
    Protocol::OpId opId(op->inMessage->getId());
    Driver::Address* replyAddress =
        driver->getAddress(&op->inMessage->get()
                                ->getHeader<Protocol::Message::Header>()
                                ->replyAddress);
    op->state.store(OpContext::State::IN_PROGRESS);
    lock_op.unlock();  // Allow Sender to take the lock.
    sender->sendMessage({opId, Protocol::MessageId::ULTIMATE_RESPONSE_TAG},
                        replyAddress, op);
}

/// See Homa::Transport::poll()
void
Transport::poll()
{
    // Receive and dispatch incomming packets.
    processPackets();

    // Allow sender and receiver to make incremental progress.
    sender->poll();
    receiver->poll();

    processInboundMessages();
    checkForUpdates();
    cleanupOps();
}

/**
 * Helper method which receives a burst of incomming packets and process them
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
        }
    }
}

/**
 * Helper method to process any incomming messages.
 */
void
Transport::processInboundMessages()
{
    for (InboundMessage* message = receiver->receiveMessage();
         message != nullptr; message = receiver->receiveMessage()) {
        Protocol::MessageId id = message->getId();
        if (id.tag == Protocol::MessageId::ULTIMATE_RESPONSE_TAG) {
            // The response message is not registered so there is no RemoteOp
            // waiting for it;  Drop the message.
            receiver->dropMessage(message);
        } else {
            // Incomming message is a request.
            Op* op = nullptr;
            {
                SpinLock::Lock lock(mutex);
                op = opPool.construct(this, driver, true);
                activeOps.insert(op);
            }
            receiver->registerOp(id, op);
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
        Op* op = nullptr;
        // Take a hint.
        {
            SpinLock::Lock lock(updateHints.mutex);
            if (updateHints.order.empty()) {
                break;
            } else {
                op = updateHints.order.front();
                updateHints.order.pop_front();
                updateHints.ops.erase(op);
            }
        }
        // Check that the hinted Op is still active.
        SpinLock::UniqueLock lock(mutex);
        if (activeOps.count(op) == 0) {
            continue;
        }

        // Lock handoff
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
        op->mutex.lock();
        assert(op->destroy);
        activeOps.erase(op);
        opPool.destroy(op);
    }
}

}  // namespace Core
}  // namespace Homa
