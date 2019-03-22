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

#include "Protocol.h"

#include <algorithm>
#include <memory>
#include <mutex>
#include <utility>

namespace Homa {
namespace Core {

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
    , opContextPool()
    , serverOpQueue()
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
    OpContext* op = nullptr;
    {
        std::lock_guard<SpinLock> lock(mutex);
        op = opContextPool.construct(this, driver, false);
    }
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
    OpContext* op = nullptr;
    {
        std::lock_guard<SpinLock> lock(mutex);
        if (!serverOpQueue.empty()) {
            op = serverOpQueue.front();
            serverOpQueue.pop_front();
        }
    }
    if (op != nullptr) {
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
 * @param op
 *      OpContext which is no longer needed.
 *
 * @sa Homa::Core::Transport; no support for concurrent calls to same OpContext.
 */
void
Transport::releaseOp(OpContext* op)
{
    op->retained.store(false);
    // TODO(cstlee): Hook into GC mechanism.
}

/**
 * Signal that the outbound Message should be sent as a request.
 *
 * @param op
 *      OpContext that contains the request Message to be sent.
 * @param destination
 *      Network address to which the request should be sent.

 * @sa Homa::Core::Transport; no support for concurrent calls to same OpContext.
 */
void
Transport::sendRequest(OpContext* op, Driver::Address* destination)
{
    // Transport::mutex not needed
    if (op->isServerOp) {
        Protocol::MessageId requestId(op->inMessage.load()->getId());
        Protocol::MessageId delegationId(Protocol::OpId(requestId),
                                         requestId.tag + 1);
        sender->sendMessage(delegationId, destination, op);
    } else {
        Protocol::OpId opId(transportId, nextOpSequenceNumber++);
        op->state.store(OpContext::State::IN_PROGRESS);
        receiver->registerOp({opId, Protocol::MessageId::ULTIMATE_RESPONSE_TAG},
                             op);
        sender->sendMessage({opId, Protocol::MessageId::INITIAL_REQUEST_TAG},
                            destination, op);
    }
}

/**
 * Signal that the outbound Message should be sent as a reply.
 *
 * @param op
 *      OpContext that contains the reply Message to be sent.
 *
 * @sa Homa::Core::Transport; no support for concurrent calls to same OpContext.
 */
void
Transport::sendReply(OpContext* op)
{
    assert(op->isServerOp);
    Protocol::OpId opId(op->inMessage.load()->getId());
    Driver::Address* replyAddress =
        driver->getAddress(&op->inMessage.load()
                                ->get()
                                ->getHeader<Protocol::Message::Header>()
                                ->replyAddress);
    op->state.store(OpContext::State::IN_PROGRESS);
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

    // Process any incomming Messages
    processInboundMessages();
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
        OpContext* op = nullptr;
        switch (header->opcode) {
            case Protocol::Packet::DATA:
                op = receiver->handleDataPacket(packet, driver);
                processReceivedMessage(op);
                break;
            case Protocol::Packet::GRANT:
                sender->handleGrantPacket(packet, driver);
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
    for (Receiver::InboundMessage* message = receiver->receiveMessage();
         message != nullptr; message = receiver->receiveMessage()) {
        Protocol::MessageId id = message->getId();
        if (id.tag == Protocol::MessageId::ULTIMATE_RESPONSE_TAG) {
            // The response message is not registered so there is no RemoteOp
            // waiting for it;  Drop the message.
            receiver->dropMessage(message);
        } else {
            // Incomming message is a request.
            OpContext* op = nullptr;
            {
                std::lock_guard<SpinLock> lock(mutex);
                op = opContextPool.construct(this, driver, true);
            }
            receiver->registerOp(id, op);
        }
    }
}

/**
 * Helper method to process an OpContext with an InboundMessage that has been
 * fully received.
 *
 * @param op
 *      OpContext with a fully received InboundMessage.
 */
void
Transport::processReceivedMessage(OpContext* op)
{
    if (op != nullptr) {
        assert(op->inMessage.load()->isReady());
        if (op->isServerOp) {
            std::lock_guard<SpinLock> lock(mutex);
            serverOpQueue.push_back(op);
        } else {
            op->state.store(OpContext::State::COMPLETED);
        }
    }
}

}  // namespace Core
}  // namespace Homa
