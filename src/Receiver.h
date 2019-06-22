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

#ifndef HOMA_CORE_RECEIVER_H
#define HOMA_CORE_RECEIVER_H

#include "Homa/Driver.h"

#include <atomic>
#include <deque>
#include <unordered_map>

#include "ControlPacket.h"
#include "InboundMessage.h"
#include "ObjectPool.h"
#include "Protocol.h"
#include "SpinLock.h"
#include "Transport.h"

namespace Homa {
namespace Core {

// Forward declaration

/**
 * The Receiver processes incomming Data packets, assembling them into messages
 * and return the message to higher-level software on request.
 *
 * This class is thread-safe.
 */
class Receiver {
  public:
    explicit Receiver(Transport* transport);
    virtual ~Receiver();
    virtual void handleDataPacket(Driver::Packet* packet, Driver* driver);
    virtual void handleBusyPacket(Driver::Packet* packet, Driver* driver);
    virtual void handlePingPacket(Driver::Packet* packet, Driver* driver);
    virtual InboundMessage* receiveMessage();
    virtual void dropMessage(InboundMessage* message);
    virtual void registerOp(Protocol::MessageId id, Transport::Op* op);
    virtual void dropOp(Transport::Op* op);
    virtual void poll();

    /**
     * Send a DONE packet to the Sender of an Op's incomming request.
     *
     * @param op
     *      Op whose incomming request should be acknowledged.
     * @param driver
     *      Driver with which the DONE packet should be sent.
     * @param lock_op
     *      Used to remind the caller to hold the op's mutex while calling
     *      this method.
     */
    static inline void sendDonePacket(Transport::Op* op, Driver* driver,
                                      const SpinLock::Lock& lock_op)
    {
        (void)lock_op;
        ControlPacket::send<Protocol::Packet::DoneHeader>(
            driver, op->inMessage->source, op->inMessage->getId());
    }

  private:
    void schedule();
    void sendGrantPacket(InboundMessage* message, Driver* driver,
                         const SpinLock::Lock& lock_message);

    /// Mutex for monitor-style locking of Receiver state.
    SpinLock mutex;

    /// Transport of which this Receiver is a part.
    Transport* transport;

    /// Tracks the set of Transport::Op objects with expected InboundMessages.
    std::unordered_map<Protocol::MessageId, Transport::Op*,
                       Protocol::MessageId::Hasher>
        registeredOps;

    /// Tracks the set of InboundMessage objects that do not have an associated
    /// Transport::Op.
    std::unordered_map<Protocol::MessageId, InboundMessage*,
                       Protocol::MessageId::Hasher>
        unregisteredMessages;

    /// Unregistered InboundMessage objects to be processed by the transport.
    std::deque<InboundMessage*> receivedMessages;

    /// Used to allocate additional Transport::Op objects when receiving a new
    /// unregistered Message.
    ObjectPool<InboundMessage> messagePool;

    /// True if the Receiver is executing schedule(); false, otherwise. Use to
    /// prevent concurrent calls to trySend() from blocking on eachother.
    std::atomic_flag scheduling = ATOMIC_FLAG_INIT;
};

}  // namespace Core
}  // namespace Homa

#endif  // HOMA_CORE_RECEIVER_H
