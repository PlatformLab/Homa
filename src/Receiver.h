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

#include "Message.h"
#include "ObjectPool.h"
#include "Protocol.h"
#include "Scheduler.h"
#include "SpinLock.h"
#include "Tub.h"

#include <deque>
#include <mutex>
#include <unordered_map>

namespace Homa {
namespace Core {

// Forward declaration
class OpContext;

/**
 * The Receiver processes incomming Data packets, assembling them into messages
 * and return the message to higher-level software on request.
 *
 * This class is thread-safe.
 */
class Receiver {
  public:
    /**
     * Represents an incoming message that is being assembled or being processed
     * by the application.
     *
     * InboundMessage objects are contained in the OpContext but should only be
     * accessed by the Receiver.
     */
    class InboundMessage {
      public:
        InboundMessage()
            // : Message(driver, dataHeaderLength, messageLength)
            : mutex()
            , id(0, 0, 0)
            , source(nullptr)
            , message()
            , fullMessageReceived(false)
        {}

        /**
         * Return a pointer to a Message object that can be read by applications
         * of the Transport.  Otherwise, nullptr will be returned when no
         * Message is available.
         */
        Message* get()
        {
            std::lock_guard<SpinLock> lock(mutex);
            return message.get();
        }

        /**
         * Return the unique identifier for this Message.
         */
        Protocol::MessageId getId()
        {
            return id;
        }

        /**
         * Return true if the InboundMessage has been received; false otherwise.
         */
        bool isReady() const
        {
            std::lock_guard<SpinLock> lock(mutex);
            return fullMessageReceived;
        }

      private:
        /// Monitor style lock.
        mutable SpinLock mutex;
        /// Contains the unique identifier for this message.
        Protocol::MessageId id;
        /// Contains source address this message.
        Driver::Address* source;
        /// Collection of packets being received.
        Tub<Message> message;
        /// True if all packets of the message have been received.
        bool fullMessageReceived;

        friend class Receiver;
    };

    explicit Receiver(Scheduler* scheduler);
    virtual ~Receiver();
    virtual OpContext* handleDataPacket(Driver::Packet* packet, Driver* driver);
    virtual InboundMessage* receiveMessage();
    virtual void dropMessage(InboundMessage* message);
    virtual void registerOp(Protocol::MessageId id, OpContext* op);
    virtual void dropOp(OpContext* op);
    virtual void poll();

  private:
    /// Mutext for monitor-style locking of Receiver state.
    SpinLock mutex;

    /// Scheduler that should be informed when message packets are received.
    Scheduler* const scheduler;

    /// Tracks the set of OpContext objects with expected InboundMessages.
    std::unordered_map<Protocol::MessageId, OpContext*,
                       Protocol::MessageId::Hasher>
        registeredOps;

    /// Tracks the set of InboundMessage objects that do not have an associated
    /// OpContext.
    std::unordered_map<Protocol::MessageId, InboundMessage*,
                       Protocol::MessageId::Hasher>
        unregisteredMessages;

    /// Unregistered InboundMessage objects to be processed by the transport.
    std::deque<InboundMessage*> receivedMessages;

    /// Used to allocate additional OpContext objects when receiving a new
    /// unregistered Message.
    ObjectPool<InboundMessage> messagePool;
};

}  // namespace Core
}  // namespace Homa

#endif  // HOMA_CORE_RECEIVER_H