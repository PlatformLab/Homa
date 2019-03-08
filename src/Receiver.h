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
#include "Protocol.h"
#include "Scheduler.h"
#include "SpinLock.h"

#include <deque>
#include <mutex>
#include <unordered_map>

namespace Homa {
namespace Core {

// Forward declaration
class OpContext;
class OpContextPool;

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
    class InboundMessage : public Message {
      public:
        InboundMessage(Protocol::MessageId msgId, Driver* driver,
                       uint16_t dataHeaderLength, uint32_t messageLength)
            : Message(msgId, driver, dataHeaderLength, messageLength)
            , fullMessageReceived(false)
        {}

        /**
         * Return true if the InboundMessage has been received; false otherwise.
         *
         * @param opLock
         *      Remind the caller that the OpContext mutex should be held.
         */
        bool isReady(std::lock_guard<SpinLock>& opLock)
        {
            (void)opLock;
            return fullMessageReceived;
        }

      private:
        /// True if all packets of the message have been received.
        bool fullMessageReceived;

        friend class Receiver;
    };

    explicit Receiver(Scheduler* scheduler, OpContextPool* opPool);
    ~Receiver();
    void handleDataPacket(Driver::Packet* packet, Driver* driver);
    OpContext* receiveMessage();
    void registerMessage(Protocol::MessageId msgId, OpContext* op);
    void dropMessage(OpContext* op);
    void poll();

  private:
    /// Scheduler that should be informed when message packets are received.
    Scheduler* const scheduler;

    /// Used to allocate additional OpContext objects when receiving a new
    /// unregistered Message.
    OpContextPool* const opPool;

    /// Tracks the set of incomming messages.
    struct {
        /// Protects the inboundMessages structure.
        SpinLock mutex;

        /// Contains the associated OpContext for a given MessageId.
        std::unordered_map<Protocol::MessageId, OpContext*,
                           Protocol::MessageId::Hasher>
            message;
    } inboundMessages;

    /// Messages that have been received but not yet requested by the transport.
    struct {
        /// Protects the receivedMessages structure.
        SpinLock mutex;

        /// Collection of received messages.
        std::deque<OpContext*> queue;
    } receivedMessages;
};

}  // namespace Core
}  // namespace Homa

#endif  // HOMA_CORE_RECEIVER_H