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

#ifndef HOMA_CORE_SENDER_H
#define HOMA_CORE_SENDER_H

#include "Homa/Driver.h"

#include "Message.h"
#include "Protocol.h"
#include "SpinLock.h"

#include <atomic>
#include <deque>
#include <unordered_map>

namespace Homa {
namespace Core {

// Forward declaration
class OpContext;

/**
 * The Sender takes takes outgoing messages and sends out the message's packets
 * based on Homa's send policy and information (GRANTS) received from  the
 * Scheduler at the message's destination.
 */
class Sender {
  public:
    /**
     * Represents an outgoing message that is being sent.
     *
     * OutboundMessage objects are contained in the OpContext but should only
     * be accessed by the Sender.
     */
    class OutboundMessage : public Message {
      public:
        /**
         * Construct an OutboundMessage.
         *
         * @copydetails Core::Message::Message()
         */
        OutboundMessage(Protocol::MessageId msgId, Driver* driver,
                        uint16_t dataHeaderLength)
            : Message(msgId, driver, dataHeaderLength)
            , sending(false)
            , grantOffset(0)
            , grantIndex(-1)
            , sentIndex(-1)
        {}

        /// True if this message is being sent; false otherwise.
        bool sending;

      private:
        /// The offset up-to which we can send for this message.
        uint32_t grantOffset;
        /// The packet index that contains the grantOffset.
        int grantIndex;
        /// The packet index up to which all packets have been sent.
        int sentIndex;

        friend class Sender;
    };

    explicit Sender();
    ~Sender();

    void handleGrantPacket(Driver::Packet* packet, Driver* driver);
    void sendMessage(OpContext* op);
    void dropMessage(Protocol::MessageId msgId);
    void poll();

  private:
    /// Protects the top-level
    SpinLock sendMutex;

    /// Tracks the set of outbound messages.
    struct {
        /// Protects the outboundMessages structure.
        SpinLock mutex;

        /// Contains the associated OpContext for a given MessageId.
        std::unordered_map<Protocol::MessageId, OpContext*,
                           Protocol::MessageId::Hasher>
            message;

        /// Queue of message to be sent.
        std::deque<OpContext*> sendQueue;
    } outboundMessages;

    void trySend();
    void cleanup();
};

}  // namespace Core
}  // namespace Homa

#endif  // HOMA_CORE_SENDER_H