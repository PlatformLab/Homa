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
#include <mutex>
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
     * Represents an outgoing message that can be sent.
     *
     * OutboundMessage objects are contained in the OpContext but should only
     * be accessed by the Sender.
     */
    class OutboundMessage {
      public:
        /**
         * Construct an OutboundMessage.
         */
        explicit OutboundMessage(Driver* driver)
            : mutex()
            , id(0, 0, 0)
            , destination(nullptr)
            , message(driver, sizeof(Protocol::Packet::DataHeader), 0)
            , grantOffset(0)
            , grantIndex(-1)
            , sentIndex(-1)
            , sent(false)
        {}

        /**
         * Return a pointer to a Message object that can be populated by
         * applications of the Transport.  Caller should take care not
         * to provide access to the returned Message while the Sender is
         * processing the Message.
         */
        Message* get()
        {
            std::lock_guard<SpinLock> lock(mutex);
            return &message;
        }

      private:
        /// Monitor style lock.
        SpinLock mutex;
        /// Contains the unique identifier for this message.
        Protocol::MessageId id;
        /// Contains destination address this message.
        Driver::Address* destination;
        /// Collection of packets to be sent.
        Message message;
        /// The offset up-to which we can send for this message.
        uint32_t grantOffset;
        /// The packet index that contains the grantOffset.
        int grantIndex;
        /// The packet index up to which all packets have been sent.
        int sentIndex;
        /// True if this message has been fully sent; false otherwise.
        bool sent;

        friend class Sender;
    };

    explicit Sender();
    virtual ~Sender();

    virtual void handleGrantPacket(Driver::Packet* packet, Driver* driver);
    virtual void sendMessage(Protocol::MessageId id,
                             Driver::Address* destination, OpContext* op);
    virtual void dropMessage(OpContext* op);
    virtual void poll();

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
    } outboundMessages;

    void trySend();
};

}  // namespace Core
}  // namespace Homa

#endif  // HOMA_CORE_SENDER_H
