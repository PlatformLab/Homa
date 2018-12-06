/* Copyright (c) 2018, Stanford University
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

namespace Homa {
namespace Core {

// Forward declaration
class OpContext;

/**
 * The Sender takes takes outgoing messages and sends out the message's packets
 * based on Homa's send policy and information (GRANTS) received from  the
 * Scheduler at the message's desintation.
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
        OutboundMessage(Protocol::MessageId msgId, uint16_t dataHeaderLength,
                        Driver* driver)
            : Message(msgId, dataHeaderLength, driver)
            , sending()
            , mutex()
            , grantOffset(0)
            , grantIndex(-1)
            , sentIndex(-1)
        {
            sending.clear();
        }

        /// True if this message is being sent; false otherwise.
        std::atomic_flag sending;

      private:
        /// Ensure thread-safety for a multi-threaded Sender.
        SpinLock mutex;
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

    void handleGrantPacket(OpContext* op, Driver::Packet* packet,
                           Driver* driver);
    void sendMessage(OpContext* op);
    void poll();

  private:
    /// Protects the top-level
    SpinLock sendMutex;

    /// Protects the send queue.
    SpinLock queueMutex;

    /// Queue of packets to be sent.
    std::deque<OutboundMessage*> sendQueue;

    void trySend();
    void cleanup();
};

}  // namespace Core
}  // namespace Homa

#endif  // HOMA_CORE_SENDER_H