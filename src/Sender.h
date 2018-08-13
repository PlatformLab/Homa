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

#include "MessageContext.h"
#include "Protocol.h"
#include "SpinLock.h"

#include <deque>
#include <unordered_map>

namespace Homa {
namespace Core {

/**
 * The Sender takes takes outgoing messages and sends out the message's packets
 * based on Homa's send policy and information (GRANTS) received from  the
 * Scheduler at the message's desintation.
 */
class Sender {
  public:
    explicit Sender();
    ~Sender();

    void handleGrantPacket(Driver::Packet* packet, Driver* driver);
    void sendMessage(MessageContext* context);
    void poll();

  private:
    /// Protects the top-level
    SpinLock sendMutex;

    /**
     * Represents an outgoing message that is being sent.
     */
    struct OutboundMessage {
        /// Ensure thread-safety for a multi-threaded Sender.
        SpinLock mutex;
        /// Contains the metadata and maintains access to message data packets.
        MessageContext* const context;
        /// The offset up-to which we can send for this message.
        uint32_t grantOffset;
        /// The packet index that contains the grantOffset.
        int grantIndex;
        /// The packet index up to which all packets have been sent.
        int sentIndex;

        explicit OutboundMessage(MessageContext* context)
            : mutex()
            , context(context)
            , grantOffset(0)
            , grantIndex(-1)
            , sentIndex(-1)
        {}
    };

    /**
     * Collection of all current outgoing messages.
     */
    std::unordered_map<Protocol::MessageId, OutboundMessage*,
                       Protocol::MessageId::Hasher>
        messageMap;

    /// Pool from which OutboundMessage objects can be allocated.
    ObjectPool<OutboundMessage> outboundPool;

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