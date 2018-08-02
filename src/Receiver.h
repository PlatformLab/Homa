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

#ifndef HOMA_CORE_RECEIVER_H
#define HOMA_CORE_RECEIVER_H

#include "Driver.h"
#include "MessageContext.h"
#include "Protocol.h"
#include "Scheduler.h"
#include "SpinLock.h"

#include <deque>
#include <unordered_map>

namespace Homa {
namespace Core {

/**
 * The Receiver processes incomming Data packets, assembling them into messages
 * and return the message to higher-level software on request.
 *
 * This class is thread-safe.
 */
class Receiver {
  public:
    explicit Receiver(Scheduler* scheduler, MessagePool* messagePool);
    ~Receiver();
    void handleDataPacket(Driver::Packet* packet, Driver* driver);
    MessageContext* receiveMessage();
    void poll();

  private:
    /// Scheudler that should be informed when message packets are received.
    Scheduler* scheduler;

    /// Protects access main receive strucures: _messages_ and _messagePool_.
    /// The _messageQueue_ is protected by a seperate mutex to avoid deadlock.
    SpinLock receiveMutex;

    /**
     * Represents an incoming message that is being assembled or being processed
     * by the application.
     */
    struct InboundMessage {
        /// Ensure thread-safety between a multi-threaded Receiever.
        SpinLock mutex;
        /// Contains the metadata and maintains access to message data packets.
        MessageContext* context;
        /// True if all packets of the message have been recevied.
        bool fullMessageReceived;

        explicit InboundMessage(MessageContext* context)
            : mutex()
            , context(context)
            , fullMessageReceived(false)
        {}
    };

    /**
     * Collection of all current incoming messages.
     */
    std::unordered_map<Protocol::MessageId, InboundMessage*,
                       Protocol::MessageId::Hasher>
        messageMap;

    /// Pool from which InboundMessage objects can be allocated.
    ObjectPool<InboundMessage> inboundPool;

    /// Pool from which MessageContext objects can be allocated.
    MessagePool* contextPool;

    /// Protects access to the messageQueue;
    SpinLock queueMutex;

    /// Contains fully received messages waiting to be delivered to applications
    /// when receiveMessage() is called.
    std::deque<MessageContext*> messageQueue;
};

}  // namespace Core
}  // namespace Homa

#endif  // HOMA_CORE_RECEIVER_H