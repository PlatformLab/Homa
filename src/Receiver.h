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
#include "Intrusive.h"
#include "ObjectPool.h"
#include "Policy.h"
#include "Protocol.h"
#include "SpinLock.h"
#include "Timeout.h"
#include "Transport.h"

namespace Homa {
namespace Core {

// Forward declaration

/**
 * The Receiver processes incoming Data packets, assembling them into messages
 * and return the message to higher-level software on request.
 *
 * This class is thread-safe.
 */
class Receiver {
  public:
    explicit Receiver(Transport* transport, Policy::Manager* policyManager,
                      uint64_t messageTimeoutCycles,
                      uint64_t resendIntervalCycles);
    virtual ~Receiver();
    virtual void handleDataPacket(Driver::Packet* packet, Driver* driver);
    virtual void handleBusyPacket(Driver::Packet* packet, Driver* driver);
    virtual void handlePingPacket(Driver::Packet* packet, Driver* driver);
    virtual InboundMessage* receiveMessage();
    virtual void dropMessage(InboundMessage* message);
    virtual void poll();

    /**
     * Send a DONE packet to the Sender of an incoming request message.
     *
     * @param message
     *      Incoming request (message) that should be acknowledged.
     * @param driver
     *      Driver with which the DONE packet should be sent.
     */
    static inline void sendDonePacket(InboundMessage* message, Driver* driver)
    {
        SpinLock::Lock lock_message(message->mutex);
        ControlPacket::send<Protocol::Packet::DoneHeader>(
            driver, message->source, message->id);
    }

    /**
     * Send an ERROR packet to the Sender of an incoming request message.
     *
     * @param message
     *      Incoming request (message) that should be failed.
     * @param driver
     *      Driver with which the ERROR packet should be sent.
     */
    static inline void sendErrorPacket(InboundMessage* message, Driver* driver)
    {
        SpinLock::Lock lock_message(message->mutex);
        ControlPacket::send<Protocol::Packet::ErrorHeader>(
            driver, message->source, message->id);
    }

  private:
    void checkMessageTimeouts();
    void checkResendTimeouts();
    void schedule();

    /// Mutex for monitor-style locking of Receiver state.
    SpinLock mutex;

    /// Transport of which this Receiver is a part.
    Transport* transport;

    /// Provider of network packet priority and grant policy decisions.
    Policy::Manager* policyManager;

    /// Tracks the set of inbound messages being received by this Receiver.
    std::unordered_map<Protocol::MessageId, InboundMessage*,
                       Protocol::MessageId::Hasher>
        inboundMessages;

    /// List of inbound messages that require grants to complete.
    Intrusive::List<InboundMessage> scheduledMessages;

    /// InboundMessage objects to be processed by the transport.
    struct {
        /// Monitor style lock.
        SpinLock mutex;
        /// List of completely received messages.
        Intrusive::List<InboundMessage> queue;
    } receivedMessages;

    /// Used to allocate InboundMessage objects.
    ObjectPool<InboundMessage> messagePool;

    /// Maintains InboundMessage objects in increasing order of timeout.
    TimeoutManager<InboundMessage> messageTimeouts;

    /// Maintains InboundMessage object in increase order of resend timeout.
    TimeoutManager<InboundMessage> resendTimeouts;

    /// True if the Receiver is executing schedule(); false, otherwise. Use to
    /// prevent concurrent calls to trySend() from blocking on eachother.
    std::atomic_flag scheduling = ATOMIC_FLAG_INIT;
};

}  // namespace Core
}  // namespace Homa

#endif  // HOMA_CORE_RECEIVER_H
