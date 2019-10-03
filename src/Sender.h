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

#include <atomic>
#include <unordered_map>

#include <Homa/Driver.h>
#include <Homa/Homa.h>

#include "Intrusive.h"
#include "Message.h"
#include "ObjectPool.h"
#include "Policy.h"
#include "Protocol.h"
#include "SpinLock.h"
#include "Timeout.h"

namespace Homa {
namespace Core {
// Forward Declaration
class Transport;

/**
 * The Sender takes takes outgoing messages and sends out the message's packets
 * based on Homa's send policy and information (GRANTS) received from  the
 * Scheduler at the message's destination.
 *
 * This class is thread-safe.
 */
class Sender {
  public:
    explicit Sender(Transport* transport, uint64_t transportId,
                    Policy::Manager* policyManager,
                    uint64_t messageTimeoutCycles, uint64_t pingIntervalCycles);
    virtual ~Sender();

    virtual Homa::OutMessage* allocMessage();
    virtual void handleDonePacket(Driver::Packet* packet, Driver* driver);
    virtual void handleGrantPacket(Driver::Packet* packet, Driver* driver);
    virtual void handleResendPacket(Driver::Packet* packet, Driver* driver);
    virtual void handleUnknownPacket(Driver::Packet* packet, Driver* driver);
    virtual void handleErrorPacket(Driver::Packet* packet, Driver* driver);
    virtual void poll();
    virtual uint64_t checkTimeouts();

  private:
    /**
     * Represents an outgoing message that can be sent.
     *
     * Sender::Message objects are contained in the Transport::Op but should
     * only be accessed by the Sender.
     */
    class Message : public Homa::OutMessage, public Core::Message {
      public:
        /**
         * Construct an Message.
         */
        explicit Message(Sender* sender, Driver* driver)
            : Core::Message(driver, sizeof(Protocol::Packet::DataHeader), 0)
            , mutex()
            , sender(sender)
            , id(0, 0)
            , destination()
            , state(Status::NOT_STARTED)
            , grantIndex(0)
            , priority(0)
            , sentIndex(0)
            , unsentBytes(0)
            , readyQueueNode(this)
            , messageTimeout(this)
            , pingTimeout(this)
        {}

        /// See Homa::OutMessage::send()
        virtual void send(Driver::Address destination)
        {
            sender->sendMessage(this, destination);
        }

        /// See Homa::OutMessage::cancel()
        virtual void cancel()
        {
            sender->cancelMessage(this);
        }

        /// See Homa::OutMessage::getStatus()
        virtual Status getStatus() const
        {
            return state.load();
        }

        /// See Homa::OutMessage::release()
        virtual void release()
        {
            sender->dropMessage(this);
        }

      private:
        /// Monitor style lock.
        mutable SpinLock mutex;
        /// The Sender responsible for sending this message.
        Sender* const sender;
        /// Contains the unique identifier for this message.
        Protocol::MessageId id;
        /// Contains destination address this message.
        Driver::Address destination;
        /// This message's current state.
        std::atomic<Status> state;
        /// Packets up to (but excluding) this index can be sent.
        uint16_t grantIndex;
        /// The network priority at which this Message should be sent.
        int priority;
        /// Packets up to (but excluding) this index have been sent.
        uint16_t sentIndex;
        /// The number of bytes that still need to be sent for this Message.
        uint32_t unsentBytes;
        /// Intrusive structure used by the Sender to keep track of this message
        /// when it has packets to send.
        Intrusive::List<Message>::Node readyQueueNode;
        /// Intrusive structure used by the Sender to keep track when the
        /// sending of this message should be considered failed.
        Timeout<Message> messageTimeout;
        /// Intrusive structure used by the Sender to keep track when this
        /// message should be checked to ensure progress is still being made.
        Timeout<Message> pingTimeout;

        friend class Sender;
    };

    void sendMessage(Sender::Message* message, Driver::Address destination);
    void cancelMessage(Sender::Message* message);
    void dropMessage(Sender::Message* message);
    uint64_t checkMessageTimeouts();
    uint64_t checkPingTimeouts();
    void trySend();
    void hintMessageReady(Message* message, const SpinLock::UniqueLock& lock,
                          const SpinLock::Lock& lock_message);

    /// Protects the top-level
    SpinLock mutex;

    /// Transport of which this Sender is a part.
    Transport* transport;

    /// Transport identifier.
    const uint64_t transportId;

    /// Provider of network packet priority decisions.
    Policy::Manager* policyManager;

    /// The sequence number to be used for the next Message.
    uint64_t nextMessageSequenceNumber;

    /// The maximum number of bytes that should be queued in the Driver.
    const uint32_t DRIVER_QUEUED_BYTE_LIMIT;

    /// Tracks the set of outbound messages being sent by the Sender.
    std::unordered_map<Protocol::MessageId, Message*,
                       Protocol::MessageId::Hasher>
        outboundMessages;

    /// A list of outbound messages that have packets that can be sent.
    /// Messages are kept in order of priority.
    Intrusive::List<Message> readyQueue;

    /// Maintains Message objects in increasing order of timeout.
    TimeoutManager<Message> messageTimeouts;

    /// Maintains Message object in increase order of ping timeout.
    TimeoutManager<Message> pingTimeouts;

    /// True if the Sender is currently executing trySend(); false, otherwise.
    /// Use to prevent concurrent trySend() calls from blocking on each other.
    std::atomic_flag sending = ATOMIC_FLAG_INIT;

    /// Hint whether there are messages ready to be sent (i.e. the readyQueue is
    /// not empty). Encoded into a single bool to make checking if there is work
    /// to do more efficient.
    std::atomic<bool> sendReady;

    /// Used to allocate Message objects.
    struct MessageAllocator {
        /// Default constructor.
        MessageAllocator()
            : mutex()
            , pool()
        {}
        /// Allocator monitor lock.
        SpinLock mutex;
        /// Pool allocator for Message objects.
        ObjectPool<Message> pool;
    } messageAllocator;
};

}  // namespace Core
}  // namespace Homa

#endif  // HOMA_CORE_SENDER_H
