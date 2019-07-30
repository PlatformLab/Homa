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

#include "Intrusive.h"
#include "Message.h"
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
    /**
     * Represents an outgoing message that can be sent.
     *
     * Sender::Message objects are contained in the Transport::Op but should
     * only be accessed by the Sender.
     */
    class Message : public Core::Message {
      public:
        /**
         * Defines the possible states of this Sender::Message.
         */
        enum class State {
            NOT_STARTED,  //< This message has not yet been passed to Sender.
            IN_PROGRESS,  //< Sender is in the process of sending this message.
            SENT,         //< Sender has sent out every packet of the message.
            COMPLETED,    //< Receiver has acknowledged receipt of this message.
            FAILED,       //< Sender failed to send out this message.
        };

        /**
         * Construct an Message.
         */
        explicit Message(Driver* driver, void* op)
            : Core::Message(driver, sizeof(Protocol::Packet::DataHeader), 0)
            , mutex()
            , id(0, 0)
            , destination()
            , state(Message::State::NOT_STARTED)
            , grantIndex(0)
            , priority(0)
            , sentIndex(0)
            , unsentBytes(0)
            , op(op)
            , readyQueueNode(this)
            , messageTimeout(this)
            , pingTimeout(this)
        {}

        /**
         * Return the current state of this message.
         */
        State getState() const
        {
            return state.load();
        }

      private:
        /// Monitor style lock.
        mutable SpinLock mutex;
        /// Contains the unique identifier for this message.
        Protocol::MessageId id;
        /// Contains destination address this message.
        Driver::Address destination;
        /// This message's current state.
        std::atomic<State> state;
        /// Packets up to (but excluding) this index can be sent.
        uint16_t grantIndex;
        /// The network priority at which this Message should be sent.
        int priority;
        /// Packets up to (but excluding) this index have been sent.
        uint16_t sentIndex;
        /// The number of bytes that still need to be sent for this Message.
        uint32_t unsentBytes;
        /// Transport::Op associated with this message.
        void* const op;
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

    explicit Sender(Transport* transport, uint64_t transportId,
                    Policy::Manager* policyManager,
                    uint64_t messageTimeoutCycles, uint64_t pingIntervalCycles);
    virtual ~Sender();

    virtual void handleDonePacket(Driver::Packet* packet, Driver* driver);
    virtual void handleGrantPacket(Driver::Packet* packet, Driver* driver);
    virtual void handleResendPacket(Driver::Packet* packet, Driver* driver);
    virtual void handleUnknownPacket(Driver::Packet* packet, Driver* driver);
    virtual void handleErrorPacket(Driver::Packet* packet, Driver* driver);
    virtual void sendMessage(Sender::Message* message,
                             Driver::Address destination);
    virtual void dropMessage(Sender::Message* message);
    virtual void poll();

  private:
    void checkMessageTimeouts();
    void checkPingTimeouts();
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
};

}  // namespace Core
}  // namespace Homa

#endif  // HOMA_CORE_SENDER_H
