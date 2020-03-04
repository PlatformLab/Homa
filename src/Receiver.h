/* Copyright (c) 2018-2020, Stanford University
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

#include <Homa/Driver.h>

#include <atomic>
#include <deque>
#include <unordered_map>

#include "ControlPacket.h"
#include "Intrusive.h"
#include "Message.h"
#include "ObjectPool.h"
#include "Policy.h"
#include "Protocol.h"
#include "SpinLock.h"
#include "Timeout.h"

namespace Homa {
namespace Core {

/**
 * The Receiver processes incoming Data packets, assembling them into messages
 * and return the message to higher-level software on request.
 *
 * This class is thread-safe.
 */
class Receiver {
  public:
    explicit Receiver(Driver* driver, Policy::Manager* policyManager,
                      uint64_t messageTimeoutCycles,
                      uint64_t resendIntervalCycles);
    virtual ~Receiver();
    virtual void handleDataPacket(Driver::Packet* packet, Driver* driver);
    virtual void handleBusyPacket(Driver::Packet* packet, Driver* driver);
    virtual void handlePingPacket(Driver::Packet* packet, Driver* driver);
    virtual Homa::InMessage* receiveMessage();
    virtual void poll();
    virtual uint64_t checkTimeouts();

  private:
    // Forward declaration
    class Message;
    struct Peer;

    /**
     * Contains metadata for a Message that requires additional GRANTs.
     */
    struct ScheduledMessageInfo {
        /**
         * Implements a binary comparison function for the strict weak priority
         * ordering of two Message objects.
         */
        struct ComparePriority {
            bool operator()(const Message& a, const Message& b)
            {
                return a.scheduledMessageInfo.bytesRemaining <
                       b.scheduledMessageInfo.bytesRemaining;
            }
        };

        /**
         * ScheduledMessageInfo constructor.
         *
         * @param message
         *      Message to which this metadata is associated.
         * @param length
         *      Number of bytes the associated message is expected to contain.
         */
        explicit ScheduledMessageInfo(Message* message, int length)
            : messageLength(length)
            , bytesRemaining(length)
            , bytesGranted(0)
            , priority(0)
            , peer(nullptr)
            , scheduledMessageNode(message)
        {}

        /// The number of bytes this Message is expected to contain.
        const int messageLength;

        /// The number of bytes that still needs to be received for this
        /// Message.
        int bytesRemaining;

        /// The cumulative number of bytes that have granted for this Message.
        int bytesGranted;

        /// The network priority at which the Receiver requests Message be sent.
        int priority;

        /// Peer object that holds this message.  If peer is non-null, the
        /// message is scheduled and more GRANTs may be needed.
        Peer* peer;

        /// Intrusive structure used by the Receiver to keep track of when this
        /// message should be issued grants.
        Intrusive::List<Message>::Node scheduledMessageNode;
    };

    /**
     * Represents an incoming message that is being assembled or being processed
     * by the application.
     */
    class Message : public Homa::InMessage, public Core::Message {
      public:
        /**
         * Defines the possible states of this Message.
         */
        enum class State {
            IN_PROGRESS,  //< Receiver is in the process of receiving this
                          // message.
            COMPLETED,    //< Receiver has received the entire message.
            DROPPED,      //< Message was COMPLETED but the Receiver has lost
                          //< communication with the Sender.
        };

        explicit Message(Receiver* receiver, Driver* driver,
                         uint16_t packetHeaderLength, uint32_t messageLength,
                         Protocol::MessageId id, Driver::Address source,
                         int numUnscheduledPackets)
            : Core::Message(driver, packetHeaderLength, messageLength)
            , receiver(receiver)
            , id(id)
            , source(source)
            , numExpectedPackets((messageLength + PACKET_DATA_LENGTH - 1) /
                                 PACKET_DATA_LENGTH)
            , numUnscheduledPackets(numUnscheduledPackets)
            , scheduled(numExpectedPackets > numUnscheduledPackets)
            , state(Message::State::IN_PROGRESS)
            , bucketNode(this)
            , receivedMessageNode(this)
            , messageTimeout(this)
            , resendTimeout(this)
            , scheduledMessageInfo(this, messageLength)
        {}

        /// See Homa::InMessage::acknowledge()
        virtual void acknowledge() const
        {
            MessageBucket* bucket = receiver->messageBuckets.getBucket(id);
            SpinLock::Lock lock(bucket->mutex);
            ControlPacket::send<Protocol::Packet::DoneHeader>(driver, source,
                                                              id);
        }

        /// See Homa::InMessage::fail()
        virtual void fail() const
        {
            MessageBucket* bucket = receiver->messageBuckets.getBucket(id);
            SpinLock::Lock lock(bucket->mutex);
            ControlPacket::send<Protocol::Packet::ErrorHeader>(driver, source,
                                                               id);
        }

        /// See Homa::InMessage::dropped()
        virtual bool dropped() const
        {
            return state.load() == State::DROPPED;
        }

        /// See Homa::InMessage::release()
        virtual void release()
        {
            receiver->dropMessage(this);
        }

        /**
         * Return the current state of this message.
         */
        State getState() const
        {
            return state.load();
        }

      private:
        /// The Receiver responsible for this message.
        Receiver* const receiver;

        /// Contains the unique identifier for this message.
        const Protocol::MessageId id;

        /// Contains source address this message.
        const Driver::Address source;

        /// Number of packets the message is expected to contain.
        const int numExpectedPackets;

        /// Number of packets that will be sent without GRANTs.
        const int numUnscheduledPackets;

        /// True if the Message exceeds the unscheduled byte limit and requires
        /// GRANTs to be sent.
        const bool scheduled;

        /// This message's current state.
        std::atomic<State> state;

        /// Intrusive structure used by the Receiver to hold on to this Message
        /// in one of the Receiver's MessageBuckets.  Access to this structure
        /// is protected by the associated MessageBucket::mutex;
        Intrusive::List<Message>::Node bucketNode;

        /// Intrusive structure used by the Receiver to keep track of this
        /// message when it has been completely received.
        Intrusive::List<Message>::Node receivedMessageNode;

        /// Intrusive structure used by the Receiver to keep track when the
        /// receiving of this message should be considered failed.
        Timeout<Message> messageTimeout;

        /// Intrusive structure used by the Receiver to keep track when
        /// unreceived parts of this message should be re-requested.
        Timeout<Message> resendTimeout;

        /// Intrusive structure used by the Receiver to keep track of this
        /// Message if the Message still requires more GRANTs to be sent.
        /// Access to this structure is protected by Receiver::schedulerMutex.
        ScheduledMessageInfo scheduledMessageInfo;

        friend class Receiver;
    };

    /**
     * A collection of incoming Message objects and their associated timeouts.
     *
     * Messages are split into multiple buckets to support fine-grain
     * synchronization when searching for and accessing Message objects.
     */
    struct MessageBucket {
        /**
         * MessageBucket constructor.
         *
         * @param messageTimeoutCycles
         *      Number of cycles of inactivity to wait before a Message is
         *      considered failed.
         * @param resendIntervalCycles
         *      Number of cycles of inactivity to wait between requesting
         *      retransmission of un-received parts of a Message.
         *      liveness of a Message.
         */
        explicit MessageBucket(uint64_t messageTimeoutCycles,
                               uint64_t resendIntervalCycles)
            : mutex()
            , messages()
            , messageTimeouts(messageTimeoutCycles)
            , resendTimeouts(resendIntervalCycles)
        {}

        /**
         * Return the Message with the given MessageId.
         *
         * @param msgId
         *      MessageId of the Message to be found.
         * @param lock
         *      Reminder to hold the MessageBucket::mutex during this call. (Not
         *      used)
         * @return
         *      A pointer to the Message if found; nullptr, otherwise.
         */
        Message* findMessage(const Protocol::MessageId& msgId,
                             const SpinLock::Lock& lock)
        {
            (void)lock;
            Message* message = nullptr;
            for (auto it = messages.begin(); it != messages.end(); ++it) {
                if (it->id == msgId) {
                    message = &(*it);
                    break;
                }
            }
            return message;
        }

        /// Mutex protecting the contents of this bucket.
        SpinLock mutex;

        /// Collection of inbound messages
        Intrusive::List<Message> messages;

        /// Maintains Message objects in increasing order of timeout.
        TimeoutManager<Message> messageTimeouts;

        /// Maintains Message object in increase order of resend timeout.
        TimeoutManager<Message> resendTimeouts;
    };

    /**
     * Maps from a message's MessageId to the MessageBucket which should hold
     * the message (if it exists).
     */
    struct MessageBucketMap {
        /**
         * The number of buckets in a MessageBuckets in this map.  This must be
         * a power of 2.
         */
        static const int NUM_BUCKETS = 256;

        /**
         * Bit mask used to map from a hashed key to the bucket index.
         */
        static const uint HASH_KEY_MASK = 0xFF;

        // Make sure bit mask correctly matches the number of buckets.
        static_assert(NUM_BUCKETS == HASH_KEY_MASK + 1);

        /**
         * Helper method to create the set of buckets.
         *
         * @param messageTimeoutCycles
         *      Number of cycles of inactivity to wait before a Message is
         *      considered failed.
         * @param resendIntervalCycles
         *      Number of cycles of inactivity to wait between requesting
         *      retransmission of un-received parts of a Message.
         *      liveness of a Message.
         */
        static std::array<MessageBucket*, NUM_BUCKETS> makeBuckets(
            uint64_t messageTimeoutCycles, uint64_t resendIntervalCycles)
        {
            std::array<MessageBucket*, NUM_BUCKETS> buckets;
            for (int i = 0; i < NUM_BUCKETS; ++i) {
                buckets[i] = new MessageBucket(messageTimeoutCycles,
                                               resendIntervalCycles);
            }
            return buckets;
        }

        /**
         * MessageBucketMap constructor.
         *
         * @param messageTimeoutCycles
         *      Number of cycles of inactivity to wait before a Message is
         *      considered failed.
         * @param resendIntervalCycles
         *      Number of cycles of inactivity to wait between requesting
         *      retransmission of un-received parts of a Message.
         *      liveness of a Message.
         */
        explicit MessageBucketMap(uint64_t messageTimeoutCycles,
                                  uint64_t resendIntervalCycles)
            : buckets(makeBuckets(messageTimeoutCycles, resendIntervalCycles))
            , hasher()
        {}

        /**
         * MessageBucketMap destructor.
         */
        ~MessageBucketMap()
        {
            for (int i = 0; i < NUM_BUCKETS; ++i) {
                delete buckets[i];
            }
        }

        /**
         * Return the MessageBucket that should hold a Message with the given
         * MessageId.
         */
        MessageBucket* getBucket(const Protocol::MessageId& msgId) const
        {
            uint index = hasher(msgId) & HASH_KEY_MASK;
            return buckets[index];
        }

        /// Array of buckets.
        std::array<MessageBucket*, NUM_BUCKETS> const buckets;

        /// MessageId hash function container.
        Protocol::MessageId::Hasher hasher;
    };

    /**
     * Holds the incoming scheduled messages from another transport.
     */
    struct Peer {
        /**
         * Peer constructor.
         */
        Peer()
            : scheduledMessages()
            , scheduledPeerNode(this)
        {}

        /**
         * Peer destructor.
         */
        ~Peer()
        {
            scheduledMessages.clear();
        }

        /**
         * Implements a binary comparison function for the strict weak priority
         * ordering of two Peer objects.
         */
        struct ComparePriority {
            bool operator()(const Peer& a, const Peer& b)
            {
                assert(!a.scheduledMessages.empty());
                assert(!b.scheduledMessages.empty());
                ScheduledMessageInfo::ComparePriority comp;
                return comp(a.scheduledMessages.front(),
                            b.scheduledMessages.front());
            }
        };

        /// Contains all the scheduled messages coming from a single transport.
        Intrusive::List<Message> scheduledMessages;
        /// Intrusive structure to track all Peers with scheduled messages.
        Intrusive::List<Peer>::Node scheduledPeerNode;
    };

    void dropMessage(Receiver::Message* message);
    uint64_t checkMessageTimeouts();
    uint64_t checkResendTimeouts();
    void trySendGrants();
    void schedule(Message* message, const SpinLock::Lock& lock);
    void unschedule(Message* message, const SpinLock::Lock& lock);
    void updateSchedule(Message* message, const SpinLock::Lock& lock);

    /// Driver with which all packets will be sent and received.  This driver
    /// is chosen by the Transport that owns this Sender.
    Driver* const driver;

    /// Provider of network packet priority and grant policy decisions.
    Policy::Manager* const policyManager;

    /// Tracks the set of inbound messages being received by this Receiver.
    MessageBucketMap messageBuckets;

    /// Protects access to the Receiver's scheduler state (i.e. peerTable,
    /// scheduledPeers, and ScheduledMessageInfo).
    SpinLock schedulerMutex;

    /// Collection of all peers; used for fast access.  Access is protected by
    /// the schedulerMutex.
    std::unordered_map<Driver::Address, Peer> peerTable;

    /// List of peers with inbound messages that require grants to complete.
    /// Access is protected by the schedulerMutex.
    Intrusive::List<Peer> scheduledPeers;

    /// Message objects to be processed by the transport.
    struct {
        /// Protects the receivedMessage.queue
        SpinLock mutex;
        /// List of completely received messages.
        Intrusive::List<Message> queue;
    } receivedMessages;

    /// True if the Receiver is executing trySendGrants(); false, otherwise.
    /// Used to prevent concurrent calls to trySendGrants() from blocking on
    /// each other.
    std::atomic_flag granting = ATOMIC_FLAG_INIT;

    /// Used to allocate Message objects.
    struct {
        /// Protects the messageAllocator.pool
        SpinLock mutex;
        /// Pool from which Message objects can be allocated.
        ObjectPool<Message> pool;
    } messageAllocator;
};

}  // namespace Core
}  // namespace Homa

#endif  // HOMA_CORE_RECEIVER_H
