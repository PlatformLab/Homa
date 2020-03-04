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

#ifndef HOMA_CORE_SENDER_H
#define HOMA_CORE_SENDER_H

#include <Homa/Driver.h>

#include <array>
#include <atomic>
#include <unordered_map>

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
 * The Sender manages the sending of outbound messages based on the policy set
 * by the destination Transport's Receiver.  There is one Sender per Transport.
 *
 * This class is thread-safe.
 */
class Sender {
  public:
    explicit Sender(uint64_t transportId, Driver* driver,
                    Policy::Manager* policyManager,
                    uint64_t messageTimeoutCycles, uint64_t pingIntervalCycles);
    virtual ~Sender();

    virtual Homa::OutMessage* allocMessage();
    virtual void handleDonePacket(Driver::Packet* packet, Driver* driver);
    virtual void handleResendPacket(Driver::Packet* packet, Driver* driver);
    virtual void handleGrantPacket(Driver::Packet* packet, Driver* driver);
    virtual void handleUnknownPacket(Driver::Packet* packet, Driver* driver);
    virtual void handleErrorPacket(Driver::Packet* packet, Driver* driver);
    virtual void poll();
    virtual uint64_t checkTimeouts();

  private:
    /// Forward declarations
    class Message;

    /**
     * Contains metadata for a Message that has been queued to be sent.
     */
    struct QueuedMessageInfo {
        /**
         * Implements a binary comparison function for the strict weak priority
         * ordering of two Message objects.
         */
        struct ComparePriority {
            bool operator()(const Message& a, const Message& b)
            {
                return a.queuedMessageInfo.unsentBytes <
                       b.queuedMessageInfo.unsentBytes;
            }
        };

        /**
         * QueuedMessageInfo constructor.
         *
         * @param message
         *      Message to which this metadata is associated.
         */
        explicit QueuedMessageInfo(Message* message)
            : id(0, 0)
            , destination()
            , packets(nullptr)
            , unsentBytes(0)
            , packetsGranted(0)
            , priority(0)
            , packetsSent(0)
            , sendQueueNode(message)
        {}

        /// Contains the unique identifier for this message.
        Protocol::MessageId id;

        /// Contains destination address this message.
        Driver::Address destination;

        /// Handle to the queue Message for access to the packets that will
        /// be sent.  This member documents that the packets are logically owned
        /// by the sendQueue and thus protected by the queueMutex.
        Core::Message* packets;

        /// The number of bytes that still need to be sent for a queued Message.
        int unsentBytes;

        /// The number of packets that can be sent for this Message.
        int packetsGranted;

        /// The network priority at which this Message should be sent.
        int priority;

        /// The number of packets that have been sent for this Message.
        int packetsSent;

        /// Intrusive structure used to enqueue the associated Message into
        /// the sendQueue.
        Intrusive::List<Message>::Node sendQueueNode;
    };

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
            , sender(sender)
            , id(0, 0)
            , destination()
            , state(Status::NOT_STARTED)
            , bucketNode(this)
            , messageTimeout(this)
            , pingTimeout(this)
            , queuedMessageInfo(this)
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
        /// The Sender responsible for sending this message.
        Sender* const sender;

        /// Contains the unique identifier for this message.
        Protocol::MessageId id;

        /// Contains destination address this message.
        Driver::Address destination;

        /// This message's current state.
        std::atomic<Status> state;

        /// Intrusive structure used by the Sender to hold on to this Message
        /// in one of the Sender's MessageBuckets.  Access to this structure
        /// is protected by the associated MessageBucket::mutex;
        Intrusive::List<Message>::Node bucketNode;

        /// Intrusive structure used by the Sender to keep track when the
        /// sending of this message should be considered failed.  Access to this
        /// structure is protected by the associated MessageBucket::mutex.
        Timeout<Message> messageTimeout;

        /// Intrusive structure used by the Sender to keep track when this
        /// message should be checked to ensure progress is still being made.
        /// Access to this structure is protected by the associated
        /// MessageBucket::mutex;
        Timeout<Message> pingTimeout;

        /// Intrusive structure used by the Sender to keep track of this Message
        /// if it has been queued to be sent.  Access to this structure is
        /// protected by the Sender::queueMutex.
        QueuedMessageInfo queuedMessageInfo;

        friend class Sender;
    };

    /**
     * A collection of outgoing Message objects and their associated timeouts.
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
         * @param pingIntervalCycles
         *      Number of cycles of inactivity to wait between checking on the
         *      liveness of a Message.
         */
        explicit MessageBucket(uint64_t messageTimeoutCycles,
                               uint64_t pingIntervalCycles)
            : mutex()
            , messages()
            , messageTimeouts(messageTimeoutCycles)
            , pingTimeouts(pingIntervalCycles)
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

        /// Collection of outbound messages
        Intrusive::List<Message> messages;

        /// Maintains Message objects in increasing order of timeout.
        TimeoutManager<Message> messageTimeouts;

        /// Maintains Message object in increase order of ping timeout.
        TimeoutManager<Message> pingTimeouts;
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
         * @param pingIntervalCycles
         *      Number of cycles of inactivity to wait between checking on the
         *      liveness of a Message.
         */
        static std::array<MessageBucket*, NUM_BUCKETS> makeBuckets(
            uint64_t messageTimeoutCycles, uint64_t pingIntervalCycles)
        {
            std::array<MessageBucket*, NUM_BUCKETS> buckets;
            for (int i = 0; i < NUM_BUCKETS; ++i) {
                buckets[i] =
                    new MessageBucket(messageTimeoutCycles, pingIntervalCycles);
            }
            return buckets;
        }

        /**
         * MessageBucketMap constructor.
         *
         * @param messageTimeoutCycles
         *      Number of cycles of inactivity to wait before a Message is
         *      considered failed.
         * @param pingIntervalCycles
         *      Number of cycles of inactivity to wait between checking on the
         *      liveness of a Message.
         */
        explicit MessageBucketMap(uint64_t messageTimeoutCycles,
                                  uint64_t pingIntervalCycles)
            : buckets(makeBuckets(messageTimeoutCycles, pingIntervalCycles))
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

    void sendMessage(Sender::Message* message, Driver::Address destination);
    void cancelMessage(Sender::Message* message);
    void dropMessage(Sender::Message* message);
    uint64_t checkMessageTimeouts();
    uint64_t checkPingTimeouts();
    void trySend();

    /// Transport identifier.
    const uint64_t transportId;

    /// Driver with which all packets will be sent and received.  This driver
    /// is chosen by the Transport that owns this Sender.
    Driver* const driver;

    /// Provider of network packet priority decisions.
    Policy::Manager* const policyManager;

    /// The sequence number to be used for the next Message.
    std::atomic<uint64_t> nextMessageSequenceNumber;

    /// The maximum number of bytes that should be queued in the Driver.
    const uint32_t DRIVER_QUEUED_BYTE_LIMIT;

    /// Tracks all outbound messages being sent by the Sender.
    MessageBucketMap messageBuckets;

    /// Protects the readyQueue.
    SpinLock queueMutex;

    /// A list of outbound messages that have unsent packets.  Messages are kept
    /// in order of priority.
    Intrusive::List<Message> sendQueue;

    /// True if the Sender is currently executing trySend(); false, otherwise.
    /// Use to prevent concurrent trySend() calls from blocking on each other.
    std::atomic_flag sending = ATOMIC_FLAG_INIT;

    /// Hint whether there are messages ready to be sent (i.e. there are granted
    /// messages in the sendQueue. Encoded into a single bool so that checking
    /// if there is work to do is more efficient.
    std::atomic<bool> sendReady;

    /// Used to allocate Message objects.
    struct {
        /// Protects the messageAllocator.pool
        SpinLock mutex;
        /// Pool allocator for Message objects.
        ObjectPool<Message> pool;
    } messageAllocator;
};

}  // namespace Core
}  // namespace Homa

#endif  // HOMA_CORE_SENDER_H
