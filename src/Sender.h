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
#include <Homa/Homa.h>
#include <Homa/Util.h>

#include <array>
#include <atomic>
#include <unordered_map>

#include "Intrusive.h"
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
    virtual ~Sender() = default;

    virtual Homa::OutMessage* allocMessage(uint16_t sourcePort);
    virtual void handleDonePacket(Driver::Packet* packet);
    virtual void handleResendPacket(Driver::Packet* packet);
    virtual void handleGrantPacket(Driver::Packet* packet);
    virtual void handleUnknownPacket(Driver::Packet* packet);
    virtual void handleErrorPacket(Driver::Packet* packet);

    virtual void poll();
    virtual void checkTimeouts();

  private:
    /// Forward declarations
    class Message;
    struct MessageBucket;

    Message* handleIncomingPacket(Driver::Packet* packet, bool resetTimeout);

    /**
     * Contains metadata for a Message that has been queued to be sent.
     */
    struct QueuedMessageInfo {
        /**
         * QueuedMessageInfo constructor.
         *
         * @param message
         *      Message to which this metadata is associated.
         */
        explicit QueuedMessageInfo(Message* message)
            : unsentBytes(0)
            , packetsGranted(0)
            , packetsSent(0)
            , priority(0)
            , sendQueueNode(message)
        {}

        /// The number of bytes that still need to be sent for a queued Message.
        /// This variable is used to rank messages in SRPT order so it must be
        /// protected by Sender::queueMutex.
        int unsentBytes;

        /// The number of packets that can be sent for this Message.
        int packetsGranted;

        /// The number of packets that have been sent for this Message.
        int packetsSent;

        /// The network priority at which this Message should be sent.
        int priority;

        /// Intrusive structure used to enqueue the associated Message into
        /// the sendQueue. Protected by Sender::queueMutex.
        Intrusive::List<Message>::Node sendQueueNode;
    };

    /**
     * Represents an outgoing message that can be sent.
     */
    class Message : public Homa::OutMessage {
      public:
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
         * Construct an Message.
         */
        explicit Message(Sender* sender, uint64_t messageId,
                         uint16_t sourcePort)
            : sender(sender)
            , driver(sender->driver)
            , TRANSPORT_HEADER_LENGTH(sizeof(Protocol::Packet::DataHeader))
            , PACKET_DATA_LENGTH(driver->getMaxPayloadSize() -
                                 TRANSPORT_HEADER_LENGTH)
            , id(sender->transportId, messageId)
            , bucket(sender->messageBuckets.getBucket(id))
            , source{driver->getLocalAddress(), sourcePort}
            , destination()
            , options(Options::NONE)
            , held(true)
            , start(0)
            , messageLength(0)
            , numPackets(0)
            , occupied()
            // packets is not initialized to reduce the work done during
            // construction. See Message::occupied.
            , state(Status::NOT_STARTED)
            , bucketNode(this)
            , numPingTimeouts(0)
            , pingTimeout(this)
            , queuedMessageInfo(this)
        {}

        virtual ~Message();
        void append(const void* source, size_t count) override;
        void cancel() override;
        Status getStatus() const override;
        void setStatus(Status newStatus, bool deschedule);
        size_t length() const override;
        void prepend(const void* source, size_t count) override;
        void release() override;
        void reserve(size_t count) override;
        void send(SocketAddress destination,
                  Options options = Options::NONE) override;

      private:
        /// Define the maximum number of packets that a message can hold.
        static const int MAX_MESSAGE_PACKETS = 1024;

        Driver::Packet* getPacket(size_t index) const;
        Driver::Packet* getOrAllocPacket(size_t index);

        /// The Sender responsible for sending this message.
        Sender* const sender;

        /// Driver from which packets were allocated and to which they should be
        /// returned when this message is no longer needed.
        Driver* const driver;

        /// Number of bytes at the beginning of each Packet that should be
        /// reserved for the Homa transport header.
        const int TRANSPORT_HEADER_LENGTH;

        /// Number of bytes of data in each full packet.
        const int PACKET_DATA_LENGTH;

        /// Contains the unique identifier for this message.
        const Protocol::MessageId id;

        /// Message bucket this message belongs to.
        MessageBucket* const bucket;

        /// Contains source address of this message.
        const SocketAddress source;

        /// Contains destination address of this message. Must be constant after
        /// send() is invoked.
        SocketAddress destination;

        /// Contains flags for any requested optional send behavior. Must be
        /// constant after send() is invoked.
        Options options;

        /// True if a pointer to this message is accessible by the application
        /// (e.g. the message has been allocated via allocMessage() but has not
        /// been release via dropMessage()); false, otherwise.
        std::atomic<bool> held;

        /// First byte where data is or will go if empty. Must be constant after
        /// send() is invoked.
        int start;

        /// Number of bytes in this Message including any reserved headroom.
        /// Must be constant after send() is invoked.
        int messageLength;

        /// Number of packets currently contained in this message. Must be
        /// constant after send() is invoked.
        int numPackets;

        // FIXME: seems like an overkill? (e.g., packets should be added in order)
        /// Bit array representing which entries in the _packets_ array are set.
        /// Used to avoid having to zero out the entire _packets_ array. Must be
        /// constant after send() is invoked.
        std::bitset<MAX_MESSAGE_PACKETS> occupied;

        /// Collection of Packet objects that make up this context's Message.
        /// These Packets will be released when this context is destroyed. Must
        /// be constant after send() is invoked.
        Driver::Packet* packets[MAX_MESSAGE_PACKETS];

        /// This message's current state.
        std::atomic<Status> state;

        /// Intrusive structure used by the Sender to hold on to this Message
        /// in one of the Sender's MessageBuckets.  Access to this structure
        /// is protected by the associated MessageBucket::mutex;
        Intrusive::List<Message>::Node bucketNode;

        /// Number of ping timeouts that occurred in a row.  Access to this
        /// structure is protected by the associated MessageBucket::mutex.
        int numPingTimeouts;

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
         * @param Sender
         *      Sender that owns this bucket.
         * @param pingIntervalCycles
         *      Number of cycles of inactivity to wait between checking on the
         *      liveness of a Message.
         */
        explicit MessageBucket(Sender* sender, uint64_t pingIntervalCycles)
            : sender(sender)
            , mutex()
            , messages()
            , pingTimeouts(pingIntervalCycles)
        {}

        /**
         * Destruct a MessageBucket. Will destroy all contained Message objects.
         */
        ~MessageBucket()
        {
            // Intrusive::List is not responsible for destructing its elements;
            // it must be done manually.
            for (auto& message : messages) {
                sender->messageAllocator.destroy(&message);
            }
        }

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
            for (auto& it : messages) {
                if (it.id == msgId) {
                    return &it;
                }
            }
            return nullptr;
        }

        /// Sender that owns this object.
        Sender* const sender;

        /// Mutex protecting the contents of this bucket. See Sender::queueMutex
        /// for locking order constraints.
        SpinLock mutex;

        /// Collection of outbound messages
        Intrusive::List<Message> messages;

        /// Maintains Message objects in increasing order of ping timeout.
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

        // Make sure the number of buckets is a power of 2.
        static_assert(Util::isPowerOfTwo(NUM_BUCKETS));

        /**
         * Bit mask used to map from a hashed key to the bucket index.
         */
        static const uint HASH_KEY_MASK = 0xFF;

        // Make sure bit mask correctly matches the number of buckets.
        static_assert(NUM_BUCKETS == HASH_KEY_MASK + 1);

        /**
         * MessageBucketMap constructor.
         *
         * @param sender
         *      Sender that owns this bucket map.
         * @param pingIntervalCycles
         *      Number of cycles of inactivity to wait between checking on the
         *      liveness of a Message.
         */
        explicit MessageBucketMap(Sender* sender, uint64_t pingIntervalCycles)
            : buckets()
            , hasher()
        {
            buckets.reserve(NUM_BUCKETS);
            for (int i = 0; i < NUM_BUCKETS; ++i) {
                buckets.emplace_back(sender, pingIntervalCycles);
            }
        }

        /**
         * MessageBucketMap destructor.
         */
        ~MessageBucketMap() = default;

        /**
         * Return the MessageBucket that should hold a Message with the given
         * MessageId.
         */
        MessageBucket* getBucket(const Protocol::MessageId& msgId)
        {
            uint index = hasher(msgId) & HASH_KEY_MASK;
            return &buckets[index];
        }

        /// Array of NUM_BUCKETS buckets. Defined as a vector to avoid the need
        /// for a default constructor in MessageBucket.
        std::vector<MessageBucket> buckets;

        /// MessageId hash function container.
        Protocol::MessageId::Hasher hasher;
    };

    void startMessage(Sender::Message* message, bool restart);
    void checkPingTimeouts(uint64_t now, MessageBucket* bucket);
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

    /// The number of ping timeouts to occur before declaring a message timeout.
    const int MESSAGE_TIMEOUT_INTERVALS;

    /// Tracks all outbound messages being sent by the Sender.
    MessageBucketMap messageBuckets;

    /// Protects the sendQueue, including all member variables of its items.
    /// When multiple locks must be acquired, this class follows the locking
    /// order constraint below ("<" means "acquired before"):
    ///     queueMutex < MessageBucket::mutex
    /// Usually, it's more natural to acquire coarser-grained locks first,
    /// unless inverting the order would make the common code path simpler
    /// and/or faster.
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

    /// The index of the next bucket in the messageBuckets::buckets array to
    /// process in the poll loop. The index is held in the lower order bits of
    /// this variable; the higher order bits should be masked off using the
    /// MessageBucketMap::HASH_KEY_MASK bit mask.
    std::atomic<uint> nextBucketIndex;

    /// Used to allocate Message objects.
    ObjectPool<Message> messageAllocator;
};

}  // namespace Core
}  // namespace Homa

#endif  // HOMA_CORE_SENDER_H
