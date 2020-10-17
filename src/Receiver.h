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
#include <Homa/Homa.h>
#include <Homa/Util.h>

#include <atomic>
#include <deque>
#include <unordered_map>

#include "ControlPacket.h"
#include "Intrusive.h"
#include "ObjectPool.h"
#include "Policy.h"
#include "Protocol.h"
#include "SpinLock.h"
#include "Timeout.h"
#include "Util.h"

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
    virtual bool handleDataPacket(Driver::Packet* packet, IpAddress sourceIp);
    virtual void handleBusyPacket(Driver::Packet* packet);
    virtual void handlePingPacket(Driver::Packet* packet, IpAddress sourceIp);
    virtual Homa::InMessage* receiveMessage();
    virtual void poll();
    virtual void checkTimeouts();

  private:
    // Forward declaration
    class Message;
    struct MessageBucket;
    struct Peer;

    Message* handleIncomingPacket(Driver::Packet* packet, bool createIfAbsent,
                                  IpAddress* sourceIp = nullptr);

    /**
     * Contains metadata for a Message that requires additional GRANTs.
     */
    struct ScheduledMessageInfo {
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
    class Message : public Homa::InMessage {
      public:
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
         * Defines the possible states of this Message.
         */
        enum class State {
            IN_PROGRESS,  //< Receiver is in the process of receiving this
                          // message.
            COMPLETED,    //< Receiver has received the entire message.
        };

        explicit Message(Receiver* receiver, Driver* driver,
                         size_t packetHeaderLength, int messageLength,
                         Protocol::MessageId id, SocketAddress source,
                         int numUnscheduledPackets)
            : driver(driver)
            , id(id)
            , bucket(receiver->messageBuckets.getBucket(id))
            , source(source)
            , TRANSPORT_HEADER_LENGTH(packetHeaderLength)
            , PACKET_DATA_LENGTH(driver->getMaxPayloadSize() -
                                 TRANSPORT_HEADER_LENGTH)
            , numExpectedPackets(
                  Util::roundUpIntDiv(messageLength, PACKET_DATA_LENGTH))
            , numUnscheduledPackets(numUnscheduledPackets)
            , scheduled(numExpectedPackets > numUnscheduledPackets)
            , start(0)
            , messageLength(messageLength)
            , numPackets(0)
            , occupied()
            // packets is not initialized to reduce the work done during
            // construction. See Message::occupied.
            , state(Message::State::IN_PROGRESS)
            , bucketNode(this)
            , receivedMessageNode(this)
            , numResendTimeouts(0)
            , resendTimeout(this)
            , scheduledMessageInfo(this, messageLength)
        {}

        virtual ~Message();
        void acknowledge() const override;
        size_t get(size_t offset, void* destination,
                           size_t count) const override;
        size_t length() const override;
        void strip(size_t count) override;
        void release() override;

        /**
         * Return the current state of this message.
         */
        State getState() const
        {
            return state.load(std::memory_order_acquire);
        }

      private:
        /// Define the maximum number of packets that a message can hold.
        static const int MAX_MESSAGE_PACKETS = 1024;

        Driver::Packet* getPacket(size_t index) const;
        bool setPacket(size_t index, Driver::Packet* packet);

        /// Driver from which packets were received and to which they should be
        /// returned when this message is no longer needed.
        Driver* const driver;

        /// Contains the unique identifier for this message.
        const Protocol::MessageId id;

        /// Message bucket this message belongs to.
        MessageBucket* const bucket;

        /// Contains source address this message.
        const SocketAddress source;

        /// Number of bytes at the beginning of each Packet that should be
        /// reserved for the Homa transport header.
        const int TRANSPORT_HEADER_LENGTH;

        /// Number of bytes of data in each full packet.
        const int PACKET_DATA_LENGTH;

        /// Number of packets the message is expected to contain.
        const int numExpectedPackets;

        /// Number of packets that will be sent without GRANTs.
        const int numUnscheduledPackets;

        /// True if the Message exceeds the unscheduled byte limit and requires
        /// GRANTs to be sent.
        const bool scheduled;

        /// First byte where data is or will go if empty.
        int start;

        /// Number of bytes in this Message including any stripped bytes.
        int messageLength;

        /// Number of packets currently contained in this message.
        int numPackets;

        /// Bit array representing which entires in the _packets_ array are set.
        /// Used to avoid having to zero out the entire _packets_ array.
        std::bitset<MAX_MESSAGE_PACKETS> occupied;

        /// Collection of Packet objects that make up this context's Message.
        /// These Packets will be released when this context is destroyed.
        Driver::Packet* packets[MAX_MESSAGE_PACKETS];

        /// This message's current state.
        std::atomic<State> state;

        /// Intrusive structure used by the Receiver to hold on to this Message
        /// in one of the Receiver's MessageBuckets.  Access to this structure
        /// is protected by the associated MessageBucket::mutex;
        Intrusive::List<Message>::Node bucketNode;

        /// Intrusive structure used by the Receiver to keep track of this
        /// message when it has been completely received.
        Intrusive::List<Message>::Node receivedMessageNode;

        /// Number of resend timeouts that occurred in a row.  Access to this
        /// structure is protected by the associated MessageBucket::mutex.
        int numResendTimeouts;

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
         * @param receiver
         *      Receiver that owns this bucket.
         * @param resendIntervalCycles
         *      Number of cycles of inactivity to wait between requesting
         *      retransmission of un-received parts of a Message.
         *      liveness of a Message.
         */
        explicit MessageBucket(Receiver* receiver,
                               uint64_t resendIntervalCycles)
            : receiver(receiver)
            , mutex()
            , messages()
            , resendTimeouts(resendIntervalCycles)
        {}

        /**
         * Destruct a MessageBucket. Will destroy all contained Message objects.
         */
        ~MessageBucket()
        {
            // Intrusive::List is not responsible for destructing its elements;
            // it must be done manually.
            for (auto& message : messages) {
                receiver->messageAllocator.destroy(&message);
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

        /// The Receiver that owns this bucket.
        Receiver* const receiver;

        /// Mutex protecting the contents of this bucket.
        SpinLock mutex;

        /// Collection of inbound messages
        Intrusive::List<Message> messages;

        /// Maintains Message object in increasing order of resend timeout.
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
         * @param resendIntervalCycles
         *      Number of cycles of inactivity to wait between requesting
         *      retransmission of un-received parts of a Message.
         *      liveness of a Message.
         */
        explicit MessageBucketMap(uint64_t resendIntervalCycles)
            : buckets()
            , hasher()
        {
            buckets.reserve(NUM_BUCKETS);
            for (int i = 0; i < NUM_BUCKETS; ++i) {
                buckets.emplace_back(resendIntervalCycles);
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

    /**
     * Holds the incoming scheduled messages from another transport.
     *
     * The lifetime of a Peer is the same as Receiver: we never destruct Peer
     * objects when the transport is running.
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
         * Peer destructor. Only invoked from the destructor of Receiver.
         */
        ~Peer()
        {
            // By the time we need to destruct a peer, all Message's coming from
            // it should have been released.
            assert(scheduledMessages.empty());

            // To keep Peer (constructor) simple, we don't store a reference to
            // the outer Receiver in Peer. As a result, Receiver is responsible
            // for clearing schedulerPeers.
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
                Message::ComparePriority comp;
                return comp(a.scheduledMessages.front(),
                            b.scheduledMessages.front());
            }
        };

        /// Contains all the scheduled messages coming from a single transport.
        Intrusive::List<Message> scheduledMessages;
        /// Intrusive structure to track all Peers with scheduled messages.
        Intrusive::List<Peer>::Node scheduledPeerNode;
    };

    void checkResendTimeouts(uint64_t now, MessageBucket* bucket);
    void trySendGrants();
    void schedule(Message* message, const SpinLock::Lock& lock);
    void unschedule(Message* message, const SpinLock::Lock& lock);
    void updateSchedule(Message* message, const SpinLock::Lock& lock);

    /// Driver with which all packets will be sent and received.  This driver
    /// is chosen by the Transport that owns this Receiver.
    Driver* const driver;

    /// Provider of network packet priority and grant policy decisions. Not
    /// owned by this class.
    Policy::Manager* const policyManager;

    /// The number of resend timeouts to occur before declaring a message
    /// timeout.
    const int MESSAGE_TIMEOUT_INTERVALS;

    /// Tracks the set of inbound messages being received by this Receiver.
    MessageBucketMap messageBuckets;

    /// Protects access to the Receiver's scheduler state (i.e. peerTable,
    /// scheduledPeers, and ScheduledMessageInfo).
    SpinLock schedulerMutex;

    /// Collection of all peers; used for fast access.  Access is protected by
    /// the schedulerMutex.
    std::unordered_map<IpAddress, Peer, IpAddress::Hasher> peerTable;

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

#endif  // HOMA_CORE_RECEIVER_H
