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

#ifndef HOMA_CORE_TRANSPORT_H
#define HOMA_CORE_TRANSPORT_H

#include <atomic>
#include <bitset>
#include <deque>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "InboundMessage.h"
#include "ObjectPool.h"
#include "OpContext.h"
#include "OutboundMessage.h"
#include "Policy.h"
#include "SpinLock.h"

/**
 * Homa
 */
namespace Homa {
namespace Core {

// Forward Declarations
class Receiver;
class Sender;

/**
 * Internal implementation of Homa::Transport.
 *
 * This class is thread-safe for concurrent calls operating of different
 * OpContext objects.  This class does NOT support concurrent calls on the same
 * OpContext object; unsupported calls should be avoided by the calling
 * interface (Homa::RemoteOp, Homa::ServerOp, Homa::Transport).
 */
class Transport {
  public:
    /**
     * Contains the state for an operation that is sent and received by the
     * Transport and its helper modules.
     */
    class Op : public OpContext {
      public:
        /**
         * Constructor.
         */
        explicit Op(Transport* transport, Driver* driver, Protocol::OpId opId,
                    bool isServerOp = true)
            : OpContext(transport)
            , mutex()
            , opId(opId)
            , outMessage(driver, this)
            , inMessage(nullptr)
            , retained(false)
            , isServerOp(isServerOp)
            , destroy()
        {}

        /**
         * @copydoc OpContext::getOutMessage()
         */
        virtual Message* getOutMessage()
        {
            SpinLock::Lock lock(mutex);
            return static_cast<Message*>(&outMessage);
        }

        /**
         * @copydoc OpContext::getInMessage()
         */
        virtual const Message* getInMessage()
        {
            SpinLock::Lock lock(mutex);
            if (inMessage != nullptr) {
                return static_cast<Message*>(inMessage);
            }
            return nullptr;
        }

        /// Mutex for controlling internal access to Op members.
        SpinLock mutex;

        /// Identifier for the operation with which this Op is associated.
        const Protocol::OpId opId;

        /// Message to be sent out as part of this Op.  Processed by the Sender.
        OutboundMessage outMessage;

        /// Message to be received as part of this Op.  Processed by the
        /// Receiver.
        InboundMessage* inMessage;

      private:
        /**
         * Signal that this Op should be garbage collected.
         *
         * @param lock
         *      Used to remind the caller to hold the Op's mutex while calling
         *      this method.
         */
        inline void drop(const SpinLock::Lock& lock)
        {
            (void)lock;
            if (!destroy) {
                destroy = true;
                SpinLock::Lock lock(transport->unusedOps.mutex);
                transport->unusedOps.queue.push_back(this);
            }
        }

        void processUpdates(const SpinLock::Lock& lock);

        /// True if this Op is being held by the application in a RemoteOp or a
        /// ServerOp; otherwise, false.
        std::atomic<bool> retained;

        /// True if this Op is for a ServerOp; false it is for a RemoteOp.
        const bool isServerOp;

        /// True if this Op will be destroyed soon; false otherwise.
        bool destroy;

        friend class Transport;
    };

    explicit Transport(Driver* driver, uint64_t transportId);

    ~Transport();
    OpContext* allocOp();
    OpContext* receiveOp();
    void releaseOp(OpContext* context);
    void sendRequest(OpContext* context, Driver::Address destination);
    void sendReply(OpContext* context);
    void poll();

    /**
     * Signal that an Op's state may have been updated.
     *
     * @param op
     *      Pointer to an Op whose state may have been updated.
     */
    inline void hintUpdatedOp(void* op)
    {
        SpinLock::Lock lock(updateHints.mutex);
        auto ret = updateHints.ops.insert(op);
        if (ret.second) {
            updateHints.order.push_back(op);
        }
    }

    /// Driver from which this transport will send and receive packets.
    Driver* const driver;

  private:
    void processPackets();
    void processInboundMessages();
    void checkForUpdates();
    void cleanupOps();

    /// Unique identifier for this transport.
    const std::atomic<uint64_t> transportId;

    /// Unique identifier for the next RemoteOp this transport sends.
    std::atomic<uint64_t> nextOpSequenceNumber;

    /// Module which manages the network packet priority policy.
    Policy::Manager policyManager;

    /// Module which controls the sending of message.
    std::unique_ptr<Core::Sender> sender;

    /// Module which receives packets and forms them into messages.
    std::unique_ptr<Core::Receiver> receiver;

    /// Protects the internal state of the Transport.
    SpinLock mutex;

    /// Pool from which this transport will allocate Op objects.
    ObjectPool<Op> opPool;

    /// Set of Op objects are currently being managed by this Transport.
    std::unordered_set<Op*> activeOps;

    /// Tracks the set of Op objects that were initiated by this Transport
    /// (i.e. Op objects that represent RemoteOps).
    std::unordered_map<Protocol::OpId, Op*, Protocol::OpId::Hasher> remoteOps;

    /// Collection of Op objects that may have been recently updated.
    struct {
        /// Protects updateHints.
        SpinLock mutex;
        /// Set of Op objects that might have been updated.
        std::unordered_set<void*> ops;
        /// The order in which Op objects were (possibly) updated.  Used to
        /// ensure Op object processing is not starved.
        std::deque<void*> order;
    } updateHints;

    /// Collection of Op objects that are waiting to be destructed.  Allow the
    /// Op the asynchronously request its own destruction.
    struct {
        /// Protects unusedOps.
        SpinLock mutex;
        /// Holds the Op objects that should be eventually freed.
        std::deque<Op*> queue;
    } unusedOps;

    /// Collection of ServerOp contexts that are ready but have not yet been
    /// delivered to the application.
    struct {
        /// Protects pendingServerOps.
        SpinLock mutex;
        /// Holds the Op objects for the pending ServerOps.
        std::deque<Op*> queue;
    } pendingServerOps;
};

}  // namespace Core
}  // namespace Homa

#endif  // HOMA_CORE_TRANSPORT_H
