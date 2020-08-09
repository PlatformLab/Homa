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

#ifndef HOMA_CORE_TRANSPORT_H
#define HOMA_CORE_TRANSPORT_H

#include <Homa/Homa.h>

#include <atomic>
#include <bitset>

#include "ObjectPool.h"
#include "Policy.h"
#include "Receiver.h"
#include "Sender.h"
#include "SpinLock.h"

/**
 * Homa
 */
namespace Homa::Core {

/**
 * Internal implementation of Homa::Transport.
 */
class TransportImpl final : public Transport {
  public:
    explicit TransportImpl(Driver* driver, MailboxDir* mailboxDir,
                           uint64_t transportId);
    explicit TransportImpl(Driver* driver, MailboxDir* mailboxDir,
                           Sender* sender, Receiver* receiver,
                           uint64_t transportId);
    ~TransportImpl();
    void free() override;
    Homa::unique_ptr<Socket> open(uint16_t port) override;
    uint64_t checkTimeouts() override;
    void processPacket(Driver::Packet* packet, IpAddress source) override;
    void registerCallbackSendReady(Callback func) override;
    bool trySend(uint64_t* waitUntil) override;
    bool trySendGrants() override;

    /// See Homa::Transport::getDriver()
    virtual Driver* getDriver()
    {
        return driver;
    }

    /// See Homa::Transport::getId()
    virtual uint64_t getId()
    {
        return transportId;
    }

    /**
     * Internal implementation of Homa::Socket.
     *
     * @sa
     *      TransportImpl::socketMap
     */
    class SocketImpl final : public Socket {
      public:
        explicit SocketImpl(TransportImpl* transport, uint16_t port,
                            Mailbox* mailbox);
        virtual ~SocketImpl() = default;

        Homa::unique_ptr<Homa::OutMessage> alloc() override;
        void close() override;
        Homa::unique_ptr<Homa::InMessage> receive(bool blocking) override;
        void shutdown() override;

        /// See Homa::Socket::isShutdown()
        bool isShutdown() const override
        {
            return disabled.load(std::memory_order_relaxed);
        }

        /// See Homa::Socket::getLocalAddress()
        Address getLocalAddress() const override
        {
            return localAddress;
        }

      private:
        /// Has the socket been shut down?
        std::atomic<bool> disabled;

        /// Local address of the socket.
        Address localAddress;

        /// Mailbox assigned to this socket. Not owned by this class.
        Mailbox* mailbox;

        /// Transport that owns this socket.
        TransportImpl* transport;
    };

  private:
    /// Unique identifier for this transport.
    const uint64_t transportId;

    /// Driver from which this transport will send and receive packets.
    /// Not owned by this class.
    Driver* const driver;

    /// Module which manages the network packet priority policy.
    std::unique_ptr<Policy::Manager> policyManager;

    /// Module which controls the sending of message.
    std::unique_ptr<Core::Sender> sender;

    /// Module which receives packets and forms them into messages.
    std::unique_ptr<Core::Receiver> receiver;

    /// Module which keeps track of mailboxes currently in use. Not owned by
    /// this class (we don't even know whether it's instantiated by "new").
    MailboxDir* const mailboxDir;
};

}  // namespace Homa::Core

#endif  // HOMA_CORE_TRANSPORT_H
