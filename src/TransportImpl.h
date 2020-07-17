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
#include <deque>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "ObjectPool.h"
#include "Policy.h"
#include "Receiver.h"
#include "Sender.h"
#include "SpinLock.h"

/**
 * Homa
 */
namespace Homa {
namespace Core {

/**
 * Internal implementation of Homa::Transport.
 *
 */
class TransportImpl : public Transport {
  public:
    explicit TransportImpl(Driver* driver, uint64_t transportId);
    ~TransportImpl();

    /// See Homa::Transport::alloc()
    virtual Homa::unique_ptr<Homa::OutMessage> alloc(uint16_t sourcePort)
    {
        Homa::OutMessage* outMessage = sender->allocMessage(sourcePort);
        return Homa::unique_ptr<Homa::OutMessage>(outMessage);
    }

    /// See Homa::Transport::receive()
    virtual Homa::unique_ptr<Homa::InMessage> receive()
    {
        return Homa::unique_ptr<Homa::InMessage>(receiver->receiveMessage());
    }

    virtual void poll();

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

  private:
    void processPackets();
    void processPacket(Driver::Packet* packet, IpAddress source);

    /// Unique identifier for this transport.
    const std::atomic<uint64_t> transportId;

    /// Driver from which this transport will send and receive packets.
    Driver* const driver;

    /// Module which manages the network packet priority policy.
    std::unique_ptr<Policy::Manager> policyManager;

    /// Module which controls the sending of message.
    std::unique_ptr<Core::Sender> sender;

    /// Module which receives packets and forms them into messages.
    std::unique_ptr<Core::Receiver> receiver;

    /// Caches the next cycle time that timeouts will need to rechecked.
    std::atomic<uint64_t> nextTimeoutCycles;
};

}  // namespace Core
}  // namespace Homa

#endif  // HOMA_CORE_TRANSPORT_H
