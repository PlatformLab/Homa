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
class Transport {
  public:
    explicit Transport(Driver* driver, uint64_t transportId);

    ~Transport();

    /**
     * Allocate Message that can be sent with this Transport.
     *
     * The release() method should be called on the returned message when the
     * caller no longer needs access to it.
     *
     * @return
     *      A pointer to the allocated message.
     */
    Homa::OutMessage* alloc()
    {
        return sender->allocMessage();
    }

    /**
     * Receive a Message delivered to this Transport.
     *
     * The release() method should be called on the returned message when the
     * caller no longer needs access to it.
     *
     * @return
     *      Pointer to the received message, if any.  Otherwise, nullptr is
     *      returned if no message has been delivered.
     */
    Homa::InMessage* receive()
    {
        return receiver->receiveMessage();
    }

    void poll();

    /// Driver from which this transport will send and receive packets.
    Driver* const driver;

  private:
    void processPackets();

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

    std::atomic<uint64_t> nextTimeoutCycles;
};

}  // namespace Core
}  // namespace Homa

#endif  // HOMA_CORE_TRANSPORT_H
