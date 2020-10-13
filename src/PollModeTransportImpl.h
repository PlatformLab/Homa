/* Copyright (c) 2020, Stanford University
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

#pragma once

#include <Homa/Transports/PollModeTransport.h>
#include <atomic>
#include "TransportImpl.h"

namespace Homa {

/**
 * Internal implementation of Homa::PollModeTransport.
 */
class PollModeTransportImpl final : public PollModeTransport {
  public:
    explicit PollModeTransportImpl(Driver* driver, uint64_t transportId);
    explicit PollModeTransportImpl(Driver* driver, Core::Sender* sender,
                                   Core::Receiver* receiver,
                                   uint64_t transportId);
    virtual ~PollModeTransportImpl() = default;
    Homa::unique_ptr<OutMessage> alloc(uint16_t port) override;
    void free() override;
    Driver* getDriver() override;
    uint64_t getId() override;
    void poll() override;
    Homa::unique_ptr<Homa::InMessage> receive() override;

  private:
    /**
     * Callbacks defined for the polling-based transport implementation.
     */
    class PollModeCallbacks : public Core::Transport::Callbacks {
      public:
        explicit PollModeCallbacks(PollModeTransportImpl* owner)
            : owner(owner)
        {}

        ~PollModeCallbacks() override = default;

        bool deliver(uint16_t port, InMessage* message) override
        {
            (void)port;
            SpinLock::Lock _(owner->mutex);
            owner->receiveQueue.push_back(message);
            return true;
        }

      private:
        PollModeTransportImpl* owner;
    };

    void processPackets();

    /// Transport callbacks.
    PollModeCallbacks callbacks;

    /// Core transport instance.
    Core::TransportImpl core;

    /// Caches the next cycle time that timeouts will need to rechecked.
    std::atomic<uint64_t> nextTimeoutCycles;

    /// Monitor-style lock which protects the receive queue.
    SpinLock mutex;

    /// Queue of completed incoming messages.
    std::vector<InMessage*> receiveQueue;
};

}  // namespace Homa