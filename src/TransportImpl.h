/* Copyright (c) 2018, Stanford University
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

#ifndef HOMA_TRANSPORTIMPL_H
#define HOMA_TRANSPORTIMPL_H

#include "MessageContext.h"
#include "Receiver.h"
#include "Scheduler.h"
#include "Sender.h"

#include <Homa/Homa.h>

#include <atomic>
#include <bitset>
#include <vector>

/**
 * Homa
 */
namespace Homa {
namespace Core {

/**
 * Provides the implementation of Homa::Transport.
 *
 * This class is thread-safe.
 */
class TransportImpl {
  public:
    explicit TransportImpl(Driver* driver, uint64_t transportId);

    ~TransportImpl();
    Message newMessage();
    Message receiveMessage();
    void sendMessage(Message* message, SendFlag flags = SEND_NO_FLAGS,
                     Message* completes[] = nullptr, uint16_t numCompletes = 0);
    void poll();

    /// Driver from which this transport will send and receive packets.
    Driver* const driver;

  private:
    /// Pool from which this transport will allocation MessageContext objects.
    Core::MessagePool messagePool;

    /// Module which controls the sending of message.
    Core::Sender sender;

    /// Module which schendules incoming packets.
    Core::Scheduler scheduler;

    /// Module which receives packets and forms them into messages.
    Core::Receiver receiver;

    /// Unique identifier for this transport.
    const uint64_t transportId;

    /// Unique identifier for the next message this transport sends.
    std::atomic<uint64_t> nextMessgeId;
};

}  // namespace Core
}  // namespace Homa

#endif  // HOMA_TRANSPORTIMPL_H
