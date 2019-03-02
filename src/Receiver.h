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

#ifndef HOMA_CORE_RECEIVER_H
#define HOMA_CORE_RECEIVER_H

#include "Homa/Driver.h"

#include "Message.h"
#include "Protocol.h"
#include "Scheduler.h"
#include "SpinLock.h"

#include <deque>
#include <mutex>
#include <unordered_map>

namespace Homa {
namespace Core {

// Forward declaration
class OpContext;

/**
 * The Receiver processes incomming Data packets, assembling them into messages
 * and return the message to higher-level software on request.
 *
 * This class is thread-safe.
 */
class Receiver {
  public:
    /**
     * Represents an incoming message that is being assembled or being processed
     * by the application.
     *
     * InboundMessage objects are contained in the OpContext but should only be
     * accessed by the Receiver.
     */
    class InboundMessage : public Message {
      public:
        InboundMessage(Protocol::MessageId msgId, Driver* driver,
                       uint16_t dataHeaderLength, uint32_t messageLength)
            : Message(msgId, driver, dataHeaderLength, messageLength)
            , mutex()
            , fullMessageReceived(false)
        {}

        /**
         * Return true if the InboundMessage has been received; false otherwise.
         */
        bool isReady()
        {
            std::lock_guard<SpinLock> _(mutex);
            return fullMessageReceived;
        }

      private:
        /// Ensure thread-safety between a multi-threaded Receiver.
        SpinLock mutex;
        /// True if all packets of the message have been received.
        bool fullMessageReceived;

        friend class Receiver;
    };

    explicit Receiver(Scheduler* scheduler);
    ~Receiver();
    void handleDataPacket(OpContext* op, Driver::Packet* packet,
                          Driver* driver);
    void poll();

  private:
    /// Scheduler that should be informed when message packets are received.
    Scheduler* const scheduler;
};

}  // namespace Core
}  // namespace Homa

#endif  // HOMA_CORE_RECEIVER_H