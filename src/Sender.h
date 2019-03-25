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

#ifndef HOMA_CORE_SENDER_H
#define HOMA_CORE_SENDER_H

#include "Homa/Driver.h"

#include <atomic>
#include <unordered_map>

#include "Message.h"
#include "OutboundMessage.h"
#include "Protocol.h"
#include "SpinLock.h"
#include "Transport.h"

namespace Homa {
namespace Core {

/**
 * The Sender takes takes outgoing messages and sends out the message's packets
 * based on Homa's send policy and information (GRANTS) received from  the
 * Scheduler at the message's destination.
 *
 * This class is thread-safe.
 */
class Sender {
  public:
    explicit Sender();
    virtual ~Sender();

    virtual void handleGrantPacket(Driver::Packet* packet, Driver* driver);
    virtual void sendMessage(Protocol::MessageId id,
                             Driver::Address* destination, Transport::Op* op);
    virtual void dropMessage(Transport::Op* op);
    virtual void poll();

  private:
    /// Protects the top-level
    SpinLock mutex;

    /// Tracks the set of outbound messages; contains the associated Op
    /// for a given MessageId.
    std::unordered_map<Protocol::MessageId, Transport::Op*,
                       Protocol::MessageId::Hasher>
        outboundMessages;

    /// True if the Sender is currently executing trySend(); false, otherwise.
    /// Use to prevent concurrent calls to trySend() from blocking on eachother.
    std::atomic_flag sending = ATOMIC_FLAG_INIT;

    void trySend();
};

}  // namespace Core
}  // namespace Homa

#endif  // HOMA_CORE_SENDER_H
