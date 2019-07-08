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
#include "Timeout.h"

namespace Homa {
namespace Core {
// Forward Declaration
class Transport;

/**
 * The Sender takes takes outgoing messages and sends out the message's packets
 * based on Homa's send policy and information (GRANTS) received from  the
 * Scheduler at the message's destination.
 *
 * This class is thread-safe.
 */
class Sender {
  public:
    explicit Sender(Transport* transport, uint64_t transportId,
                    uint64_t messageTimeoutCycles, uint64_t pingIntervalCycles);
    virtual ~Sender();

    virtual void handleDonePacket(Driver::Packet* packet, Driver* driver);
    virtual void handleGrantPacket(Driver::Packet* packet, Driver* driver);
    virtual void handleResendPacket(Driver::Packet* packet, Driver* driver);
    virtual void handleUnknownPacket(Driver::Packet* packet, Driver* driver);
    virtual void handleErrorPacket(Driver::Packet* packet, Driver* driver);
    virtual void sendMessage(OutboundMessage* message,
                             Driver::Address* destination);
    virtual void dropMessage(OutboundMessage* message);
    virtual void poll();

  private:
    void checkMessageTimeouts();
    void checkPingTimeouts();
    void trySend();

    /// Protects the top-level
    SpinLock mutex;

    /// Transport of which this Sender is a part.
    Transport* transport;

    /// Transport identifier.
    const uint64_t transportId;

    /// The sequence number to be used for the next OutboundMessage.
    uint64_t nextMessageSequenceNumber;

    /// Tracks the set of outbound messages being sent by the Sender.
    std::unordered_map<Protocol::MessageId, OutboundMessage*,
                       Protocol::MessageId::Hasher>
        outboundMessages;

    /// Maintains OutboundMessage objects in increasing order of timeout.
    TimeoutManager<OutboundMessage> messageTimeouts;

    /// Maintains OutboundMessage object in increase order of ping timeout.
    TimeoutManager<OutboundMessage> pingTimeouts;

    /// True if the Sender is currently executing trySend(); false, otherwise.
    /// Use to prevent concurrent calls to trySend() from blocking on eachother.
    std::atomic_flag sending = ATOMIC_FLAG_INIT;
};

}  // namespace Core
}  // namespace Homa

#endif  // HOMA_CORE_SENDER_H
