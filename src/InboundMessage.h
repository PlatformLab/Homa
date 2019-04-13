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

#ifndef HOMA_CORE_INBOUNDMESSAGE_H
#define HOMA_CORE_INBOUNDMESSAGE_H

#include "Message.h"
#include "Protocol.h"
#include "SpinLock.h"
#include "Tub.h"

namespace Homa {
namespace Core {

class Receiver;

/**
 * Represents an incoming message that is being assembled or being processed
 * by the application.
 *
 * InboundMessage objects are held in the Transport::Op but should only be
 * accessed by the Receiver.
 */
class InboundMessage {
  public:
    InboundMessage()
        : mutex()
        , id(0, 0, 0)
        , source(nullptr)
        , numExpectedPackets(0)
        , grantIndexLimit(0)
        , message()
        , newPacket(false)
        , fullMessageReceived(false)
    {}

    /**
     * Return a pointer to a Message object that can be read by applications
     * of the Transport.  Otherwise, nullptr will be returned when no
     * Message is available.
     */
    Message* get()
    {
        SpinLock::Lock lock(mutex);
        return message.get();
    }

    /**
     * Return the unique identifier for this Message.
     */
    Protocol::MessageId getId()
    {
        return id;
    }

    /**
     * Return true if the InboundMessage has been received; false otherwise.
     */
    bool isReady() const
    {
        SpinLock::Lock lock(mutex);
        return fullMessageReceived;
    }

  private:
    /// Monitor style lock.
    mutable SpinLock mutex;
    /// Contains the unique identifier for this message.
    Protocol::MessageId id;
    /// Contains source address this message.
    Driver::Address* source;
    /// Number of packets the message is expected to contain.
    uint16_t numExpectedPackets;
    /// The packet index up to which the Receiver as granted.
    uint16_t grantIndexLimit;
    /// Collection of packets being received.
    Tub<Message> message;
    /// Marked true when a new data packet arrives; cleared by the scheduler.
    bool newPacket;
    /// True if all packets of the message have been received.
    bool fullMessageReceived;

    friend class Receiver;
};

}  // namespace Core
}  // namespace Homa

#endif  // HOMA_CORE_INBOUNDMESSAGE_H
