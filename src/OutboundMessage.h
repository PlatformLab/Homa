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

#ifndef HOMA_CORE_OUTBOUNDMESSAGE_H
#define HOMA_CORE_OUTBOUNDMESSAGE_H

#include <Homa/Driver.h>

#include "Message.h"
#include "Protocol.h"
#include "SpinLock.h"
#include "Timeout.h"

namespace Homa {
namespace Core {
class Sender;

/**
 * Represents an outgoing message that can be sent.
 *
 * OutboundMessage objects are contained in the Transport::Op but should only
 * be accessed by the Sender.
 */
class OutboundMessage : public Message {
  public:
    /**
     * Defines the possible states of this OutboundMessage.
     */
    enum class State {
        NOT_STARTED,  //< This message has not yet been passed to Sender.
        IN_PROGRESS,  //< Sender is in the process of sending this message.
        SENT,         //< Sender has sent out every packet of the message.
        COMPLETED,    //< Receiver has acknowledged receipt of this message.
        FAILED,       //< Sender failed to send out this message.
    };

    /**
     * Construct an OutboundMessage.
     */
    explicit OutboundMessage(Driver* driver, void* op)
        : Message(driver, sizeof(Protocol::Packet::DataHeader), 0)
        , mutex()
        , id(0, 0)
        , destination(nullptr)
        , state(OutboundMessage::State::NOT_STARTED)
        , grantIndex(0)
        , sentIndex(0)
        , rawUnsentBytes(0)
        , op(op)
        , readyQueueNode(this)
        , messageTimeout(this)
        , pingTimeout(this)
    {}

    /**
     * Return the current state of this message.
     */
    State getState() const
    {
        return state.load();
    }

  private:
    /// Monitor style lock.
    mutable SpinLock mutex;
    /// Contains the unique identifier for this message.
    Protocol::MessageId id;
    /// Contains destination address this message.
    Driver::Address* destination;
    /// This message's current state.
    std::atomic<State> state;
    /// Packets up to (but excluding) this index can be sent.
    uint16_t grantIndex;
    /// Packets up to (but excluding) this index have been sent.
    uint16_t sentIndex;
    /// The number of bytes (including DataHeader bytes) that still need to be
    /// sent for this Message.
    uint32_t rawUnsentBytes;
    /// Transport::Op associated with this message.
    void* const op;
    /// Intrusive structure used by the Sender to keep track of this message
    /// when it has packets to send.
    Intrusive::List<OutboundMessage>::Node readyQueueNode;
    /// Intrusive structure used by the Sender to keep track when the sending of
    /// this message should be considered failed.
    Timeout<OutboundMessage> messageTimeout;
    /// Intrusive structure used by the Sender to keep track when this message
    /// should be checked to ensure progress is still being made.
    Timeout<OutboundMessage> pingTimeout;

    friend class Sender;
};

}  // namespace Core
}  // namespace Homa

#endif  // HOMA_CORE_OUTBOUNDMESSAGE_H
