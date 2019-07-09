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

#include <Homa/Driver.h>

#include "Intrusive.h"
#include "Message.h"
#include "Protocol.h"
#include "SpinLock.h"
#include "Timeout.h"

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
class InboundMessage : public Message {
  public:
    /**
     * Defines the possible states of this InboundMessage.
     */
    enum class State {
        IN_PROGRESS,  //< Receiver is in the process of receiving this message.
        COMPLETED,    //< Receiver has received the entire message.
        DROPPED,      //< Message was COMPLETED but the Receiver has lost
                      //< communication with the Sender.
    };

    explicit InboundMessage(Driver* driver, uint16_t packetHeaderLength,
                            uint32_t messageLength)
        : Message(driver, packetHeaderLength, messageLength)
        , mutex()
        , id(0, 0)
        , source(nullptr)
        , numExpectedPackets(0)
        , grantIndexLimit(0)
        , state(InboundMessage::State::IN_PROGRESS)
        , newPacket(false)
        , op(nullptr)
        , receivedMessageNode(this)
        , messageTimeout(this)
        , resendTimeout(this)
    {}

    /**
     * Associate a particular Transport::Op with this Message.  Allows the
     * receiver to single the Transport about this Message when update occur.
     */
    void registerOp(void* op)
    {
        SpinLock::Lock lock(mutex);
        this->op = op;
    }

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
    /// Contains source address this message.
    Driver::Address* source;
    /// Number of packets the message is expected to contain.
    uint16_t numExpectedPackets;
    /// The packet index up to which the Receiver as granted.
    uint16_t grantIndexLimit;
    /// This message's current state.
    std::atomic<State> state;
    /// Marked true when a new data packet arrives; cleared by the scheduler.
    bool newPacket;
    /// Transport::Op associated with this message.
    void* op;
    /// Intrusive structure used by the Receiver to keep track of this message
    /// when it has been completely received.
    Intrusive::List<InboundMessage>::Node receivedMessageNode;
    /// Intrusive structure used by the Receiver to keep track when the
    /// receiving of this message should be considered failed.
    Timeout<InboundMessage> messageTimeout;
    /// Intrusive structure used by the Receiver to keep track when unreceived
    /// parts of this message should be re-requested.
    Timeout<InboundMessage> resendTimeout;

    friend class Receiver;
};

}  // namespace Core
}  // namespace Homa

#endif  // HOMA_CORE_INBOUNDMESSAGE_H
