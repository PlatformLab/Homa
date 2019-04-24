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

namespace Homa {
namespace Core {
class Sender;

/**
 * Represents an outgoing message that can be sent.
 *
 * OutboundMessage objects are contained in the Transport::Op but should only
 * be accessed by the Sender.
 */
class OutboundMessage {
  public:
    /**
     * Construct an OutboundMessage.
     */
    explicit OutboundMessage(Driver* driver)
        : id(0, 0, 0)
        , destination(nullptr)
        , message(driver, sizeof(Protocol::Packet::DataHeader), 0)
        , grantIndex(0)
        , sentIndex(0)
        , sent(false)
        , acknowledged(true)
        , failed(false)
    {}

    /**
     * Return a pointer to a Message object that can be populated by
     * applications of the Transport.  Caller should take care not
     * to provide access to the returned Message while the Sender is
     * processing the Message.
     */
    Message* get()
    {
        return &message;
    }

    /**
     * True if this Message has finished processing; false, otherwise.
     */
    bool isDone()
    {
        return sent && acknowledged;
    }

    /**
     * True if this Message (or related delegated Message) has failed to send;
     * false, otherwise.
     */
    bool hasFailed() const
    {
        return failed;
    }

  private:
    /// Contains the unique identifier for this message.
    Protocol::MessageId id;
    /// Contains destination address this message.
    Driver::Address* destination;
    /// Collection of packets to be sent.
    Message message;
    /// Packets up to (but excluding) this index can be sent.
    uint16_t grantIndex;
    /// Packets up to (but excluding) this index have been sent.
    uint16_t sentIndex;
    /// True if this message has been fully sent; false, otherwise.
    bool sent;
    /// True if this message is no longer waiting for a DONE acknowledgement;
    /// false, otherwise.
    bool acknowledged;
    /// True if this message (or some delegated message down the line) has
    /// failed to send.
    bool failed;

    friend class Sender;
};

}  // namespace Core
}  // namespace Homa

#endif  // HOMA_CORE_OUTBOUNDMESSAGE_H
