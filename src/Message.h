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

#ifndef HOMA_CORE_MESSAGE_H
#define HOMA_CORE_MESSAGE_H

#include <Homa/Homa.h>

#include "Protocol.h"

#include <bitset>

namespace Homa {
namespace Core {

/**
 * The Message holds the Driver::Packet objects and metadata that make up
 * a Homa::Message.  The Message manages the lifetimes of held Packet objects.
 *
 * This class is not thread-safe but should only be modified by one part of
 * the transport a time.
 */
class Message : public Homa::Message {
  public:
    /// Define the maximum number of packets that a message can hold.
    static const uint16_t MAX_MESSAGE_PACKETS = 1024;

    explicit Message(Protocol::MessageId msgId, Driver* driver,
                     uint16_t packetHeaderLength, uint32_t messageLength = 0);
    ~Message();

    virtual void append(const void* source, uint32_t num);
    virtual uint32_t get(uint32_t offset, void* destination,
                         uint32_t num) const;
    virtual uint32_t length() const;

    Driver::Packet* getPacket(uint16_t index) const;
    bool setPacket(uint16_t index, Driver::Packet* packet);
    uint16_t getNumPackets() const;

    uint32_t rawLength() const;

    /**
     * Define this Message to have a header of type MessageHeader.  Used by
     * senders to construct outbound messages.  This method should only be
     * called once.
     *
     * @return
     *      Return a pointer to a contiguous memory region where the defined
     *      header can be stored.
     */
    template <typename MessageHeader>
    MessageHeader* defineHeader()
    {
        MESSAGE_HEADER_LENGTH = sizeof(MessageHeader);
        // As an optimization, assume the header fits within the first packet of
        // the message.
        assert(MESSAGE_HEADER_LENGTH <= PACKET_DATA_LENGTH);
        messageLength = std::max(messageLength, MESSAGE_HEADER_LENGTH);
        return getHeader<MessageHeader>();
    }

    /**
     * Return a pointer to a contiguous memory region where the header of type
     * MessageHeader is assumed to be stored.  Used by receivers to read the
     * header of inbound messages.
     */
    template <typename MessageHeader>
    MessageHeader* getHeader()
    {
        // As an optimization, assume the header fits within the first packet of
        // the message.
        assert(sizeof(MessageHeader) <= PACKET_DATA_LENGTH);
        return reinterpret_cast<MessageHeader*>(getHeader());
    }

    /// Contains the unique identifier for this message.
    const Protocol::MessageId msgId;

    /// Contains the source address for a received message and the destination
    /// for a sent message.
    Driver::Address* address;

    /// Driver from which packets were allocated and to which they should be
    /// returned when this message is no longer needed.
    Driver* const driver;

    /// Number of bytes used per packet for the Homa protocol packet header.
    const uint16_t PACKET_HEADER_LENGTH;

    /// Number of bytes of data in each full packet.
    const uint16_t PACKET_DATA_LENGTH;

  private:
    /// Number of bytes used at the beginning of the Message for the Homa
    /// protocol Message header.
    uint32_t MESSAGE_HEADER_LENGTH;

    /// Number of bytes in this Message including the header.
    uint32_t messageLength;

    /// Number of packets contained in this context.
    uint16_t numPackets;

    /// Bit array representing which entires in the _packets_ array are set.
    /// Used to avoid having to zero out the entire _packets_ array.
    std::bitset<MAX_MESSAGE_PACKETS> occupied;

    /// Collection of Packet objects that make up this context's Message.
    /// These Packets will be released when this context is destroyed.
    Driver::Packet* packets[MAX_MESSAGE_PACKETS];

    Driver::Packet* getOrAllocPacket(uint16_t index);
    void* getHeader();

    Message(const Message&) = delete;
    Message& operator=(const Message&) = delete;
};

}  // namespace Core
}  // namespace Homa

#endif  // HOMA_CORE_MESSAGE_H