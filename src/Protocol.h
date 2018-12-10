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

#ifndef HOMA_PROTOCOL_H
#define HOMA_PROTOCOL_H

#include <cstdint>
#include <functional>

namespace Homa {

/**
 * Defines the headers used in all Homa packets.
 */
namespace Protocol {

/**
 * This enum defines the opcode field values for packets. See the * xxxHeader
 * class definitions below for more information about each kind of packet
 */
enum PacketOpcode {
    DATA = 21,
    GRANT = 22,
};

/**
 * A unique identifier for the operation.
 */
struct OpId {
    uint64_t transportId;  ///< Uniquely identifies the client transport for
                           ///< this RemoteOp.
    uint64_t sequence;     ///< Sequence number for this RemoteOp (unique for
                           ///< transportId, monotonically increasing).

    /// MessageId constructor.
    OpId(uint64_t transportId, uint64_t sequence)
        : transportId(transportId)
        , sequence(sequence)
    {}

    /**
     * Comparison function for OpId, for use in std::maps etc.
     */
    bool operator<(OpId other) const
    {
        return (transportId < other.transportId) ||
               ((transportId == other.transportId) &&
                (sequence < other.sequence));
    }

    /**
     * Equality function for OpId, for use in std::unordered_maps etc.
     */
    bool operator==(OpId other) const
    {
        return ((transportId == other.transportId) &&
                (sequence == other.sequence));
    }

    /**
     * This class computes a hash of an OpId, so that OpId can be used
     * as keys in unordered_maps.
     */
    struct Hasher {
        /// Return a "hash" of the given OpId.
        std::size_t operator()(const OpId& opId) const
        {
            std::size_t h1 = std::hash<uint64_t>()(opId.transportId);
            std::size_t h2 = std::hash<uint64_t>()(opId.sequence);
            return h1 ^ (h2 << 1);
        }
    };
} __attribute__((packed));

/**
 * A unique identifier for a Message within an Operation.
 */
struct MessageId : public OpId {
    uint32_t messageId;  ///< Unique identifies this Message within the set
                         ///< of messages that belong to the RemoteOp.

    /// sequence number for the Message that contains a RemoteOp's initiating
    /// request RemoteOp (sent by the client).
    static const uint32_t INITIAL_REQUEST_ID = 1;
    /// sequence number for the Message that contains the final reply to the
    /// initial request (sent to the client).
    static const uint32_t ULTIMATE_RESPONSE_ID = 0;

    /// MessageId constructor.
    MessageId(uint64_t transportId, uint64_t sequence, uint32_t messageId = 1)
        : OpId(transportId, sequence)
        , messageId(messageId)
    {}

    /**
     * Comparison function for OpId, for use in std::maps etc.
     */
    bool operator<(MessageId other) const
    {
        return OpId::operator<(other) ||
               ((OpId::operator==(other)) && (messageId < other.messageId));
    }

    /**
     * Equality function for OpId, for use in std::unordered_maps etc.
     */
    bool operator==(MessageId other) const
    {
        return (OpId::operator==(other)) && (messageId == other.messageId);
    }

    /**
     * This class computes a hash of an MessageId, so that MessageId can be used
     * as keys in unordered_maps.
     */
    struct Hasher : public OpId::Hasher {
        /// Return a "hash" of the given MessageId.
        std::size_t operator()(const MessageId& msgId) const
        {
            std::size_t h1 = OpId::Hasher::operator()(msgId);
            std::size_t h2 = std::hash<uint64_t>()(msgId.messageId);
            return h1 ^ (h2 << 1);
        }
    };
} __attribute__((packed));

/**
 * This is the first part of the Homa packet header and is common to all
 * versions of the protocol. The struct contains version information about the
 * protocol used in the encompassing packet. The Transport should always send
 * this prefix and can always expect it when receiving a Homa packet. The prefix
 * is seperated into its own struct becuase the Transport may need to know the
 * protocol version before interpreting the rest of the packet.
 */
struct HeaderPrefix {
    uint8_t version;  ///< The version of the protocol being used by this
                      ///< packet.

    /// HeaderPrefix constructor.
    HeaderPrefix(uint8_t version)
        : version(version)
    {}
} __attribute__((packed));

/**
 * Describes the wire format for header fields that are common to all packet
 * types.
 */
struct CommonHeader {
    HeaderPrefix prefix;  ///< Common to all versions of the protocol.
    uint8_t opcode;       ///< One of the values of PacketOpcode.
    MessageId messageId;  ///< RemoteOp/Message associated with this packet.

    /// CommonHeader constructor.
    CommonHeader(PacketOpcode opcode, MessageId messageId)
        : prefix(1)
        , opcode(opcode)
        , messageId(messageId)
    {}
} __attribute__((packed));

/**
 * Describes the wire format for GRANT packets. A GRANT is sent by
 * the receiver back to the sender to indicate that it is now safe
 * for the sender to transmit a given range of bytes in the message.
 * This packet type is used for flow control.
 */
struct GrantHeader {
    CommonHeader common;  ///< Common header fields.
    uint32_t offset;      ///< Byte offset within the message; the
                          ///< sender should now transmit all data up
                          ///< to (but not including) this offset, if
                          ///< it hasn't already.

    /// GrantHeader constructor.
    GrantHeader(MessageId messageId, uint32_t offset)
        : common(PacketOpcode::GRANT, messageId)
        , offset(offset)
    {}
} __attribute__((packed));

/**
 * Describes the wire format for a DATA packet, which contains a portion of
 * a request or response message
 */
struct DataHeader {
    CommonHeader common;   ///< Common header fields.
    uint32_t totalLength;  ///< Total # bytes in the message (*not* just in this
                           ///< packet).
    uint16_t index;  ///< Index of this packet in the array of packets that form
                     ///< the message. With the know packet data length, the
                     ///< index can by computed given the packet's byte offset
                     ///< into the message and vice versa.

    // The remaining packet bytes after the header constitute message data
    // starting at the offset corresponding to the given packet index.

    /// DataHeader constructor.
    DataHeader(MessageId messageId, uint32_t totalLength, uint16_t index)
        : common(PacketOpcode::DATA, messageId)
        , totalLength(totalLength)
        , index(index)
    {}
} __attribute__((packed));

}  // namespace Protocol
}  // namespace Homa

#endif  // HOMA_PROTOCOL_H