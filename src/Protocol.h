/* Copyright (c) 2018-2020, Stanford University
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
 * Defines the wire format structures used in Homa protocol.
 *
 * The Protocol defines headers both at the Packet level as well as at the
 * Message level.  Packet level headers contain information to process each
 * individual packet.  In contrast, Message level headers contain information
 * needed to process the Message but aren't needed to process each individual
 * packet.  This separation reduces Homa's protocol overhead by only including
 * Message level headers once per Message.
 */
namespace Protocol {

/**
 * A unique identifier for a Message sent or received by the transport.
 */
struct MessageId {
    uint64_t transportId;  ///< Uniquely identifies the sending transport for
                           ///< this message.
    uint64_t sequence;     ///< Sequence number for this message (unique for
                           ///< transportId, monotonically increasing).

    /// MessageId default constructor.
    MessageId() = default;

    /// MessageId constructor.
    MessageId(uint64_t transportId, uint64_t sequence)
        : transportId(transportId)
        , sequence(sequence)
    {}

    /**
     * Comparison function for MessageId, for use in std::maps etc.
     */
    bool operator<(MessageId other) const
    {
        return (transportId < other.transportId) ||
               ((transportId == other.transportId) &&
                (sequence < other.sequence));
    }

    /**
     * Equality function for MessageId, for use in std::unordered_maps etc.
     */
    bool operator==(MessageId other) const
    {
        return ((transportId == other.transportId) &&
                (sequence == other.sequence));
    }

    /**
     * This class computes a hash of an MessageId, so that MessageId can be used
     * as keys in unordered_maps.
     */
    struct Hasher {
        /// Return a "hash" of the given MessageId.
        std::size_t operator()(const MessageId& messageId) const
        {
            std::size_t h1 = std::hash<uint64_t>()(messageId.transportId);
            std::size_t h2 = std::hash<uint64_t>()(messageId.sequence);
            return h1 ^ (h2 << 1);
        }
    };
} __attribute__((packed));

/**
 * Contains the header definitions for Homa packets.
 */
namespace Packet {

/**
 * This enum defines the opcode field values for packets. See the xxxHeader
 * class definitions below for more information about each kind of packet
 */
enum Opcode {
    DATA = 21,
    GRANT = 22,
    DONE = 23,
    RESEND = 24,
    BUSY = 25,
    PING = 26,
    UNKNOWN = 27,
    ERROR = 28,
};

/**
 * This is the first part of the Homa packet header and is common to all
 * versions of the protocol. The first four bytes of the header store the source
 * and destination ports, which is common for many transport layer protocols
 * (e.g., TCP, UDP, etc.) The struct also contains version information about the
 * protocol used in the encompassing packet. The Transport should always send
 * this prefix and can always expect it when receiving a Homa packet. The prefix
 * is separated into its own struct because the Transport may need to know the
 * protocol version before interpreting the rest of the packet.
 */
struct HeaderPrefix {
    uint16_t sport,
        dport;        ///< Transport layer (L4) source and destination ports
                      ///< in network byte order; only used by DataHeader.
    uint8_t version;  ///< The version of the protocol being used by this
                      ///< packet.

    /// HeaderPrefix constructor.
    HeaderPrefix(uint16_t sport, uint16_t dport, uint8_t version)
        : sport(sport)
        , dport(dport)
        , version(version)
    {}
} __attribute__((packed));

/**
 * Describes the wire format for header fields that are common to all packet
 * types.
 */
struct CommonHeader {
    HeaderPrefix prefix;  ///< Common to all versions of the protocol.
    uint8_t opcode;       ///< One of the values of Opcode.
    MessageId messageId;  ///< RemoteOp/Message associated with this packet.

    /// CommonHeader constructor.
    CommonHeader(Opcode opcode, MessageId messageId)
        : prefix(0, 0, 1)
        , opcode(opcode)
        , messageId(messageId)
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
    uint8_t policyVersion;  ///< Version of the network priority policy being
                            ///< used by the Sender.
    uint16_t unscheduledIndexLimit;  ///< Packets with an index up to (but not
                                     ///< including) this value will be sent
                                     ///< without being granted.
    uint16_t index;  ///< Index of this packet in the array of packets that form
                     ///< the message.

    // The remaining packet bytes after the header constitute message data
    // starting at the offset corresponding to the given packet index.

    /// DataHeader constructor.
    DataHeader(uint16_t sport, uint16_t dport, MessageId messageId,
               uint32_t totalLength, uint8_t policyVersion,
               uint16_t unscheduledIndexLimit, uint16_t index)
        : common(Opcode::DATA, messageId)
        , totalLength(totalLength)
        , policyVersion(policyVersion)
        , unscheduledIndexLimit(unscheduledIndexLimit)
        , index(index)
    {
        common.prefix.sport = htobe16(sport);
        common.prefix.dport = htobe16(dport);
    }
} __attribute__((packed));

/**
 * Describes the wire format for GRANT packets. A GRANT is sent by the receiver
 * back to the sender to indicate that it is now safe for the sender to transmit
 * a given range of DATA packets in the message. This packet type is used for
 * flow control.
 */
struct GrantHeader {
    CommonHeader common;  ///< Common header fields.
    uint32_t byteLimit;   ///< The cumulative number of bytes of the associated
                          ///< message that can be transmitted by the sender.
    uint8_t priority;     ///< The network priority the sender should use to
                          ///< transmit the associated message.

    /// GrantHeader constructor.
    GrantHeader(MessageId messageId, uint32_t byteLimit, uint8_t priority)
        : common(Opcode::GRANT, messageId)
        , byteLimit(byteLimit)
        , priority(priority)
    {}
} __attribute__((packed));

/**
 * Describes the wire format for a DONE packet.  The DONE packet is sent by a
 * Receiver on behalf of its application to signal that a particular Message
 * has been delivered to and processed by the application.  The transport will
 * try to ensure reliable delivery of a Message until DONE is received.
 */
struct DoneHeader {
    CommonHeader common;  ///< Common header fields.

    /// DoneHeader constructor.
    DoneHeader(MessageId messageId)
        : common(Opcode::DONE, messageId)
    {}
} __attribute__((packed));

/**
 * Describes the wire format for a RESEND packet.  The RESEND packet is used by
 * the receiver to request that a particular range of packets within a Message
 * be resent.
 */
struct ResendHeader {
    CommonHeader common;  ///< Common header fields.
    uint16_t index;  ///< Index of the first packet that should be resent among
                     ///< the array of packets that form the message.
    uint16_t num;  ///< Number of packet in the range of packets that should be
                   ///< resent starting with the packet at _index_.
    uint8_t priority;  ///< The granted priority if this RESEND is interpreted
                       ///< as a GRANT.  (See GrantHeader.priority)

    /// DoneHeader constructor.
    ResendHeader(MessageId messageId, uint16_t index, uint16_t num,
                 uint8_t priority)
        : common(Opcode::RESEND, messageId)
        , index(index)
        , num(num)
        , priority(priority)
    {}
} __attribute__((packed));

/**
 * Describes the wire format for a BUSY packet.  The BUSY packet is used by the
 * sender to indicate to the receiver that it is currently busy and is not
 * sending DATA for this particular message.  Responds to a RESEND.
 */
struct BusyHeader {
    CommonHeader common;  ///< Common header fields.

    /// BusyHeader constructor.
    BusyHeader(MessageId messageId)
        : common(Opcode::BUSY, messageId)
    {}
} __attribute__((packed));

/**
 * Describes the wire format for a PING packet.  The PING packet used to ensure
 * that a particular Message is still actively being processed and will not be
 * timed out.
 */
struct PingHeader {
    CommonHeader common;  ///< Common header fields.

    /// PingHeader constructor.
    PingHeader(MessageId messageId)
        : common(Opcode::PING, messageId)
    {}
} __attribute__((packed));

/**
 * Describes the wire format for a UNKNOWN packet.  The UNKNOWN packet is used
 * to indicate that the receiver has no knowledge a particular Message.  For
 * example, a receiver might reply UNKNOWN if it received a PING for a message
 * that timed out or was never received.
 */
struct UnknownHeader {
    CommonHeader common;  ///< Common header fields.

    /// UnknownHeader constructor.
    UnknownHeader(MessageId messageId)
        : common(Opcode::UNKNOWN, messageId)
    {}
} __attribute__((packed));

/**
 * Describes the wire format for a ERROR packet.  The ERROR packet is used to
 * indicate that the Operation associated with a particular Message has
 * encountered a transport level error.
 */
struct ErrorHeader {
    CommonHeader common;  ///< Common header fields.

    /// ErrorHeader constructor.
    ErrorHeader(MessageId messageId)
        : common(Opcode::ERROR, messageId)
    {}
} __attribute__((packed));

}  // namespace Packet
}  // namespace Protocol
}  // namespace Homa

#endif  // HOMA_PROTOCOL_H
