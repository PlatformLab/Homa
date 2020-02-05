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

/**
 * @file Protocol.h
 *
 * This file contains wire protocol definitions for RemoteOp messages.
 */

#ifndef HOMA_INCLUDE_HOMA_PROTOCOL_H
#define HOMA_INCLUDE_HOMA_PROTOCOL_H

#include <Homa/Driver.h>

#include <cstdint>
#include <functional>

namespace Homa {
namespace Protocol {

/**
 * A unique identifier for the operation.
 */
struct OpId {
    uint64_t transportId;  ///< Uniquely identifies the client transport for
                           ///< this RemoteOp.
    uint64_t sequence;     ///< Sequence number for this RemoteOp (unique for
                           ///< transportId, monotonically increasing).

    /// OpId default constructor.
    OpId()
        : transportId(0)
        , sequence(0)
    {}

    /// OpId constructor.
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
 * Contains the header definitions for a Homa Message; one Op will involve
 * the sending and receiving of two or more messages.
 */
namespace Message {

/// Identifier for the Message that contains a RemoteOp's initiating request
/// RemoteOp (sent by the client).
static const int32_t INITIAL_REQUEST_ID = 0;
/// Identifier for the Message that contains the final reply to the
/// initial request (sent to the client).
static const int32_t ULTIMATE_RESPONSE_ID = -1;

/**
 * This is the first part of the Homa packet header and is common to all
 * versions of the protocol. The struct contains version information about the
 * protocol used in the encompassing Message. The Transport should always send
 * this prefix and can always expect it when receiving a Homa Message. The
 * prefix is separated into its own struct because the Transport may need to
 * know the protocol version before interpreting the rest of the packet.
 */
struct HeaderPrefix {
    uint8_t version;  ///< The version of the protocol being used by this
                      ///< Message.

    /// HeaderPrefix constructor.
    HeaderPrefix(uint8_t version)
        : version(version)
    {}
} __attribute__((packed));

/**
 * Describes the wire format for header fields for all Message.
 */
struct Header {
    HeaderPrefix prefix;  ///< Common to all versions of the protocol.
    OpId opId;            ///< Id of the Op to which this message belongs.
    int32_t stageId;  ///< Uniquely identifies this Message within the set of
                      ///< messages that belong to the RemoteOp.
    Driver::WireFormatAddress replyAddress;  ///< Replies to this Message should
                                             ///< be sent to this address.

    /// CommonHeader default constructor.
    Header()
        : prefix(1)
        , opId()
        , stageId()
        , replyAddress()
    {}

    /// CommonHeader constructor.
    explicit Header(OpId opId, int32_t stageId)
        : prefix(1)
        , opId(opId)
        , stageId(stageId)
        , replyAddress()
    {}
} __attribute__((packed));

}  // namespace Message
}  // namespace Protocol
}  // namespace Homa

#endif  // HOMA_INCLUDE_HOMA_PROTOCOL_H
