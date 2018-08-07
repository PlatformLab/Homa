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

#ifndef HOMA_RPCPROTOCOL_H
#define HOMA_RPCPROTOCOL_H

#include <cstdint>
#include <cstdlib>
#include <functional>

namespace Homa {
namespace RpcProtocol {

/**
 * A unique identifier for an Rpc.
 */
struct RpcId {
    uint64_t managerId;  // Uniquely identifies the source manager for this Rpc.
    uint64_t sequence;   // Sequence number for this Rpc (unique for managerId,
                         // monotonically increasing).

    RpcId(uint64_t managerId, uint64_t sequence)
        : managerId(managerId)
        , sequence(sequence)
    {}

    /**
     * Comparison function for RpcId, for use in std::maps etc.
     */
    bool operator<(RpcId other) const
    {
        return (managerId < other.managerId) ||
               ((managerId == other.managerId) && (sequence < other.sequence));
    }

    /**
     * Equality function for RpcId, for use in std::unordered_maps etc.
     */
    bool operator==(RpcId other) const
    {
        return ((managerId == other.managerId) && (sequence == other.sequence));
    }

    /**
     * This class computes a hash of an RpcId, so that RpcId can be used
     * as keys in unordered_maps.
     */
    struct Hasher {
        std::size_t operator()(const RpcId& rpcId) const
        {
            std::size_t h1 = std::hash<uint64_t>()(rpcId.managerId);
            std::size_t h2 = std::hash<uint64_t>()(rpcId.sequence);
            return h1 ^ (h2 << 1);
        }
    };
} __attribute__((packed));

/**
 * Describes the wire format header fields for all RPCs.
 */
struct RpcHeader {
    RpcId rpcId;      // Unique identifier for this RPC
    bool fromClient;  // true for requests from clients, false for responses
                      // from the server.

    RpcHeader()
        : rpcId(0, 0)
        , fromClient(false)
    {}

    RpcHeader(uint64_t managerId, uint64_t sequence, bool fromClient)
        : rpcId(managerId, sequence)
        , fromClient(fromClient)
    {}
} __attribute__((packed));

}  // namespace RpcProtocol
}  // namespace Homa

#endif  // HOMA_RPCPROTOCOL_H
