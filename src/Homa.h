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

#ifndef HOMA_HOMA_H
#define HOMA_HOMA_H

#include <Homa/Homa.h>

#include <atomic>
#include <cstdint>
#include <deque>
#include <unordered_map>

#include "Protocol.h"
#include "SpinLock.h"

namespace Homa {
/**
 * Contains the private members of Homa::Transport so they are not exposed to
 * users of the library.
 */
struct TransportInternal {
    /**
     * Constructor.
     */
    explicit TransportInternal(uint64_t transportId)
        : mutex()
        , transportId(transportId)
        , nextOpSequenceNumber(1)
        , remoteOps()
        , pendingServerOps()
        , detachedServerOps()
    {}

    /**
     * Destructor.
     */
    ~TransportInternal() {}

    // Monitor style mutex.
    SpinLock mutex;

    /// Unique identifier for this transport.
    const uint64_t transportId;

    /// Unique identifier for the next RemoteOp this transport sends.
    uint64_t nextOpSequenceNumber;

    /// Tracks the set of RemoteOp objects that were initiated by this Transport
    std::unordered_map<Protocol::OpId, RemoteOp*, Protocol::OpId::Hasher>
        remoteOps;

    /// Collection of ServerOp objects (incoming requests) that haven't been
    /// requested by the application.
    std::deque<ServerOp> pendingServerOps;

    /// ServerOp that have been remanded to the care of the Transport to
    /// complete its progress.
    std::deque<ServerOp> detachedServerOps;
};

}  // namespace Homa

#endif  // HOMA_HOMA_H
