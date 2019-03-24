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

#ifndef HOMA_CORE_OPCONTEXT_H
#define HOMA_CORE_OPCONTEXT_H

#include "Receiver.h"
#include "Sender.h"
#include "SpinLock.h"

namespace Homa {
namespace Core {

// forward declaration
class Transport;

/**
 * Holds all the relevant data and metadata for a RemoteOp or ServerOp.
 */
struct OpContext {
    /// The Core::Transport which manages this OpContext.
    Transport* const transport;

    /// True if this context is being held by the application in a RemoteOp or
    /// a ServerOp; otherwise, false.
    std::atomic<bool> retained;

    /// True if this context is for a ServerOp; false it is for a RemoteOp.
    const bool isServerOp;

    /// Possible states of the operation.
    enum class State {
        NOT_STARTED,
        IN_PROGRESS,
        COMPLETED,
        FAILED,
    };

    /// This operation's current state.
    std::atomic<State> state;

    /// Mutex for controlling internal access to OpContext members.
    SpinLock mutex;

    /// Message to be sent out as part of this Op.  Processed by the Sender.
    Sender::OutboundMessage outMessage;

    /// Message to be received as part of this Op.  Processed by the Receiver.
    std::atomic<Receiver::InboundMessage*> inMessage;

    explicit OpContext(Transport* transport, Driver* driver,
                       bool isServerOp = true)
        : transport(transport)
        , retained(false)
        , isServerOp(isServerOp)
        , state(State::NOT_STARTED)
        , mutex()
        , outMessage(driver)
        , inMessage(nullptr)
    {}
};

}  // namespace Core
}  // namespace Homa

#endif  // HOMA_CORE_OPCONTEXT_H
