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

#include <atomic>

namespace Homa {
namespace Core {

// forward declaration
class Transport;

/**
 * Holds all the relevant data and metadata for a RemoteOp or ServerOp.
 */
struct OpContext {
    /// Constructor.
    explicit OpContext(Transport* transport)
        : transport(transport)
        , state(State::NOT_STARTED)
    {}

    /// Return a pointer to the Outbound Message.
    virtual Message* getOutMessage() = 0;

    /// Return a pointer to the Inbound Message.
    virtual const Message* getInMessage() = 0;

    /// The Core::Transport which manages this OpContext.
    Transport* const transport;

    /// Possible states of the operation.
    enum class State {
        NOT_STARTED,
        IN_PROGRESS,
        COMPLETED,
        FAILED,
    };

    /// This operation's current state.
    std::atomic<State> state;
};

}  // namespace Core
}  // namespace Homa

#endif  // HOMA_CORE_OPCONTEXT_H
