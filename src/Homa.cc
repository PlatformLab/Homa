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

#include <Homa/Homa.h>

#include "OpContext.h"
#include "Transport.h"

namespace Homa {

RemoteOp::RemoteOp(Transport* transport)
    : request(nullptr)
    , response(nullptr)
    , op(transport->internal->allocOp())
{
    request = op->getOutMessage();
}

RemoteOp::~RemoteOp()
{
    op->transport->releaseOp(op);
}

void
RemoteOp::send(Driver::Address* destination)
{
    // Don't let applications touch the outbound message while it is being
    // processed by the Transport.
    request = nullptr;
    response = nullptr;
    op->transport->sendRequest(op, destination);
}

bool
RemoteOp::isReady()
{
    Core::OpContext::State state = op->state.load();
    switch (state) {
        case Core::OpContext::State::NOT_STARTED:
            // Fall through to IN_PROGRESS.
        case Core::OpContext::State::IN_PROGRESS:
            return false;
            break;
        case Core::OpContext::State::COMPLETED:
            // Grant access to the received response.
            response = op->getInMessage();
            // Fall through to FAILED.
        case Core::OpContext::State::FAILED:
            // Restore access to the request.
            request = op->getOutMessage();
            return true;
            break;
        default:
            ERROR("Unexpected operation state.");
            return false;
            break;
    }
}

void
RemoteOp::wait()
{
    while (!isReady()) {
        op->transport->poll();
    }
}

ServerOp::ServerOp()
    : request(nullptr)
    , response(nullptr)
    , op(nullptr)
{}

ServerOp::ServerOp(ServerOp&& other)
    : request(std::move(other.request))
    , response(std::move(other.response))
    , op(std::move(other.op))
{
    other.request = nullptr;
    other.response = nullptr;
    other.op = nullptr;
}

ServerOp::~ServerOp()
{
    if (op != nullptr) {
        op->transport->releaseOp(op);
    }
}

ServerOp&
ServerOp::operator=(ServerOp&& other)
{
    request = std::move(other.request);
    response = std::move(other.response);
    op = std::move(other.op);
    other.request = nullptr;
    other.response = nullptr;
    other.op = nullptr;
    return *this;
}

ServerOp::operator bool() const
{
    if (op != nullptr) {
        return true;
    } else {
        return false;
    }
}

void
ServerOp::reply()
{
    if (op != nullptr) {
        response = nullptr;
        op->transport->sendReply(op);
    } else {
        WARNING("Calling reply() on empty ServerOp; nothing will be sent.");
    }
}

void
ServerOp::delegate(Driver::Address* destination)
{
    if (op != nullptr) {
        response = nullptr;
        op->transport->sendRequest(op, destination);
    } else {
        WARNING("Calling delegate() on empty ServerOp; nothing will be sent.");
    }
}

Transport::Transport(Driver* driver, uint64_t transportId)
    : internal(new Core::Transport(driver, transportId))
{}

Transport::~Transport() = default;

ServerOp
Transport::receiveServerOp()
{
    ServerOp op;
    op.op = internal->receiveOp();
    if (op.op != nullptr) {
        op.request = op.op->getInMessage();
        op.response = op.op->getOutMessage();
    }
    return op;
}

Driver::Address*
Transport::getAddress(std::string const* const addressString)
{
    return internal->driver->getAddress(addressString);
}

void
Transport::poll()
{
    internal->poll();
}

}  // namespace Homa
