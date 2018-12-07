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

#include <Homa/Homa.h>

#include "OpContext.h"

namespace Homa {

RemoteOp::RemoteOp()
    : request(nullptr)
    , response(nullptr)
    , op(nullptr)
{}

RemoteOp::RemoteOp(RemoteOp&& other)
    : request(std::move(other.request))
    , response(std::move(other.response))
    , op(std::move(other.op))
{
    other.request = nullptr;
    other.response = nullptr;
    other.op = nullptr;
}

RemoteOp::~RemoteOp() {}

RemoteOp&
RemoteOp::operator=(RemoteOp&& other)
{
    request = std::move(other.request);
    response = std::move(other.response);
    op = std::move(other.op);
    other.request = nullptr;
    other.response = nullptr;
    other.op = nullptr;
    return *this;
}

RemoteOp::operator bool() const
{
    if (op != nullptr) {
        return true;
    } else {
        return false;
    }
}

void
RemoteOp::setDestination(Driver::Address* destination)
{
    if (op == nullptr) {
        return;
    }
    assert(op->outMessage);
    op->outMessage->address = destination;
}

void
RemoteOp::send()
{
    // TODO(cstlee): hook send into the transport
}

bool
RemoteOp::isReady()
{
    // TODO(cstlee): add thread-safe hook to test
    return false;
}

void
RemoteOp::wait()
{
    while (!isReady())
        ;
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

ServerOp::~ServerOp() {}

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
    // TODO(cstlee): hook send into the transport
}

void
ServerOp::deligate(Driver::Address* destination)
{
    assert(op->outMessage);
    op->outMessage->address = destination;
    // TODO(cstlee): hook send into the transport
}

}  // namespace Homa