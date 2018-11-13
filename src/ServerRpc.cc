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

#include "Homa/ServerRpc.h"

#include "Homa/RpcManager.h"

#include <algorithm>

namespace Homa {

ServerRpc::ServerRpc()
    : request()
    , response()
    , manager()
{}

ServerRpc::ServerRpc(ServerRpc&& other)
    : request(std::move(other.request))
    , response(std::move(other.response))
    , manager(std::move(other.manager))
{
    other.manager = nullptr;
}

ServerRpc::~ServerRpc() {}

ServerRpc&
ServerRpc::operator=(ServerRpc&& other)
{
    request = std::move(other.request);
    response = std::move(other.response);
    manager = std::move(other.manager);
    other.manager = nullptr;
    return *this;
}

ServerRpc::operator bool() const
{
    return request.operator bool();
}

void
ServerRpc::sendResponse()
{
    manager->sendServerRpcResponse(this);
}

}  // namespace Homa