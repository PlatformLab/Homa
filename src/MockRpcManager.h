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

#ifndef HOMA_MOCKRPCMANAGER_H
#define HOMA_MOCKRPCMANAGER_H

#include <gmock/gmock.h>

#include <Homa/RpcManager.h>

#include <Homa/Rpc.h>
#include <Homa/ServerRpc.h>

namespace Homa {

/**
 * MockRpcManager is a gmock supported mock implmentation of RpcManager that is
 * used in unit testing.
 *
 * @sa RpcManager
 */
class MockRpcManager : public RpcManager {
  public:
    MOCK_METHOD0(receiveServerRpc, ServerRpc());
    MOCK_METHOD0(poll, void());
    MOCK_METHOD1(newRequest, Message(Driver::Address* address));
    MOCK_METHOD1(sendRpc, void(Rpc* rpc));
    MOCK_METHOD1(sendServerRpcResponse, void(ServerRpc* serverRpc));
};

}  // namespace Homa

#endif  // HOMA_RPCMANAGER_H
