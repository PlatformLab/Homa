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

#ifndef HOMA_RPCMANAGERIMPL_H
#define HOMA_RPCMANAGERIMPL_H

#include "Homa/RpcManager.h"
#include "Homa/Transport.h"

#include "RpcProtocol.h"
#include "SpinLock.h"

#include <atomic>
#include <deque>
#include <unordered_map>

namespace Homa {

// Forward declare types to avoid including the header here.
class Rpc;
class ServerRpc;

/**
 * RpcManagerImpl coordinates the sending and receiving of request and response
 * Message objects for Rpc objects and ServerRpc objects.
 *
 * This class is thread-safe;
 */
class RpcManagerImpl : public RpcManager {
  public:
    explicit RpcManagerImpl(Transport* transport, uint64_t managerId);
    virtual ~RpcManagerImpl();
    virtual ServerRpc receiveServerRpc();
    virtual void poll();
    virtual Message newRequest(Driver::Address* address);
    virtual void sendRpc(Rpc* rpc);
    virtual void sendServerRpcResponse(ServerRpc* serverRpc);

  private:
    /// Transport with which this RpcManagerImpl will send and receive messages.
    Transport* const transport;

    /// Unique identifer for this RpcManagerImpl.
    const uint64_t managerId;

    /// RPC sequence number that should be used for the next outgoing RpcId.
    std::atomic<uint64_t> nextRpcId;

    /// Protects access to the _rpcMap_.
    SpinLock rpcMapMutex;

    /// Collection of outgoing RPC's awaiting responses.
    std::unordered_map<RpcProtocol::RpcId, Rpc*, RpcProtocol::RpcId::Hasher>
        rpcMap;

    /// Protects access to the _requestQueue_.
    SpinLock requestQueueMutex;

    /// Queue of incoming requests awaiting processing.
    std::deque<Message> requestQueue;
};

}  // namespace Homa

#endif  // HOMA_RPCMANAGERIMPL_H
