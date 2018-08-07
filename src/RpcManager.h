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

#ifndef HOMA_RPCMANAGER_H
#define HOMA_RPCMANAGER_H

#include "Homa.h"
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
 * RpcManager coordinates the sending and receiving of request and response
 * Transport::Message objects for Rpc objects and ServerRpc objects.
 *
 * This class is thread-safe;
 */
class RpcManager {
  public:
    /**
     * RpcManager contstructor.
     *
     * @param transport
     *      Transport with which messages will be sent and received.
     * @param managerId
     *      Unique identifier for this RpcManager.
     */
    explicit RpcManager(Transport* transport, uint64_t managerId);

    /**
     * RpcManager destructor.
     */
    ~RpcManager();

    /**
     * Return an incoming ServerRpc if an incoming request is available.
     *
     * Called by server implmentations.
     */
    ServerRpc receiveServerRpc();

    /**
     * Make incremental progress mananging all incoming and outgoing RPCs. Must
     * be call periodically to ensure RPCs make progress.
     *
     * Called by both client and server implmentations.
     */
    void poll();

    /**
     * Return a new Transport::Message that can be used for an RPC request.
     *
     * Called by Rpc methods internally; not for application use.
     *
     * @param address
     *      Network address to which the RPC request should be sent.
     */
    Transport::Message newRequest(Driver::Address* address);

    /**
     * Send an RPC.
     *
     * Called by Rpc methods internally; not for application use.
     *
     * @parma rpc
     *      Pointer to the RPC to be sent.
     */
    void sendRpc(Rpc* rpc);

    /**
     * Send the response for a ServerRpc.
     *
     * Called by ServerRpc methods internally; not for application use.
     *
     * @param serverRpc
     *      ServerRpc's whose response should be sent.
     */
    void sendServerRpcResponse(ServerRpc* serverRpc);

  private:
    /// Transport with which this RpcManager will send and receive messages.
    Transport* const transport;

    /// Unique identifer for this RpcManager.
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
    std::deque<Transport::Message> requestQueue;
};

}  // namespace Homa

#endif  // HOMA_RPCMANAGER_H
