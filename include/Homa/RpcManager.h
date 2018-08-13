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

#include "Homa/Driver.h"
#include "Homa/Message.h"
#include "Homa/Transport.h"

namespace Homa {

// Forward declare types to avoid including the header here.
class Rpc;
class ServerRpc;

/**
 * RpcManager coordinates the sending and receiving of request and response
 * Message objects for Rpc objects and ServerRpc objects.
 *
 * This class is thread-safe;
 */
class RpcManager {
  public:
    /**
     * Return a newly constructed RpcManager.
     *
     * Caller is responsible for calling delete on the RpcManager.
     *
     * @param transport
     *      Transport with which messages will be sent and received.
     * @param managerId
     *      Unique identifier for this RpcManager.
     * @return
     *      Pointer to new RpcManager.
     */
    static RpcManager* newRpcManager(Transport* transport, uint64_t managerId);

    /**
     * Return an incoming ServerRpc if an incoming request is available.
     *
     * Called by server implmentations.
     */
    virtual ServerRpc receiveServerRpc() = 0;

    /**
     * Make incremental progress mananging all incoming and outgoing RPCs. Must
     * be call periodically to ensure RPCs make progress.
     *
     * Called by both client and server implmentations.
     */
    virtual void poll() = 0;

    /**
     * Return a new Transport::Message that can be used for an RPC request.
     *
     * Called by Rpc methods internally; not for application use.
     *
     * @param address
     *      Network address to which the RPC request should be sent.
     */
    virtual Message newRequest(Driver::Address* address) = 0;

    /**
     * Send an RPC.
     *
     * Called by Rpc methods internally; not for application use.
     *
     * @parma rpc
     *      Pointer to the RPC to be sent.
     */
    virtual void sendRpc(Rpc* rpc) = 0;

    /**
     * Send the response for a ServerRpc.
     *
     * Called by ServerRpc methods internally; not for application use.
     *
     * @param serverRpc
     *      ServerRpc's whose response should be sent.
     */
    virtual void sendServerRpcResponse(ServerRpc* serverRpc) = 0;
};

}  // namespace Homa

#endif  // HOMA_RPCMANAGER_H
