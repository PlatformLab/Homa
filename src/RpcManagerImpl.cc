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

#include "RpcManagerImpl.h"

#include "Homa/Rpc.h"
#include "Homa/ServerRpc.h"

#include "Debug.h"

#include <mutex>

namespace Homa {

/**
 * RpcManagerImpl constructor.
 *
 * @param transport
 *      Transport with which messages will be sent and received.
 * @param managerId
 *      Unique identifier for this RpcManagerImpl.
 */
RpcManagerImpl::RpcManagerImpl(Transport* transport, uint64_t managerId)
    : transport(transport)
    , managerId(managerId)
    , nextRpcId(1)
    , rpcMapMutex()
    , rpcMap()
    , requestQueueMutex()
    , requestQueue()
{}

/**
 * RpcManagerImpl destructor.
 */
RpcManagerImpl::~RpcManagerImpl() {}

/// See Homa::RpcManager::receiveServerRpc()
ServerRpc
RpcManagerImpl::receiveServerRpc()
{
    ServerRpc serverRpc;
    {
        std::lock_guard<SpinLock> lock(requestQueueMutex);
        if (!requestQueue.empty()) {
            serverRpc.request = std::move(requestQueue.front());
            requestQueue.pop_front();
        }
    }
    // Finsh populating the ServerRpc without the requestQueueMutex.
    if (serverRpc.request) {
        serverRpc.response = transport->newMessage();
        serverRpc.manager = this;

        // add header to response
        RpcProtocol::RpcHeader header;
        serverRpc.request.get(0, &header, sizeof(header));
        header.fromClient = false;
        serverRpc.response.set(0, &header, sizeof(header));
        serverRpc.response.setDestination(serverRpc.request.getAddress());
    }
    return serverRpc;
}

/// See Homa::RpcManager::poll()
void
RpcManagerImpl::poll()
{
    processMessage(transport->receiveMessage());
    transport->poll();
}

/// See Homa::RpcManager::newRequest()
Message
RpcManagerImpl::newRequest(Driver::Address* address)
{
    RpcProtocol::RpcHeader header(managerId, nextRpcId.fetch_add(1), true);
    Message request = transport->newMessage();
    request.set(0, &header, sizeof(header));
    request.setDestination(address);
    return request;
}

/// See Homa::RpcManager::sendRpc()
void
RpcManagerImpl::sendRpc(Rpc* rpc)
{
    {
        std::lock_guard<SpinLock> lock(rpcMapMutex);
        RpcProtocol::RpcHeader header;
        rpc->request.get(0, &header, sizeof(header));
        auto it = rpcMap.find(header.rpcId);
        if (it == rpcMap.end()) {
            rpcMap.insert({header.rpcId, rpc});
        } else {
            WARNING(
                "duplicate call to sendRpc for id (%lu:%lu); request dropped.",
                header.rpcId.managerId, header.rpcId.sequence);
            return;
        }
    }
    // Don't need to hold the rpcMapMutex while sending.
    rpc->request.send(SEND_NO_ACK | SEND_EXPECT_RESPONSE);
}

/// See Homa::RpcManager::sendServerRpcResponse()
void
RpcManagerImpl::sendServerRpcResponse(ServerRpc* serverRpc)
{
    Message* request = &(serverRpc->request);
    Message* response = &(serverRpc->response);
    response->send(SEND_NO_ACK | SEND_DETACHED, &request, 1);
}

void
RpcManagerImpl::processMessage(Message message)
{
    if (message) {
        RpcProtocol::RpcHeader header;
        message.get(0, &header, sizeof(header));

        if (header.fromClient) {
            std::lock_guard<SpinLock> lock(requestQueueMutex);
            requestQueue.push_back(std::move(message));
        } else {
            std::lock_guard<SpinLock> lock(rpcMapMutex);
            auto it = rpcMap.find(header.rpcId);
            if (it != rpcMap.end()) {
                it->second->response = std::move(message);
                it->second->completed();
                rpcMap.erase(it);
            } else {
                // there is no waiting rpc for this response; drop the message.
            }
        }
    }
}

}  // namespace Homa
