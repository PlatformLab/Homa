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

#ifndef HOMA_SERVERRPC_H
#define HOMA_SERVERRPC_H

#include "Homa/Message.h"
#include "Homa/Transport.h"

namespace Homa {

// forward declaration
class RpcManager;

/**
 * Represents an incomming RPC that is either waiting to be processed or is
 * being processed.  Contains both the incomming request and a place to store
 * the response.
 *
 * Objects of this type are created by the transport and handles to them are
 * provided to the application by calling Transport::receiveServerRpc().
 *
 * This class is not thread-safe.
 */
class ServerRpc {
  public:
    /**
     * Basic constructor to create an empty ServerRpc object.
     *
     * ServerRpc objects can be filled with an incomming request by moving the
     * result of calling RpcManager::receiveServerRpc().
     */
    ServerRpc();

    /**
     * Move constructor.
     */
    ServerRpc(ServerRpc&& other);

    /**
     * Default destructor for a ServerRpc object.
     */
    ~ServerRpc();

    /**
     * Move assignment.
     */
    ServerRpc& operator=(ServerRpc&& other);

    /**
     * Returns true if the ServerRpc contains a request; false otherwise.
     */
    operator bool();

    /**
     * Send the ServerRpc's response.
     */
    void sendResponse();

    /**
     * Contains the request for this RPC. The first part this message is the
     * RpcHeader.
     */
    Message request;

    /**
     * Used by the caller to construct the RPC's response. The first part this
     * message must be reserved for the RpcHeader.
     */
    Message response;

    /// Manager responsible for receiving the request and sending the response.
    RpcManager* manager;

  private:
    ServerRpc(const ServerRpc&) = delete;
    ServerRpc& operator=(const ServerRpc&) = delete;
};

}  // namespace Homa

#endif  // HOMA_SERVERRPC_H
