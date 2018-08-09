/* Copyright (c) 2012-2018, Stanford University
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

#ifndef HOMA_RPC_H
#define HOMA_RPC_H

#include "Driver.h"
#include "Transport.h"

namespace Homa {

// forward declaration
class RpcManager;

/**
 * An Rpc object represents an remote procedure call (RPC) which can be sent
 * over the network asynchronously.
 *
 * Rpc objects consist of a Transport::Message which should contain the bytes
 * that make up the Rpc's request and a Transport::Message which will contain
 * the Rpc's response.
 *
 * This class is NOT thread-safe in general but can be used by callers in a
 * thread-safe manner by observing the following rules:
 *      1) The request cannot be modified after calling send().
 *      2) The response cannot be accessed until after calling wait().
 */
class Rpc {
  public:
    /**
     * Constructor for an RPC object.
     *
     * @param manager
     *      Pointer to the Homa::Transport which will send/receive this RPC.
     * @param address
     *      Address of a networked application to which this RPC should be sent.
     */
    Rpc(RpcManager* manager, Driver::Address* address);

    /**
     * Rpc destructor.
     */
    ~Rpc();

    /**
     * Send the Rpc asynchronously.  Ownership of this Rpc is logically handed
     * over to the RpcManager until the Rpc is complete.
     *
     * WARNING: Do not modify the Rpc after calling this method.
     */
    void send();

    /**
     * Indicates whether a response has been received for an RPC.  Used
     * for asynchronous processing of RPCs. If this call returns true, the
     * RPC's response InBuffer will be populated.
     *
     * \return
     *      True means that the RPC has finished or been canceled; #wait will
     *      not block.  False means that the RPC is still being processed.
     */
    virtual bool isReady();

    /**
     * Wait for a response to be received for this RPC.
     */
    void wait();

    /**
     * Used by the caller to construct the RPC's request. The first part this
     * message must be reserved for the RpcProtocol::RpcHeader.
     *
     * WARNING: Do not modify the request after calling send().
     */
    Transport::Message request;

    /**
     * Contains the response for this RPC. The first part this message is the
     * RpcProtocol::RpcHeader.
     *
     * WARNING: Do not access the response until after calling wait().
     */
    Transport::Message response;

    /**
     * Invoked by the RpcManager when the RpcManager has fill out the response
     * Message and considers the Rpc complete.
     */
    virtual void completed();

  protected:
    /// Possible states for an RPC.
    enum RpcState {
        NOT_STARTED,  // Initial state before the request has
                      // been sent for the first time.
        IN_PROGRESS,  // A request has been sent but no response
                      // has been received.
        FINISHED      // The RPC has completed and the server's
                      // response is available in response.
    };

    /// Current state of processing this RPC. This variable may be accessed
    /// concurrently by Rpc methods running in one thread and manager/transport
    /// code running in the different thread (the manager can can only invoke
    /// the completed method).
    std::atomic<RpcState> state;

    /**
     * This method provides safe synchronized access to the #state variable, and
     * is the only mechanism that should be used to read #state.
     *
     * @return
     *      Current state of processing for this RPC.
     */
    RpcState getState()
    {
        return state.load(std::memory_order_acquire);
    }

  private:
    /// Manager responsible for sending the request and receiving the response.
    RpcManager* const manager;

    Rpc(const Rpc&) = delete;
    Rpc& operator=(const Rpc&) = delete;
};

}  // namespace Homa

#endif  // HOMA_RPC_H
