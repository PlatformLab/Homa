/* Copyright (c) 2018-2020, Stanford University
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

#ifndef HOMA_INCLUDE_HOMA_OP_H
#define HOMA_INCLUDE_HOMA_OP_H

#include <Homa/Driver.h>
#include <Homa/Homa.h>
#include <Homa/Protocol.h>

#include <atomic>
#include <bitset>
#include <cstdint>

namespace Homa {

// forward declarations
class OpManager;
class OpManagerInternal;
namespace Core {
class OpContext;
}  // namespace Core

/**
 * A RemoteOp is a Message pair consisting of a request Message to be sent to
 * and processed by a "remote server" and a response Message that returns the
 * result of processing the request.
 *
 * An RPC (Remote Procedure Call) is a simple example of a RemoteOp.  Unlike
 * RPCs, however, the processing of the operation maybe delegated by one server
 * to another.  As such, the response may not come from the server that
 * initially received the request.
 *
 * This class is NOT thread-safe.
 */
class RemoteOp {
  public:
    enum class State {
        NOT_STARTED,  // Initial state before the request has been sent.
        IN_PROGRESS,  // The request has been sent but no response has been
                      // received.
        COMPLETED,    // The RemoteOp has completed and the server's response is
                      // available in response.
        FAILED,       // The RemoteOp has failed to send.
    };

    /**
     * Constructor for an RemoteOp object.
     *
     * @param transport
     *      Pointer to the Homa::OpManager which will send/receive this RPC.
     */
    explicit RemoteOp(OpManager* transport);

    /**
     * Default destructor for a RemoteOp object.
     */
    ~RemoteOp();

    /**
     * Send the RemoteOp asynchronously.
     *
     * WARNING: Do not modify the request after calling this method.
     *
     * @param destination
     *      The network address to which the request will be sent.
     */
    void send(Driver::Address destination);

    /**
     * Indicates whether this RemoteOp is done being processed.  Used to
     * asynchronously process a RemoteOp.  If this call returns true, the
     * RemoteOp has either completed with the response Message populated or
     * failed (e.g. request timed out) with the response Message left pointing
     * to nullptr.
     *
     * @return
     *      True means that the RemoteOp has completed or failed; #wait will not
     *      block.  False means that the RemoteOp is still being processed.
     */
    bool isReady();

    /**
     * Wait for a response to be received for this RemoteOp.
     */
    void wait();

    /// Message to be sent to and processed by the target "remote server".
    OutMessage* request;

    /// Message containing the result of processing the RemoteOp request.
    InMessage* response;

  private:
    /// OpManager that owns this RemoteOp.
    OpManager* const transport;

    /// Unique identifier for this RemoteOp.
    Protocol::OpId opId;

    /// The current state of this RemoteOp
    std::atomic<State> state;

    // Disable Copy and Assign
    RemoteOp(const RemoteOp&) = delete;
    RemoteOp& operator=(const RemoteOp&) = delete;

    friend class OpManager;
};

/**
 * A ServerOp is a Message pair consisting of an incoming request Message to
 * be processed and an outgoing response Message containing the result of
 * processing the operation.
 *
 * The request may come directly from the client or from another server that is
 * delegating the processing all or part of the operation.  The response can
 * either be sent back sent to the original client or delegated to a different
 * server for additional processing. Used by servers to handle incoming direct
 * or delegated requests.
 *
 * This class is NOT thread-safe.
 */
class ServerOp {
  public:
    enum class State {
        NOT_STARTED,  // Initial state before the request has been received.
        IN_PROGRESS,  // Request received but response has not yet been sent.
        DROPPED,      // The request was dropped.
        COMPLETED,    // The server's response has been sent/acknowledged.
        FAILED,       // The response failed to be sent/processed.
    };

    /**
     * Construct an empty ServerOp object.
     */
    ServerOp();

    /**
     * Move constructor.
     */
    ServerOp(ServerOp&& other);

    /**
     * Default destructor for a ServerOp object.
     */
    ~ServerOp();

    /**
     * Move assignment.
     */
    ServerOp& operator=(ServerOp&& other);

    /**
     * Returns true if the ServerOp contains a request; false otherwise.
     */
    operator bool() const;

    /**
     * Check and return the current State of the ServerOp.
     */
    State makeProgress();

    /**
     * Send the outMessage as a response to the initial requestor.
     */
    void reply();

    /**
     * Send the outMessage as a delegated request to the provided destination.
     *
     * @param destination
     *      The network address to which the delegated request will be sent.
     */
    void delegate(Driver::Address destination);

    /// Message containing an operation request; may come directly from a
    /// client, or from another server that has delegated the request to us.
    /// This value will be nullptr if the ServerOp is empty.
    InMessage* request;

    /// Message containing the result of processing the operation.  Message can
    /// be sent as a reply back to the client or delegated to a different server
    /// for further processing. This value will be nullptr if the ServerOp is
    /// empty.
    OutMessage* response;

  private:
    /// OpManager that owns this ServerOp.
    OpManager* transport;

    /// Current state of the ServerOp.
    std::atomic<State> state;

    /// True if the ServerOp is no longer held by the application and is being
    /// processed by the OpManager.
    std::atomic<bool> detached;

    /// Identifier the RemoteOp that triggered this ServerOp.
    Protocol::OpId opId;

    /// Unique identifier for the request message among the set of messages
    /// associated with a RemoteOp with a given OpId.
    int32_t stageId;

    /// Address of the client that sent the original request; the reply should
    /// be sent back to this address.
    Driver::Address replyAddress;

    /// True if delegate() was called on this ServerOp.
    bool delegated;

    // Disable Copy and Assign
    ServerOp(const ServerOp&) = delete;
    ServerOp& operator=(const ServerOp&) = delete;

    friend class OpManager;
};

/**
 * Provides a means of communicating across the network using the Homa protocol.
 *
 * The transport is used to send and receive messages across the network using
 * the RemoteOp and ServerOp abstractions.  The execution of the transport is
 * driven through repeated calls to the OpManager::poll() method; the transport
 * will not make any progress otherwise.
 *
 * This class is thread-safe.
 */
class OpManager {
  public:
    /**
     * Construct a new instance of a Homa-based OpManager.
     *
     * @param driver
     *      Driver with which this transport should send and receive packets.
     * @param transportId
     *      This transport's unique identifier in the group of transports among
     *      which this transport will communicate.
     */
    OpManager(Driver* driver, uint64_t transportId);

    /**
     * Homa::OpManager destructor.
     */
    ~OpManager();

    /**
     * Return a ServerOp of an incoming request that has been received by this
     * Homa::OpManager. If no request was received, the returned ServerOp will
     * be empty.
     */
    ServerOp receiveServerOp();

    /**
     * Make incremental progress performing all OpManager functionality.
     *
     * This method MUST be called for the OpManager to make progress and should
     * be called frequently to ensure timely progress.
     */
    void poll();

    /// The Driver that handles sending and receiving this OpManager's packets.
    Driver* const driver;

  private:
    /// Contains the internal implementation of Homa::OpManager which does most
    /// of the actual work.  Hides unnecessary details from users of libHoma.
    std::unique_ptr<Transport> internal;

    /// Contains the private members of Homa::OpManager.
    std::unique_ptr<Homa::OpManagerInternal> members;

    // Disable Copy and Assign
    OpManager(const OpManager&) = delete;
    OpManager& operator=(const OpManager&) = delete;

    friend class RemoteOp;
    friend class ServerOp;
};

}  // namespace Homa

#endif  // HOMA_INCLUDE_HOMA_OP_H
