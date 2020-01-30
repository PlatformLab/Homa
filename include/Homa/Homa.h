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

#ifndef HOMA_INCLUDE_HOMA_HOMA_H
#define HOMA_INCLUDE_HOMA_HOMA_H

#include <Homa/Driver.h>
#include <Homa/Protocol.h>

#include <atomic>
#include <bitset>
#include <cstdint>

namespace Homa {

// forward declarations
class Transport;
class TransportInternal;
namespace Core {
class Transport;
class OpContext;
}  // namespace Core

/**
 * Represents an array of bytes that can be sent or is received over the network
 * via Homa::Transport.
 *
 * This class is NOT thread-safe.
 */
class Message {
  public:
    /**
     * Copy an array of bytes to the end of the Message.
     *
     * @param source
     *      Address of the first byte of data (in a byte array) to be copied to
     *      the end of the Message.
     * @param num
     *      Number of bytes to be appended.
     */
    virtual void append(const void* source, uint32_t num) = 0;

    /**
     * Get the contents of a specified range of bytes in the Message by
     * copying them into the provided destination memory region.
     *
     * @param offset
     *      The number of bytes in the Message preceding the range of bytes
     *      being requested.
     * @param destination
     *      The pointer to the memory region into which the requested byte
     *      range will be copied. The caller must ensure that the buffer is
     *      big enough to hold the requested number of bytes.
     * @param num
     *      The number of bytes being requested.
     *
     * @return
     *      The number of bytes actually copied out. This number may be less
     *      than "num" if the requested byte range exceeds the range of
     *      bytes in the Message.
     */
    virtual uint32_t get(uint32_t offset, void* destination,
                         uint32_t num) const = 0;

    /**
     * Return the number of bytes this Message contains.
     */
    virtual uint32_t length() const = 0;

    /**
     * Copy an array of bytes to the beginning of the Message.
     *
     * The number of bytes prepended must have been previously reserved;
     * otherwise, the behavior is undefined.
     *
     * @param source
     *      Address of the first byte of data (in a byte array) to be copied to
     *      the beginning of the Message.
     * @param num
     *      Number of bytes to be prepended.
     *
     * @sa Message::reserve()
     */
    virtual void prepend(const void* source, uint32_t num) = 0;

    /**
     * Reserve a number of bytes at the beginning of the Message.
     *
     * The reserved space is used when bytes are prepended to the Message.
     * Sending a Message with unused reserved space will result in undefined
     * behavior.
     *
     * This method should be called before appending or prepending data to the
     * Message; otherwise, the behavior is undefined.
     *
     * @param num
     *      The number of bytes to be reserved.
     *
     * @sa Message::append(), Message::prepend()
     */
    virtual void reserve(uint32_t num) = 0;

    /**
     * Remove a number of bytes from the beginning of the Message.
     *
     * @param num
     *      Number of bytes to remove.
     */
    virtual void strip(uint32_t num) = 0;
};

/**
 * Represents a Message has been received over the network via Homa::Transport.
 *
 * This class is NOT thread-safe.
 */
class InMessage : public virtual Message {
  public:
    /**
     * Inform the sender that this message has been processed successfully.
     */
    virtual void acknowledge() const = 0;

    /**
     * Inform the sender that this message has failed to be processed.
     */
    virtual void fail() const = 0;

    /**
     * Returns true if the sender is no longer waiting for this message to be
     * processed; false otherwise.
     */
    virtual bool dropped() const = 0;

    /**
     * Signal that this message is no longer needed.  The caller should not
     * access this message following this call.
     */
    virtual void release() = 0;
};

/**
 * Represents a Message that can be sent over the network via Homa::Transport.
 *
 * This class is NOT thread-safe.
 */
class OutMessage : public virtual Message {
  public:
    /**
     * Defines the possible states of an OutMessage.
     */
    enum class Status {
        NOT_STARTED,  //< The sending of this message has not started.
        IN_PROGRESS,  //< The message is in the process of being sent.
        CANCELED,     //< The message was canceled while still IN_PROGRESS.
        SENT,         //< The message has been completely sent.
        COMPLETED,    //< The Receiver has acknowledged receipt of this message.
        FAILED,       //< The message failed to be delivered and processed.
    };

    /**
     * Send this message to the destination.
     *
     * @param destination
     *      Address of the transport to which this message will be sent.
     */
    virtual void send(Driver::Address destination) = 0;

    /**
     * Stop sending this message.
     */
    virtual void cancel() = 0;

    /**
     * Return the current state of this message.
     */
    virtual Status getStatus() const = 0;

    /**
     * Signal that this message is no longer needed.  The caller should not
     * access this message following this call.
     */
    virtual void release() = 0;
};

/**
 * A RemoteOp is a Message pair consisting of a request Message to be sent to
 * and processed by a "remote server" and a response Message that returns the
 * result of processing the request.
 *
 * An RPC (Remote Procedure Call) is a simple example of a RemoteOp.  Unlike
 * RPCs, however, the processing of the operation maybe fully or partially
 * delegated by one server to another.  As such, the response may not come from
 * the server that initially received the request.
 *
 * This class is NOT thread-safe in general.  This class will correctly handle
 * the Transport running on a different thread, but if an instance of RemoteOp
 * is accessed from multiple threads for any other purpose, the threads must
 * synchronize to ensure only one thread accesses a RemoteOp object at a time.
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
     *      Pointer to the Homa::Transport which will send/receive this RPC.
     */
    explicit RemoteOp(Transport* transport);

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
     * failed with the response Message left pointing to nullptr.
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
    /// Transport that owns this RemoteOp.
    Transport* const transport;

    /// Unique identifier for this RemoteOp.
    Protocol::OpId opId;

    /// The current state of this RemoteOp
    std::atomic<State> state;

    // Disable Copy and Assign
    RemoteOp(const RemoteOp&) = delete;
    RemoteOp& operator=(const RemoteOp&) = delete;

    friend class Transport;
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
     * Basic constructor to create an empty ServerOp object.
     *
     * ServerOp objects can be filled with an incoming request by moving the
     * result of calling Transport::receiveServerOp().
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
    State checkProgress();

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

    /// Message containing a direct or indirect operation request.
    InMessage* request;

    /// Message containing the result of processing the operation.  Message can
    /// be sent as a reply back to the client or delegated to a different server
    /// for further processing.
    ///
    /// @sa reply(), delegate()
    OutMessage* response;

  private:
    /// Transport that owns this ServerOp.
    Transport* transport;

    /// Current state of the ServerOp.
    std::atomic<State> state;

    /// True if the ServerOp is no longer held by the application and is being
    /// processed by the Transport.
    std::atomic<bool> detached;

    /// Identifier the RemoteOp that triggered this ServerOp.
    Protocol::OpId opId;

    /// Unique identifier for the request message among the set of messages
    /// associated with a RemoteOp with a given OpId.
    uint32_t requestTag;

    /// Address from which the RemoteOp originated and to which the reply
    /// should be sent.
    Driver::Address replyAddress;

    /// True if delegate() was called on this ServerOp.
    bool delegated;

    // Disable Copy and Assign
    ServerOp(const ServerOp&) = delete;
    ServerOp& operator=(const ServerOp&) = delete;

    friend class Transport;
};

/**
 * Provides a means of communicating across the network using the Homa protocol.
 *
 * The transport is used to send and receive messages across the network using
 * the RemoteOp and ServerOp abstractions.  The execution of the transport is
 * driven through repeated calls to the Transport::poll() method; the transport
 * will not make any progress otherwise.
 *
 * This class is thread-safe.
 */
class Transport {
  public:
    /**
     * Construct a new instance of a Homa-based transport.
     *
     * @param driver
     *      Driver with which this transport should send and receive packets.
     * @param transportId
     *      This transport's unique identifier in the group of transports among
     *      which this transport will communicate.
     */
    Transport(Driver* driver, uint64_t transportId);

    /**
     * Homa::Transport destructor.
     */
    ~Transport();

    /**
     * Return a ServerOp of an incoming request that has been received by this
     * Homa::Transport. If no request was received, the returned ServerOp will
     * be uninitialized.
     */
    ServerOp receiveServerOp();

    /**
     * Make incremental progress performing all Transport functionality.
     *
     * This method MUST be called for the Transport to make progress and should
     * be called frequently to ensure timely progress.
     */
    void poll();

    /// The Driver that handles sending and receiving this Transport's packets.
    Driver* const driver;

  private:
    /// Contains the internal implementation of Homa::Transport which does most
    /// of the actual work.  Hides unnecessary details from users of libHoma.
    std::unique_ptr<Core::Transport> internal;

    /// Contains the private members of Homa::Transport.
    std::unique_ptr<Homa::TransportInternal> members;

    // Disable Copy and Assign
    Transport(const Transport&) = delete;
    Transport& operator=(const Transport&) = delete;

    friend class RemoteOp;
    friend class ServerOp;
};

}  // namespace Homa

#endif  // HOMA_INCLUDE_HOMA_HOMA_H
