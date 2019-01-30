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

#ifndef HOMA_HOMA_H
#define HOMA_HOMA_H

#include <Homa/Driver.h>

#include <bitset>
#include <cstdint>

namespace Homa {

// forward declarations
class Transport;
namespace Core {
class OpContext;
}

/**
 * A Message refers to an array of bytes that can be sent or is received over
 * the network via Homa::Transport.  RemoteOp and ServerOp instances include
 * a pair of Message objects for inbound and outbound communication.
 *
 * This class is NOT thread-safe.
 */
class Message {
  public:
    /**
     * Append an array of bytes to the end of the Message by copying the
     * bytes into the Message's internal storage.
     *
     * This operation cannot be performed on a received Message or one that
     * has already been sent.
     *
     * @param source
     *      Address of the first byte of data (in a byte array) to be
     *      copied to the end of the Message.
     * @param num
     *      Number of bytes to be appended.
     */
    virtual void append(const void* source, uint32_t num) = 0;

    /**
     * Get the contents of a specified range of bytes in the Message by
     * copying them into the provided destination memory region.
     *
     * This operation cannot be performed on a detached Message.
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
     * Set the contents of a specified range of bytes in the Message using
     * the contents of the provided source memory region.
     *
     * If necessary, this operation will extend the Message to accomidate
     * the provided source content and will leave the contents of the
     * Message before the offset untouched and potentailly uninitilized.
     *
     * This operation cannot be performed on a received Message or one that
     * has already been sent.
     *
     * @param offset
     *      The number of bytes in the Message preceding the range of bytes
     *      to be set.
     * @param source
     *      The pointer to the memory region whose
     * @param num
     *      The number of bytes to set.
     */
    virtual void set(uint32_t offset, const void* source, uint32_t num) = 0;
};

/**
 * A RemoteOp is a Message pair consisting of a request Message to be sent to
 * and processed by a "remote server" and a response Message that returns the
 * result of processing the request.
 *
 * An RPC (Remote Procedure Call) is a simple example of a RemoteOp.  Unlike
 * RPCs, however, the processing of the operation maybe fully or paritally
 * deligated by one server to another.  As such, the response may not come from
 * the server that initally received the request.
 *
 * This class is NOT thread-safe.
 */
class RemoteOp {
  public:
    /**
     * Basic constructor to create an uninitialized RemoteOp object. Use by
     * applications of the Homa library.
     *
     * RemoteOp objects can be initialized by moving the result of calling
     * Transport::newRemoteOp().
     */
    RemoteOp();

    /**
     * Convenience constructor for an RemoteOp object.
     *
     * @param transport
     *      Pointer to the Homa::Transport which will send/receive this RPC.
     * @param address
     *      Address of a networked application that will process this RemoteOp.
     */
    explicit RemoteOp(Transport* transport,
                      Driver::Address* destination = nullptr);

    /**
     * Move constructor.
     */
    RemoteOp(RemoteOp&& other);

    /**
     * Default destructor for a RemoteOp object.
     */
    ~RemoteOp();

    /**
     * Move assignment.
     */
    RemoteOp& operator=(RemoteOp&& other);

    /**
     * Returns true if the RemoteOp in initialized; false otherwise.
     */
    operator bool() const;

    /**
     * Set the destiation network address for this RemoteOp.
     *
     * This operation cannot be performed after send() is called.
     */
    void setDestination(Driver::Address* destination);

    /**
     * Send the RemoteOp asynchronously.
     *
     * WARNING: Do not modify the request after calling this method.
     */
    void send();

    /**
     * Indicates whether the response has been received for this RemoteOp. Used
     * to asynchronously process an RemoteOp. If this call returns true, the
     * RemoteOp's response will be populated.
     *
     * @return
     *      True means that the RemoteOp has finished or been canceled; #wait
     *      will not block.  False means that the RemoteOp is still being
     *      processed.
     */
    bool isReady();

    /**
     * Wait for a response to be received for this RemoteOp.
     */
    void wait();

    /// Message to be sent to and processed by the target "remote server".
    Message* request;

    /// Message containing the result of processing the RemoteOp request.
    const Message* response;

  private:
    /// Contains the metadata and Message objects for this operation.
    Core::OpContext* op;

    // Disable Copy and Assign
    RemoteOp(const RemoteOp&) = delete;
    RemoteOp& operator=(const RemoteOp&) = delete;
};

/**
 * A ServerOp is a Message pair consisting of an incomming request Message to
 * be processed and an outgoing response Message containing the result of
 * processing the operation.
 *
 * The request may come directly from the client or from another server that is
 * deligating the processing all or part of the operation.  The response can
 * either be sent back sent to the original client or deligated to a different
 * server for additional processing. Used by servers to handle incomming direct
 * or deligated requests.
 *
 * This class is NOT thread-safe.
 */
class ServerOp {
  public:
    /**
     * Basic constructor to create an empty ServerOp object.
     *
     * ServerOp objects can be filled with an incomming request by moving the
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
     * Send the outMessage as a response to the initial requestor.
     */
    void reply();

    /**
     * Send the outMessage as a deligated request to the provided destination.
     *
     * @param destination
     *      The network address to which the deligated request will be sent.
     */
    void deligate(Driver::Address* destination);

    /// Message containing a direct or indirect operation request.
    const Message* request;

    /// Message containing the result of processing the operation.  Message can
    /// be sent as a reply back to the client or deligated to a different server
    /// for further processing.
    ///
    /// @sa reply(), deligate()
    Message* response;

  private:
    /// Contains the metadata and Message objects for this operation.
    Core::OpContext* op;

    // Disable Copy and Assign
    ServerOp(const ServerOp&) = delete;
    ServerOp& operator=(const ServerOp&) = delete;
};

/**
 * Provides a means of commicating across the network using the Homa protocol.
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
     * Return a new instance of a Homa-based transport.
     *
     * The caller is responsible for calling delete on the Transport when it is
     * no longer needed.
     *
     * @param driver
     *      Driver with which this transport should send and receive packets.
     * @param transportId
     *      This transport's unique identifier in the group of transports among
     *      which this transport will communicate.
     * @return
     *      Pointer to a new Homa::Transport.
     */
    static Transport* newTransport(Driver* driver, uint64_t transportId);

    /**
     * Return a ServerOp of an incomming request that has been received by this
     * Homa::Transport. If no request was received, the returned ServerOp will
     * be uninitialized.
     *
     * @sa Transport::sendMessage()
     */
    virtual ServerOp receiveServerOp() = 0;

    /**
     * Return a network address handle for the given string representation of
     * the address. Addresses and address strings are Driver specific.
     *
     * @param addressString
     *      See above.
     * @return
     *      Pointer to an Address object.
     * @throw BadAddress
     *      _addressString_ is malformed.
     */
    virtual Driver::Address* getAddress(
        std::string const* const addressString) = 0;

    /**
     * Make incremental progress performing all Transport functionality.
     *
     * This method MUST be called for the Transport to make progress and should
     * be called frequently to ensure timely progress.
     */
    virtual void poll() = 0;
};

}  // namespace Homa

#endif  // HOMA_HOMA_H