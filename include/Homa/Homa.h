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

/**
 * @file Homa/Homa.h
 *
 * Contains the Homa Transport API.  Applications of the Homa Transport library
 * should include this header.
 */

#ifndef HOMA_INCLUDE_HOMA_HOMA_H
#define HOMA_INCLUDE_HOMA_HOMA_H

#include <Homa/Driver.h>

#include <atomic>
#include <bitset>
#include <cstdint>

namespace Homa {

/**
 * Shorthand for an std::unique_ptr with a customized deleter.
 */
template <typename T>
using unique_ptr = std::unique_ptr<T, typename T::Deleter>;

/**
 * Represents a socket address to (from) which we can send (receive) messages.
 */
struct SocketAddress {
    /// IPv4 address in host byte order.
    IpAddress ip;

    /// Port number in host byte order.
    uint16_t port;
};

/**
 * Represents an array of bytes that has been received over the network.
 *
 * This class is NOT thread-safe.
 */
class InMessage {
  public:
    /**
     * Custom deleter for use with std::unique_ptr.
     */
    struct Deleter {
        void operator()(InMessage* message)
        {
            message->release();
        }
    };

    /**
     * Inform the sender that this message has been processed successfully.
     */
    virtual void acknowledge() const = 0;

    /**
     * Returns true if the sender is no longer waiting for this message to be
     * processed; false otherwise.
     */
    virtual bool dropped() const = 0;

    /**
     * Inform the sender that this message has failed to be processed.
     */
    virtual void fail() const = 0;

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
     * @param count
     *      The number of bytes being requested.
     *
     * @return
     *      The number of bytes actually copied out. This number may be less
     *      than "num" if the requested byte range exceeds the range of
     *      bytes in the Message.
     */
    virtual size_t get(size_t offset, void* destination,
                       size_t count) const = 0;

    /**
     * Return the number of bytes this Message contains.
     */
    virtual size_t length() const = 0;

    /**
     * Remove a number of bytes from the beginning of the Message.
     *
     * @param count
     *      Number of bytes to remove.
     */
    virtual void strip(size_t count) = 0;

  protected:
    /**
     * Signal that this message is no longer needed.  The caller should not
     * access this message following this call.
     */
    virtual void release() = 0;
};

/**
 * Represents an array of bytes that can be sent over the network.
 *
 * This class is NOT thread-safe.
 */
class OutMessage {
  public:
    /**
     * Defines the possible states of an OutMessage.
     */
    enum class Status {
        NOT_STARTED,  //< The sending of this message has not started.
        IN_PROGRESS,  //< The message is in the process of being sent.
        CANCELED,     //< The message was canceled while still IN_PROGRESS.
        SENT,         //< The message has been completely sent.
        COMPLETED,    //< The message has been received and processed.
        FAILED,       //< The message failed to be delivered and processed.
    };

    /**
     * Options with which an OutMessage can be sent.
     */
    enum Options {
        /// Default send behavior.
        NONE = 0,

        /// Message will not be resent if recoverable send failure occurs;
        /// provides at-most-once delivery of messages.
        NO_RETRY = 1 << 0,

        /// Once the Message has been sent, Homa will not automatically ping the
        /// Message's receiver to ensure the receiver is still alive and the
        /// Message will not "timeout" due to receiver inactivity.
        NO_KEEP_ALIVE = 1 << 1,
    };

    /**
     * Custom deleter for use with std::unique_ptr.
     */
    struct Deleter {
        void operator()(OutMessage* message)
        {
            message->release();
        }
    };

    /**
     * Copy an array of bytes to the end of the Message.
     *
     * @param source
     *      Address of the first byte of data to be copied to the end of the
     *      Message.
     * @param count
     *      Number of bytes to be appended.
     */
    virtual void append(const void* source, size_t count) = 0;

    /**
     * Stop sending this message.
     */
    virtual void cancel() = 0;

    /**
     * Return the current state of this message.
     */
    virtual Status getStatus() const = 0;

    /**
     * Return the number of bytes this Message contains.
     */
    virtual size_t length() const = 0;

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
    virtual void prepend(const void* source, size_t count) = 0;

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
     * @param count
     *      The number of bytes to be reserved.
     *
     * @sa Message::append(), Message::prepend()
     */
    virtual void reserve(size_t count) = 0;

    /**
     * Send this message to the destination.
     *
     * @param destination
     *      Network address to which this message will be sent.
     * @param options
     *      Flags to request non-default sending behavior.
     */
    virtual void send(SocketAddress destination,
                      Options options = Options::NONE) = 0;

  protected:
    /**
     * Signal that this message is no longer needed.  The caller should not
     * access this message following this call.
     */
    virtual void release() = 0;
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
     * Return a new instance of a Homa-based transport.
     *
     * The caller is responsible for calling free() on the returned pointer.
     *
     * @param driver
     *      Driver with which this transport should send and receive packets.
     * @param transportId
     *      This transport's unique identifier in the group of transports among
     *      which this transport will communicate.
     * @return
     *      Pointer to the new transport instance.
     */
    static Transport* create(Driver* driver, uint64_t transportId);

    /**
     * Allocate Message that can be sent with this Transport.
     *
     * @param sourcePort
     *      Port number of the socket from which the message will be sent.
     * @return
     *      A pointer to the allocated message.
     */
    virtual Homa::unique_ptr<Homa::OutMessage> alloc(uint16_t sourcePort) = 0;

    /**
     * Check for and return a Message sent to this Transport if available.
     *
     * @return
     *      Pointer to the received message, if any.  Otherwise, nullptr is
     *      returned if no message has been delivered.
     */
    virtual Homa::unique_ptr<Homa::InMessage> receive() = 0;

    /**
     * Make incremental progress performing all Transport functionality.
     *
     * This method MUST be called for the Transport to make progress and should
     * be called frequently to ensure timely progress.
     */
    virtual void poll() = 0;

    /**
     * Return the driver that this transport uses to send and receive packets.
     */
    virtual Driver* getDriver() = 0;

    /**
     * Return this transport's unique identifier.
     */
    virtual uint64_t getId() = 0;
};

/**
 * Combine Options flags.
 */
inline OutMessage::Options
operator|(OutMessage::Options lhs, OutMessage::Options rhs)
{
    typedef std::underlying_type<OutMessage::Options>::type options_t;
    return OutMessage::Options(static_cast<options_t>(lhs) |
                               static_cast<options_t>(rhs));
}

}  // namespace Homa

#endif  // HOMA_INCLUDE_HOMA_HOMA_H
