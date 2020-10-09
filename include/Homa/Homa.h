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
#include <functional>

namespace Homa {

/**
 * Shorthand for an std::unique_ptr with a customized deleter.
 *
 * This is used to implement the "borrow" semantics for interface classes like
 * InMessage, OutMessage, and Socket; that is, a user can obtain pointers to
 * these objects and use them to make function calls, but the user must always
 * return the objects back to the transport library eventually because the user
 * has no idea how to destruct the objects or reclaim memory.
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
     * Return the remote address from which this Message is sent.
     */
    virtual SocketAddress getSourceAddress() const = 0;

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
     * Use protected destructor to prevent users from calling delete on pointers
     * to this interface.
     */
    ~InMessage() = default;

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
    using Status = OutMessageStatus;

    /**
     * Options with which an OutMessage can be sent.
     */
    enum Options {
        NONE = 0,           //< Default send behavior.
        NO_RETRY = 1 << 0,  //< Message will not be resent if recoverable send
                            //< failure occurs; provides at-most-once delivery
                            //< of messages.
        NO_KEEP_ALIVE = 1 << 1,  //< Once the Message has been sent, Homa will
                                 //< not automatically ping the Message's
                                 //< receiver to ensure the receiver is still
                                 //< alive and the Message will not "timeout"
                                 //< due to receiver inactivity.
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
    // FIXME: this is problematic; we can't really call send a second time...

  protected:
    /**
     * Use protected destructor to prevent users from calling delete on pointers
     * to this interface.
     */
    ~OutMessage() = default;

    /**
     * Signal that this message is no longer needed.  The caller should not
     * access this message following this call.
     */
    virtual void release() = 0;
};

/**
 * Collection of user-defined transport callbacks.
 */
class Callbacks {
  public:
    /**
     * Destructor.
     */
    virtual ~Callbacks() = default;

    /**
     * Invoked when an incoming message arrives and needs to dispatched to its
     * destination in the user application for processing.
     *
     * Here are a few example use cases of this callback:
     * <ul>
     * <li> Interaction with the user's thread scheduler: e.g., an application
     * may want to block on receive until a message is delivered, so this method
     * can be used to wake up blocking threads.
     * <li> High-performance message dispatch: e.g., an application may choose
     * to implement the message receive queue with a concurrent MPMC queue as
     * opposed to a linked-list protected by a mutex;
     * <li> Lightweight synchronization: e.g., the socket table that maps from
     * port numbers to sockets is a read-mostly data structure, so lookup
     * operations can benefit from synchronization schemes such as RCU.
     * </ul>
     *
     * @param port
     *      Destination port number of the message.
     * @param message
     *      Incoming message to dispatch.
     * @return
     *      True if the message is delivered successfully; false, otherwise.
     */
    virtual bool deliver(uint16_t port, InMessage* message) = 0;

    /**
     * Invoked when some packets just became ready to be sent (and there was
     * none before).
     *
     * This callback allows the transport library to notify the users that
     * trySend() should be invoked again as soon as possible. For example,
     * the callback can be used to implement wakeup signals for the thread
     * that is responsible for calling trySend(), if this thread decides to
     * sleep when there is no packets to send.
     */
    virtual void notifySendReady() {}
};

/**
 * Provides a means of communicating across the network using the Homa protocol.
 *
 * The execution of the transport is driven through repeated calls to methods
 * like checkTimeouts(), processPacket(), trySend(), and trySendGrants(); the
 * transport will not make any progress otherwise.
 *
 * This class is thread-safe.
 */
class Transport {
  public:
    /**
     * Custom deleter for use with std::unique_ptr.
     */
    struct Deleter {
        void operator()(Transport* transport)
        {
            transport->free();
        }
    };

    /**
     * Return a new instance of a Homa-based transport.
     *
     * @param driver
     *      Driver with which this transport should send and receive packets.
     * @param callbacks
     *      Collection of user-defined callbacks to customize the behavior of
     *      the transport.
     * @param transportId
     *      This transport's unique identifier in the group of transports among
     *      which this transport will communicate.
     * @return
     *      Pointer to the new transport instance.
     */
    static Homa::unique_ptr<Transport> create(Driver* driver,
                                              Callbacks* callbacks,
                                              uint64_t transportId);

    /**
     * Allocate Message that can be sent with this Transport.
     *
     * @param port
     *      Port number of the socket from which the message will be sent.
     * @return
     *      A pointer to the allocated message.
     */
    virtual Homa::unique_ptr<Homa::OutMessage> alloc(uint16_t port) = 0;

    /**
     * Return the driver that this transport uses to send and receive packets.
     */
    virtual Driver* getDriver() = 0;

    /**
     * Return this transport's unique identifier.
     */
    virtual uint64_t getId() = 0;

    /**
     * Process any timeouts that have expired.
     *
     * This method must be called periodically to ensure timely handling of
     * expired timeouts.
     *
     * @return
     *      The rdtsc cycle time when this method should be called again.
     */
    virtual uint64_t checkTimeouts() = 0;

    /**
     * Handle an ingress packet by running it through the transport protocol
     * stack.
     *
     * @param packet
     *      The ingress packet.
     * @param source
     *      IpAddress of the socket from which the packet is sent.
     */
    virtual void processPacket(Driver::Packet* packet, IpAddress source) = 0;

    /**
     * Attempt to send out packets for any messages with unscheduled/granted
     * bytes in a way that limits queue buildup in the NIC.
     *
     * This method must be called eagerly to allow the Transport to make
     * progress toward sending outgoing messages.
     *
     * @param[out] waitUntil
     *      The rdtsc cycle time when this method should be called again
     *      (this allows the NIC to drain its transmit queue). Only set
     *      when this method returns true.
     * @return
     *      True if more packets are ready to be transmitted when the method
     *      returns; false, otherwise.
     */
    virtual bool trySend(uint64_t* waitUntil) = 0;

    /**
     * Attempt to grant to incoming messages according to the Homa protocol.
     *
     * This method must be called eagerly to allow the Transport to make
     * progress toward receiving incoming messages.
     *
     * @return
     *      True if the method has found some messages to grant; false,
     *      otherwise.
     */
    virtual bool trySendGrants() = 0;

  protected:
    /**
     * Use protected destructor to prevent users from calling delete on pointers
     * to this interface.
     */
    ~Transport() = default;

    /**
     * Free this transport instance.  No one should not access this transport
     * following this call.
     */
    virtual void free() = 0;
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
