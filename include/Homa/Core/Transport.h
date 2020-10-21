/* Copyright (c) 2020, Stanford University
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
 * @file Homa/Core/Transport.h
 *
 * Contains the low-level Homa Transport API.  Advanced users of the Homa
 * Transport library should include this header.
 */

#ifndef HOMA_INCLUDE_HOMA_CORE_TRANSPORT_H
#define HOMA_INCLUDE_HOMA_CORE_TRANSPORT_H

#include <Homa/Homa.h>

namespace Homa::Core {

/**
 * Minimal set of low-level API that can be used to create Homa-based transports
 * for different runtime environments (e.g. polling, kernel threading,
 * green threads, etc).
 *
 * The execution of a transport is driven through repeated calls to methods
 * like checkTimeouts(), processPacket(), trySend(), and trySendGrants(); the
 * transport will not make any progress otherwise. Advanced users can compose
 * these methods in a way that suits them best.
 *
 * This class is thread-safe.
 */
class Transport : public TransportBase {
  public:
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
         * Invoked when an incoming message arrives and needs to dispatched to
         * its destination in the user application for processing.
         *
         * Here are a few example use cases of this callback:
         * <ul>
         * <li>
         *   Interaction with the user's thread scheduler: e.g., an application
         *   may want to block on receive until a message is delivered, so this
         *   method can be used to wake up blocking threads.
         * <li>
         *   High-performance message dispatch: e.g., an application may choose
         *   to implement the message receive queue with a concurrent MPMC queue
         *   as opposed to a linked-list protected by a mutex;
         * <li>
         *   Lightweight synchronization: e.g., the socket table that maps port
         *   numbers to sockets is a read-mostly data structure, so lookup
         *   operations can benefit from synchronization schemes such as RCU.
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
};

}  // namespace Homa::Core

#endif  // HOMA_INCLUDE_HOMA_CORE_TRANSPORT_H