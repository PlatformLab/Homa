/* Copyright (c) 2010-2018, Stanford University
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

#include <string>
#include <vector>

namespace Homa {

/**
 * Used by Homa::Transport to send and receive unreliable datagrams. This is an
 * abstract class.
 *
 * Note: some implementation may require the application call Driver::poll() in
 * order to make progress.
 *
 * Implementations of this class should be thread-safe.
 */
class Driver {
  public:
    /**
     * A base class for Driver specific network addresses.
     */
    class Address {
      protected:
        Address() {}
        Address(const Address& other) {}

      public:
        virtual ~Address() {}

        /**
         * Return the string representation of this network address.
         */
        virtual std::string toString() const = 0;
    };

    /**
     * Represents a packet of data that can be send or is received over the
     * network using implementations of Homa::Driver. A Packet logically
     * contains only the payload and not any Driver specific headers. When
     * sending a Packet, the address field will contain the destination Address.
     * When receiving a Packet, address field will contain the source Address.
     *
     * This class defines part of the Driver interface.
     *
     * A Packet may be Driver specific and should not used interchangeably
     * between Driver instances or implementations.
     *
     * This class is NOT thread-safe but the Transport and Driver's use of
     * Packet objects should be allow the Transport and the Driver to execute on
     * different threads.
     *
     * @see Related Driver methods include: Driver::allocPacket(),
     *      Driver::releasePackets(), Driver::sendPackets(),
     *      Driver::receivePackets().
     */
    class Packet {
      public:
        /// Packet's source (receive) or destination (send).
        Address* address;

        /// Packet's network priority (send only); 0 is the lowest priority.
        int priority;

        /// Pointer to an array of bytes containing the payload of this Packet.
        void* const payload;

        /// Number of bytes the payload holds.
        uint16_t len;

        /// Maxumum number of bytes the payload can hold.
        uint16_t const MAX_PAYLOAD_SIZE;
    };

    /**
     * Driver destructor.
     */
    virtual ~Driver() {}

    /**
     * Return a Driver specific network address for the given string
     * representation of the address. Address strings are also  Driver specific.
     *
     * @param addressString
     *      See above.
     * @return
     *      Pointer to an Address object that can be the source or destination
     *      of a Packet.
     *
     * @sa Driver::Packet
     */
    virtual Address* getAddress(std::string const* const addressString) = 0;

    /**
     * Allocate a new Packet object from the Driver's pool of resources. The
     * caller must ensure that the Packet returned by this method is
     * eventually released back to the Driver; see Driver::releasePackets().
     *
     * @sa Driver::releasePackets()
     */
    virtual Packet* allocPacket() = 0;

    /**
     * Send a burst of packets over the network.
     *
     * The packets provide can be sent asynchrounously by the Driver.
     *
     * In general, Packet objects should be considered immutable once they are
     * passed to this method. The Packet::address and Packet::priority fields
     * are two exceptions; they can be modified after this call returns but not
     * currently with this call since Packet objects are not thread-safe.
     *
     * A Packet can be resent by simply calling this method again passing the
     * same Packet. However, the Driver may choose to ignore the resend request
     * if a prior send request for the same Packet is still in progress.
     *
     * @param packets
     *      Array of Packet objects to be sent over the network.
     * @param numPackets
     *      Number of Packet objects in _packets_.
     */
    virtual void sendPackets(Packet const* const packets[],
                             uint16_t numPackets) = 0;

    /**
     * Check to see if any packets have arrived that have not already been
     * returned by this method; if so, it returns some or all of them. The
     * caller must ensure that Packet objects return by this method are
     * eventually released back to the Driver; see Driver::releasePackets().
     *
     * @param maxPackets
     *      The maximum number of Packet objects that should be returned by this
     *      method.
     * @param[out] receivedPackets
     *      Recevied packets are appended to this array in order of arrival.
     *
     * @return
     *      Number of Packet objects being returned.
     *
     * @sa Driver::releasePackets()
     */
    virtual uint32_t receivePackets(uint32_t maxPackets,
                                    Packet* receivedPackets[]) = 0;

    /**
     * Release a collection of Packet objects back to the Driver. Every Packet
     * allocated using allocPacket() or recieved using receivePackets() must
     * eventually be released back to the Driver using this method. While in
     * general it is safe for applications to keep Packet objects for an
     * indeterminate period of time, doing so may be resource inefficent and
     * adversely affect Driver performance.  As such, it is recommended that
     * Packet objects be released in a timely manner.
     *
     * @param packets
     *      Set of Packet objects which should be released back to the Driver.
     * @param numPackets
     *      Number of Packet objects in _packets_.
     */
    virtual void releasePackets(Packet* packets[], uint16_t numPackets) = 0;

    /**
     * Returns the highest packet priority level this Driver supports (0 is
     * the lowest priority level). The larger the number, the more priority
     * levels are available. For example, if the highest priority level is 7
     * then the Driver has 8 priority levels, ranging from 0 (lowest priority)
     * to 7 (highest priority).
     */
    virtual int getHighestPacketPriority() {
        // Default: support only one priority level.
        return 0;
    }

    /**
     * Returns the bandwidth of the network in Mbits/second. If the driver
     * cannot determine the network bandwidth, then it returns 0.
     */
    virtual uint32_t getBandwidth() {
        return 0;
    }
};

}  // namespace Homa

#endif  // HOMA_HOMA_H
