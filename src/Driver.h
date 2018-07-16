/* Copyright (c) 2010-2018, Stanford University
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER
 * RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF
 * CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
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
     * This class is NOT thread-safe but should be implemented such that the
     * Driver, Transport, and application can run on different threads. A Driver
     * should only access Packet state at well defined times during sending
     * and receiving. Transports The Transport should ensure the Driver is not
     * operating on the Packet before access Packet state by calling
     * waitPacketsDone();
     *
     * @see Related Driver methods include: Driver::allocPacket(),
     *      Driver::releasePackets(), Driver::sendPackets(),
     *      Driver::waitPacketsDone(), Driver::receivePackets(),
     */
    class Packet {
      public:
        /// Packet's source (for incomming) or destination (for outgoing).
        Address* address;

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
     * Return a new Driver specific network address for the given string
     * representation of the address. Address strings are Driver specific.
     * Address objects are potentally expensive to create so the transport
     * should reuse addresses when possible.
     *
     * @param addressString
     *      See above.
     * @return
     *      An address that must be released later by the caller.
     *
     * @sa Driver::releaseAddress()
     */
    virtual Address* getAddress(const std::string& addressString) = 0;

    /**
     * Release an Address back to the Driver.
     *
     * @param address
     *      Pointer to Address object to be released.
     *
     * @sa Driver::getAddress()
     */
    virtual void releaseAddress(Address* address) = 0;

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
     * Packet objects may be sent asynchornously by the Driver and should not be
     * modified once while the Driver is in the process of sending the packet.
     * If a Packet needs to be modified, e.g. to be resent, the caller should
     * wait until the Driver finishes processing the Packet by calling the
     * waitPacketsDone() method.
     *
     * @param packets
     *      Set of Packet objects to be sent over the network.
     * @param priorities
     *      Set of network priorities conresponding to the Packet objects in
     *      the _packets_ vector.  0 is the lowest priority.
     *
     * @sa Driver::waitPacketsDone()
     */
    virtual void sendPackets(std::vector<Packet*>& packets,
                             std::vector<int> priorities) = 0;

    /**
     * Ensure a set of Packet objects are not in use by the Driver.
     *
     * Packet objects are not in general thread-safe and the Driver will access
     * the contents of a Packet while the Packet is being sent. To prvent
     * corruption, applications must NOT modify a Packet's contents while the
     * Driver still has access. The waitPacketsDone() method can be used to
     * ensure the Driver has finished using a Packet and is thus safe to modify.
     *
     * @param packets
     *      Set of Packet objects that will be unused by the Driver when this
     *      method returns.
     *
     * @sa Driver::Packet, Driver::sendPackets()
     */
    virtual void waitPacketsDone(std::vector<Packet*>& packets) = 0;

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
     *      Recevied packets are appended to this vector in order of arrival.
     *
     * @return
     *      Number of Packet objects being returned.
     *
     * @sa Driver::releasePackets()
     */
    virtual uint32_t receivePackets(uint32_t maxPackets,
                                    std::vector<Packet*>& receivedPackets) = 0;

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
     */
    virtual void releasePackets(std::vector<Packet*>& packets) = 0;

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
     * Returns the bandwidth of the network in Mbits/second. If the
     * driver cannot determine the network bandwidth, then it returns 0.
     */
    virtual uint32_t getBandwidth() {
        return 0;
    }

    /**
     * Perform any necessary background work that would be too expensive to
     * perform inline in other Driver methods. Some implementation may require
     * this method be called in order to make progress.
     */
    virtual void poll() {}
};

}  // namespace Homa

#endif  // HOMA_HOMA_H
