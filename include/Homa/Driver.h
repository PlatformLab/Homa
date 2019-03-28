/* Copyright (c) 2010-2019, Stanford University
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

#ifndef HOMA_INCLUDE_HOMA_DRIVER_H
#define HOMA_INCLUDE_HOMA_DRIVER_H

#include "Homa/Exception.h"

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
      public:
        /**
         * Used to hold a driver's serialized byte-format for an Address.  Each
         * driver may define its own byte-format so long as fits within the
         * allowed bytes array.  Additionally, each driver can use the type
         * field to distinguish between raw addresses of different formats.
         */
        struct Raw {
            uint8_t type;  ///< Can be used to distinguish between different raw
                           ///< address formats.
            uint8_t bytes[19];  ///< Holds an Address's serialized byte-format.
        } __attribute__((packed));

      protected:
        /// Address constructor.
        Address() {}
        /// Address copy constructor.
        Address(const Address&) {}

      public:
        virtual ~Address() {}

        /**
         * Return the string representation of this network address.
         */
        virtual std::string toString() const = 0;

        /**
         * Get the serialized byte-format for this network address.
         */
        virtual void toRaw(Raw* raw) const = 0;
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
        /// Packet's source (receive) or destination (send). This pointer is
        /// only valid for the lifetime of this Packet.
        Address* address;

        /// Packet's network priority (send only); 0 is the lowest priority.
        int priority;

        /// Pointer to an array of bytes containing the payload of this Packet.
        void* const payload;

        /// Number of bytes in the payload.
        uint16_t length;

        /// Return the maximum number of bytes the payload can hold.
        virtual uint16_t getMaxPayloadSize() = 0;

      protected:
        /**
         * Construct a Packet. Only called by Packet subclasses.
         */
        explicit Packet(void* payload, uint16_t length = 0)
            : address(NULL)
            , priority(0)
            , payload(payload)
            , length(length)
        {}

        // DISALLOW_COPY_AND_ASSIGN
        Packet(const Packet&) = delete;
        Packet& operator=(const Packet&) = delete;
    };

    /**
     * Driver destructor.
     */
    virtual ~Driver() {}

    /**
     * Return a Driver specific network address for the given string
     * representation of the address. The address string format can be Driver
     * specific.
     *
     * @param addressString
     *      See above.
     * @return
     *      Pointer to an Address object that can be the source or destination
     *      of a Packet. The pointer is valid for the lifetime of this Driver.
     * @throw BadAddress
     *      _addressString_ is malformed.
     *
     * @sa Driver::Packet
     */
    virtual Address* getAddress(std::string const* const addressString) = 0;

    /**
     * Return a Driver specific network address for the given raw serialized
     * byte-format of the address. The raw address byte-format can be Driver
     * specific.
     *
     * @param rawAddress
     *      See above.
     * @return
     *      Pointer to an Address object that can be the source or destination
     *      of a Packet. The pointer is valid for the lifetime of this Driver.
     * @throw BadAddress
     *      _rawAddress_ is malformed.
     *
     * @sa Driver::Packet
     */
    virtual Address* getAddress(Address::Raw const* const rawAddress) = 0;

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
     * The packets provide can be sent asynchronously by the Driver.
     *
     * In general, Packet objects should be considered immutable once they
     * are passed to this method. The Packet::address and Packet::priority
     * fields are two exceptions; they can be modified after this call
     * returns but not concurrently with this call since Packet objects are not
     * thread-safe.
     *
     * A Packet can be resent by simply calling this method again passing
     * the same Packet. However, the Driver may choose to ignore the resend
     * request if a prior send request for the same Packet is still in
     * progress.
     *
     * @param packets
     *      Array of Packet objects to be sent over the network.
     * @param numPackets
     *      Number of Packet objects in _packets_.
     */
    virtual void sendPackets(Packet* packets[], uint16_t numPackets) = 0;

    /**
     * Check to see if any packets have arrived that have not already been
     * returned by this method; if so, it returns some or all of them. The
     * caller must ensure that Packet objects return by this method are
     * eventually released back to the Driver; see Driver::releasePackets().
     *
     * @param maxPackets
     *      The maximum number of Packet objects that should be returned by
     * this method.
     * @param[out] receivedPackets
     *      Received packets are appended to this array in order of arrival.
     *
     * @return
     *      Number of Packet objects being returned.
     *
     * @sa Driver::releasePackets()
     */
    virtual uint32_t receivePackets(uint32_t maxPackets,
                                    Packet* receivedPackets[]) = 0;

    /**
     * Release a collection of Packet objects back to the Driver. Every
     * Packet allocated using allocPacket() or received using
     * receivePackets() must eventually be released back to the Driver using
     * this method. While in general it is safe for applications to keep
     * Packet objects for an indeterminate period of time, doing so may be
     * resource inefficent and adversely affect Driver performance.  As
     * such, it is recommended that Packet objects be released in a timely
     * manner.
     *
     * @param packets
     *      Set of Packet objects which should be released back to the
     * Driver.
     * @param numPackets
     *      Number of Packet objects in _packets_.
     */
    virtual void releasePackets(Packet* packets[], uint16_t numPackets) = 0;

    /**
     * Returns the highest packet priority level this Driver supports (0 is
     * the lowest priority level). The larger the number, the more priority
     * levels are available. For example, if the highest priority level is 7
     * then the Driver has 8 priority levels, ranging from 0 (lowest
     * priority) to 7 (highest priority).
     */
    virtual int getHighestPacketPriority()
    {
        // Default: support only one priority level.
        return 0;
    }

    /**
     * The maximum number of bytes this Driver can send in the payload of a
     * single packet.
     */
    virtual uint32_t getMaxPayloadSize() = 0;

    /**
     * Returns the bandwidth of the network in Mbits/second. If the driver
     * cannot determine the network bandwidth, then it returns 0.
     */
    virtual uint32_t getBandwidth()
    {
        return 0;
    }

    /**
     * Return this Driver's local network Address which it uses as the source
     * Address for outgoing packets. The pointer returned is valid for the
     * lifetime of this Driver.
     */
    virtual Address* getLocalAddress() = 0;
};

/**
 * Thrown if a Driver cannot be initialized properly.
 */
struct DriverInitFailure : public Exception {
    explicit DriverInitFailure(const std::string& where)
        : Exception(where)
    {}
    DriverInitFailure(const std::string& where, std::string msg)
        : Exception(where, msg)
    {}
    DriverInitFailure(const std::string& where, int errNo)
        : Exception(where, errNo)
    {}
    DriverInitFailure(const std::string& where, std::string msg, int errNo)
        : Exception(where, msg, errNo)
    {}
};

/**
 * Thrown if the Address provided is malformed or in some way not useable.
 */
struct BadAddress : public Exception {
    explicit BadAddress(const std::string& where)
        : Exception(where)
    {}
    BadAddress(const std::string& where, std::string msg)
        : Exception(where, msg)
    {}
    BadAddress(const std::string& where, int errNo)
        : Exception(where, errNo)
    {}
    BadAddress(const std::string& where, std::string msg, int errNo)
        : Exception(where, msg, errNo)
    {}
};

}  // namespace Homa

#endif  // HOMA_INCLUDE_HOMA_DRIVER_H
