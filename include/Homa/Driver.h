/* Copyright (c) 2010-2020, Stanford University
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

#include <string>

#include "Homa/Exception.h"

namespace Homa {

/**
 * Used by Homa::Transport to send and receive unreliable datagrams.  Provides
 * the interface to which all Driver implementations must conform.
 *
 * Implementations of this class should be thread-safe.
 */
class Driver {
  public:
    /**
     * Represents a Network address.
     *
     * Each Address representation is specific to the Driver instance that
     * returned the it; they cannot be use interchangeably between different
     * Driver instances.
     */
    using Address = uint64_t;

    /**
     * Used to hold a driver's serialized byte-format for a network address.
     *
     * Each driver may define its own byte-format so long as fits within the
     * bytes array.
     */
    struct WireFormatAddress {
        uint8_t type;  ///< Can be used to distinguish between different wire
                       ///< address formats.
        uint8_t bytes[19];  ///< Holds an Address's serialized byte-format.
    } __attribute__((packed));

    /**
     * Represents a packet of data that can be send or is received over the
     * network. A Packet logically contains only the payload and not any Driver
     * specific headers.
     *
     * A Packet may be Driver specific and should not used interchangeably
     * between Driver instances or implementations.
     *
     * This class is NOT thread-safe but the Transport and Driver's use of
     * Packet objects should be allow the Transport and the Driver to execute on
     * different threads.
     */
    class Packet {
      public:
        /// Packet's source or destination.  When sending a Packet, the address
        /// field will contain the destination Address. When receiving a Packet,
        /// address field will contain the source Address.
        Address address;

        /// Packet's network priority (send only); the lowest possible priority
        /// is 0.  The highest priority is positive number defined by the
        /// Driver; the highest priority can be queried by calling the method
        /// getHighestPacketPriority().
        int priority;

        /// Pointer to an array of bytes containing the payload of this Packet.
        /// This array is valid until the Packet is released back to the Driver.
        void* const payload;

        /// Number of bytes in the payload.
        int length;

        /// Return the maximum number of bytes the payload can hold.
        virtual int getMaxPayloadSize() = 0;

      protected:
        /**
         * Construct a Packet.
         */
        explicit Packet(void* payload, int length = 0)
            : address()
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
    virtual ~Driver() = default;

    /**
     * Return a Driver specific network address for the given string
     * representation of the address.
     *
     * @param addressString
     *      The string representation of the address to return.  The address
     *      string format can be Driver specific.
     *
     * @return
     *      Address that can be the source or destination of a Packet.
     *
     * @throw BadAddress
     *      _addressString_ is malformed.
     */
    virtual Address getAddress(std::string const* const addressString) = 0;

    /**
     * Return a Driver specific network address for the given serialized
     * byte-format of the address.
     *
     * @param wireAddress
     *      The serialized byte-format of the address to be returned.  The
     *      format can be Driver specific.
     *
     * @return
     *      Address that can be the source or destination of a Packet.
     *
     * @throw BadAddress
     *      _rawAddress_ is malformed.
     */
    virtual Address getAddress(WireFormatAddress const* const wireAddress) = 0;

    /**
     * Return the string representation of a network address.
     *
     * @param address
     *      Address whose string representation should be returned.
     */
    virtual std::string addressToString(const Address address) = 0;

    /**
     * Serialize a network address into its Raw byte format.
     *
     * @param address
     *      Address to be serialized.
     * @param[out] wireAddress
     *      WireFormatAddress object to which the Address is serialized.
     */
    virtual void addressToWireFormat(const Address address,
                                     WireFormatAddress* wireAddress) = 0;

    /**
     * Allocate a new Packet object from the Driver's pool of resources. The
     * caller must eventually release the packet by passing it to a call to
     * releasePacket().
     */
    virtual Packet* allocPacket() = 0;

    /**
     * Send a packet over the network.
     *
     * The packet provide can be sent asynchronously by the Driver.
     *
     * If the Driver supports buffering packets for batched sends (via the
     * cork() setting), the Driver may also send previously buffered packets
     * during this call.
     *
     * In general, Packet objects should be considered immutable once they
     * are passed to this method.
     *
     * A Packet can be resent by simply calling this method again passing
     * the same Packet. However, the Driver may choose to ignore the resend
     * request if a prior send request for the same Packet is still in
     * progress.
     *
     * Calling this method does NOT change ownership of the packet; the caller
     * still owns the packet.
     *
     * @param packet
     *      Packet to be sent over the network.
     */
    virtual void sendPacket(Packet* packet) = 0;

    /**
     * Request that the Driver enter the "corked" mode where outbound packets
     * are queued instead of immediately sent so that they can be more
     * efficiently sent out to the network in a batch.
     *
     * If the Driver supports this feature, packets may be queued until either
     * uncork() is called or some internal buffering limit is reached.
     *
     * @sa Driver::uncork(), Driver::sendPacket()
     */
    virtual void cork() {}

    /**
     * Request that the Driver exit "corked" mode and that any buffered packets
     * be sent out immediately.
     *
     * @sa Driver::cork(), Driver::sendPacket()
     */
    virtual void uncork() {}

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
     * resource inefficient and adversely affect Driver performance.  As
     * such, it is recommended that Packet objects be released in a timely
     * manner.
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
    virtual uint32_t getBandwidth() = 0;

    /**
     * Return this Driver's local network Address which it uses as the source
     * Address for outgoing packets.
     */
    virtual Address getLocalAddress() = 0;

    /**
     * Return the number of bytes that have been passed to the Driver through
     * the sendPacket() call but have not yet been pushed out to the network.
     */
    virtual uint32_t getQueuedBytes() = 0;
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
