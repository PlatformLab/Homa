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
 * A simple wrapper struct around an IP address in binary format.
 *
 * This struct is meant to provide some type-safety when manipulating IP
 * addresses. In order to avoid any runtime overhead, this struct contains
 * nothing more than the IP address, so it is trivially copyable.
 */
struct IpAddress final {
    /// IPv4 address in host byte order.
    uint32_t addr;

    /**
     * Unbox the IP address in binary format.
     */
    explicit operator uint32_t()
    {
        return addr;
    }

    /**
     * Equality function for IpAddress, for use in std::unordered_maps etc.
     */
    bool operator==(const IpAddress& other) const
    {
        return addr == other.addr;
    }

    /**
     * This class computes a hash of an IpAddress, so that IpAddress can be used
     * as keys in unordered_maps.
     */
    struct Hasher {
        /// Return a "hash" of the given IpAddress.
        std::size_t operator()(const IpAddress& address) const
        {
            return std::hash<typeof(addr)>{}(address.addr);
        }
    };

    static std::string toString(IpAddress address);
    static IpAddress fromString(const char* addressStr);
};
static_assert(std::is_trivially_copyable<IpAddress>());

/**
 * Represents a packet of data that can be send or is received over the network.
 * A Packet logically contains only the transport-layer (L4) Homa header in
 * addition to application data.
 *
 * This struct specifies the minimal object layout of a packet that the core
 * Homa protocol depends on (e.g., Homa::Core::{Sender, Receiver}); this is
 * useful for applications that only want to use the transport layer of this
 * library and have their own infrastructures for sending and receiving packets.
 */
struct PacketSpec {
    /// Pointer to an array of bytes containing the payload of this Packet.
    /// This array is valid until the Packet is released back to the Driver.
    void* payload;

    /// Number of bytes in the payload.
    int32_t length;
} __attribute__((packed));
static_assert(std::is_trivial<PacketSpec>());

/**
 * Used by Homa::Transport to send and receive unreliable datagrams.  Provides
 * the interface to which all Driver implementations must conform.
 *
 * Implementations of this class should be thread-safe.
 */
class Driver {
  public:
    /// Import PacketSpec into the Driver namespace.
    using Packet = PacketSpec;

    /**
     * Driver destructor.
     */
    virtual ~Driver() = default;

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
     * @param destination
     *      IP address of the packet destination.
     * @param priority
     *      Packet's network priority; the lowest possible priority is 0.
     *      The highest priority is positive number defined by the Driver;
     *      the highest priority can be queried by calling the method
     *      getHighestPacketPriority().
     */
    virtual void sendPacket(Packet* packet, IpAddress destination,
                            int priority) = 0;

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
     *      this method.
     * @param[out] receivedPackets
     *      Received packets are appended to this array in order of arrival.
     * @param[out] sourceAddresses
     *      Source IP addresses of the received packets are appended to this
     *      array in order of arrival.
     *
     * @return
     *      Number of Packet objects being returned.
     *
     * @sa Driver::releasePackets()
     */
    virtual uint32_t receivePackets(uint32_t maxPackets,
                                    Packet* receivedPackets[],
                                    IpAddress sourceAddresses[]) = 0;

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
     * Return this Driver's local IP address which it uses as the source
     * address for outgoing packets.
     */
    virtual IpAddress getLocalAddress() = 0;

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
