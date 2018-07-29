/* Copyright (c) 2015-2018, Stanford University
 * Copyright (c) 2014-2015, Huawei Technologies Co. Ltd.
 * Copyright (c) 2014-2016, NEC Corporation
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

#ifndef HOMA_DPDKDRIVER_H
#define HOMA_DPDKDRIVER_H

#include "Driver.h"
#include "MacAddress.h"
#include "ObjectPool.h"
#include "SpinLock.h"
#include "Tub.h"

#include <unordered_map>
#include <vector>

// Forward declarations, so we don't have to include DPDK headers here.
struct rte_mbuf;
struct rte_mempool;
struct rte_ring;

namespace Homa {

// Forward declarations
class MacAddress;

/**
 * A Driver for [DPDK](dpdk.org) communication. Simple packet send/receive style
 * interface. See Driver.h for more detail.
 *
 * This class is thread-safe.
 *
 * @sa Driver
 */
class DpdkDriver : public Driver {
    // forward declarations to avoid including implmentation in the header.
    class DpdkPacket;
    struct OverflowBuffer;

  public:
    /**
     * Construct a DpdkDriver.
     *
     * This constructor should be used in the common case where this DpdkDriver
     * is the only part the application using DPDK. Note: This constructor will
     * initialize the DPDK EAL with default values.
     *
     * @param port
     *      Selects which physical port to use for communication.
     * @throw DriverInitFailure
     *      Thrown if DpdkDriver fails to initialize for any reason.
     */
    explicit DpdkDriver(int port);

    /**
     * Construct a DpdkDriver and initilize the DPDK EAL using the provided
     * _argc_ and _argv_. [Advanced Usage]
     *
     * This constructor should be used if the caller wants to control what
     * parameters are provided to DPDK EAL initialization. The input parameters
     * _argc_ and _argv_ will be provided to rte_eal_init() directly. See the
     * DPDK documentation for initilization options.
     *
     * This constructor will maintain the currently set thread affinity by
     * overriding the default affinity set by rte_eal_init().
     *
     * @param port
     *      Selects which physical port to use for communication.
     * @param argc
     *      Parameter passed to rte_eal_init().
     * @param argv
     *      Parameter passed to rte_eal_init().
     * @throw DriverInitFailure
     *      Thrown if DpdkDriver fails to initialize for any reason.
     */
    explicit DpdkDriver(int port, int argc, char* argv[]);

    /// Used to signal to the DpdkDriver constructor that the DPDK EAL should
    /// not be initialized.
    enum NoEalInit { NO_EAL_INIT };
    /**
     * Construct a DpdkDriver without initilizing the DPDK EAL. [Advanced Usage]
     *
     * This constuctor is used when parts of the application other than the
     * DpdkDriver are using DPDK and the caller wants to take responsiblity for
     * calling rte_eal_init(). The caller must ensure that rte_eal_init() is
     * called before calling this constructor.
     *
     * @param port
     *      Selects which physical port to use for communication.
     * @param _
     *      Parameter is used only to define this constructors alternate
     *      signature.
     * @throw DriverInitFailure
     *      Thrown if DpdkDriver fails to initialize for any reason.
     */
    explicit DpdkDriver(int port, NoEalInit _);

    /**
     * DpdkDriver destructor.
     */
    virtual ~DpdkDriver();

    /**
     * Return a DpdkDriver compatible network address.
     *
     * See Driver::getAddress() for more details.
     *
     * @sa Driver::getAddress()
     */
    virtual Driver::Address* getAddress(std::string const* const addressString);

    /// See Driver::allocPacket()
    virtual Packet* allocPacket();

    /// See Driver::sendPackets()
    virtual void sendPackets(Packet* packets[], uint16_t numPackets);

    /// See Driver::receivePackets()
    virtual uint32_t receivePackets(uint32_t maxPackets,
                                    Packet* receivedPackets[]);

    /// See Driver::releasePackets()
    virtual void releasePackets(Packet* packets[], uint16_t numPackets);

    /// See Driver::getHighestPacketPriority()
    virtual int getHighestPacketPriority();

    /// See Driver::getBandwidth()
    virtual uint32_t getBandwidth();

    /// See Driver::getLocalAddress()
    virtual Driver::Address* getLocalAddress();

  private:
    /// Provides thread safety for Address operations.
    SpinLock addressLock;

    /// Collection of requested DPDK address that can be reused if the same
    /// address is requested again.
    std::unordered_map<std::string, MacAddress*> addressCache;

    /// Provides thread safety for Packet management operations.
    SpinLock packetLock;

    /// Provides memory allocation for the DPDK specific implentation of a
    /// Driver Packet.
    ObjectPool<DpdkPacket> packetPool;

    /// Provides memory allocation for packet storage when mbuf are running out.
    ObjectPool<OverflowBuffer> overflowBufferPool;

    /// Stores the MAC address of the NIC (either native or overriden).
    Tub<MacAddress> localMac;

    /// Stores the NIC's physical port id addressed by the instantiated driver.
    uint8_t portId;

    /// Holds packet buffers that are dequeued from the NIC's HW queues
    /// via DPDK.
    struct rte_mempool* mbufPool;

    /// Holds packets that are addressed to localhost instead of going through
    /// the HW queues.
    struct rte_ring* loopbackRing;

    /// Provides thread safety for receive (rx) operations.
    SpinLock rxLock;

    /// Provides thread safte for transmit (tx) operations.
    SpinLock txLock;

    /// NIC allows queuing of transmit packets without holding a software lock.
    bool hasTxLockFreeSupport;

    /// Hardware packet filter is provided by the NIC
    bool hasHardwareFilter;

    /// Effective network bandwidth, in Mbits/second.
    uint32_t bandwidthMbps;

    void _eal_init(int argc, char* argv[]);
    void _init(int port);
    DpdkPacket* _allocMbufPacket();
    void _sendPackets(struct rte_mbuf* tx_pkts[], uint16_t nb_pkts);

    // Packet(DpdkDriver)
    DpdkDriver(const DpdkDriver&) = delete;
    DpdkDriver& operator=(const DpdkDriver&) = delete;
};

}  // namespace Homa

#endif  // HOMA_DPDKDRIVER_H
