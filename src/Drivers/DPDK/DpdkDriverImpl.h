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

#ifndef HOMA_DRIVERS_DPDK_DPDKDRIVERIMPL_H
#define HOMA_DRIVERS_DPDK_DPDKDRIVERIMPL_H

#include "Homa/Driver.h"
#include "Homa/Drivers/DPDK/DpdkDriver.h"

#include "../../ObjectPool.h"
#include "../../SpinLock.h"
#include "../../Tub.h"

#include "MacAddress.h"

#include <unordered_map>
#include <vector>

// Forward declarations, so we don't have to include DPDK headers here.
struct rte_mbuf;
struct rte_mempool;
struct rte_ring;

namespace Homa {

namespace Drivers {
namespace DPDK {

// Forward declarations
class MacAddress;

/**
 * Implementation of the DpdkDriver.
 *
 * @sa DpdkDriver
 */
class DpdkDriverImpl : public DpdkDriver {
    // forward declarations to avoid including implmentation in the header.
    class DpdkPacket;
    struct OverflowBuffer;

  public:
    explicit DpdkDriverImpl(int port);
    explicit DpdkDriverImpl(int port, int argc, char* argv[]);
    explicit DpdkDriverImpl(int port, NoEalInit _);
    virtual ~DpdkDriverImpl();

    /// See Driver::getAddress()
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

    /// See Driver::getMaxPayloadSize()
    virtual uint32_t getMaxPayloadSize();

    /// See Driver::getBandwidth()
    virtual uint32_t getBandwidth();

    /// See Driver::getLocalAddress()
    virtual Driver::Address* getLocalAddress();

    /// See DpdkDriver::setLocalAddress()
    virtual void setLocalAddress(std::string const* const addressString);

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

    DpdkDriverImpl(const DpdkDriverImpl&) = delete;
    DpdkDriverImpl& operator=(const DpdkDriverImpl&) = delete;
};

}  // namespace DPDK
}  // namespace Drivers
}  // namespace Homa

#endif  // HOMA_DRIVERS_DPDK_DPDKDRIVERIMPL_H
