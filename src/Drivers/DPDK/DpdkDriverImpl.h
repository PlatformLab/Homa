/* Copyright (c) 2019-2020, Stanford University
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

#include <Homa/Drivers/DPDK/DpdkDriver.h>
#include <Homa/Drivers/Util/QueueEstimator.h>
#include <rte_common.h>
#include <rte_config.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>
#include <rte_ring.h>
#include <rte_version.h>

#include <chrono>
#include <unordered_map>

#include "MacAddress.h"
#include "ObjectPool.h"
#include "SpinLock.h"
#include "Tub.h"

namespace Homa {
namespace Drivers {
namespace DPDK {

// Number of descriptors to allocate for the tx/rx rings
const int NDESC = 256;

// Maximum number of packet buffers that the memory pool can hold. The
// documentation of `rte_mempool_create` suggests that the optimum value
// (in terms of memory usage) of this number is a power of two minus one.
const int NB_MBUF = 16383;

// If cache_size is non-zero, the rte_mempool library will try to limit the
// accesses to the common lockless pool, by maintaining a per-lcore object
// cache. It is advised to choose cache_size to have "NB_MBUF modulo cache_size
// == 0": if this is not the case, some elements will always stay in the pool
// and will never be used. See DPDK rte_mempool_create()
const int MEMPOOL_CACHE_SIZE = 32;

// The number of mbufs the driver should try to reserve for receiving packets.
// Prevents applications from claiming more mbufs once the number of available
// mbufs reaches this level.
const uint32_t NB_MBUF_RESERVED = 4096;

// The number of packets that can be held in loopback before they get dropped
const uint32_t NB_LOOPBACK_SLOTS = 4096;

// The number of packets that the driver can buffer while corked.
const uint16_t MAX_PKT_BURST = 32;

/// Size of VLAN tag, in bytes. We are using the PCP (Priority Code Point)
/// field defined in the VLAN tag to specify the packet priority.
const uint32_t VLAN_TAG_LEN = 4;

/// Strictly speaking, this DPDK driver is supposed to send/receive IP packets;
/// however, it currently only records the source IP address right after the
/// Ethernet header for simplicity.
const uint32_t IP_HDR_LEN = sizeof(IpAddress);

// Size of Ethernet header including VLAN tag plus IP header, in bytes.
const uint32_t PACKET_HDR_LEN = ETHER_HDR_LEN + VLAN_TAG_LEN + IP_HDR_LEN;

// The MTU (Maximum Transmission Unit) size of an Ethernet frame, which is the
// maximum size of the packet an Ethernet frame can carry in its payload. This
// is normally 1500 bytes.
const uint32_t MAX_PAYLOAD_SIZE = ETHER_MTU;

/// Map from priority levels to values of the PCP field. Note that PCP = 1
/// is actually the lowest priority, while PCP = 0 is the second lowest.
constexpr uint16_t PRIORITY_TO_PCP[8] = {1 << 13, 0 << 13, 2 << 13, 3 << 13,
                                         4 << 13, 5 << 13, 6 << 13, 7 << 13};

// This enum define various ethernet payload types as it must be specified
// in EthernetHeader field `etherType'.
enum EthPayloadType {
    IP_V4 = 0x0800,  // Standard ethernet type when the payload is an
                     // ip packet.
    HOMA = 0x88b5    // Used by Homa raw-Ethernet drivers.
};

/**
 * Allocated to store packet data when mbufs are not available.
 */
struct OverflowBuffer {
    /// Array of bytes used to store a packet's payload.
    char* data[MAX_PAYLOAD_SIZE];
};

/**
 * Holds the private members of the DpdkDriver so that they are not exposed in
 * the API header.
 */
class DpdkDriver::Impl {
  public:
    /**
     * Dpdk specific Packet object used to track a its lifetime and
     * contents.
     */
    struct Packet {
        explicit Packet(struct rte_mbuf* mbuf, void* data);
        explicit Packet(OverflowBuffer* overflowBuf);

        /// C-style "inheritance"
        Driver::Packet base;

        /// Used to indicate whether the packet is backed by an DPDK mbuf or a
        /// driver-level OverflowBuffer.
        enum BufferType { MBUF, OVERFLOW_BUF } bufType;  ///< Packet BufferType.

        /// A reference to the buffer that backs this packet.
        union {
            struct rte_mbuf* mbuf;
            OverflowBuffer* overflowBuf;
        } bufRef;

        /// The memory location of this packet's header. The header should be
        /// PACKET_HDR_LEN in length.
        void* header;
    };

    Impl(const char* ifname, const Config* const config = nullptr);
    Impl(const char* ifname, int argc, char* argv[],
         const Config* const config = nullptr);
    Impl(const char* ifname, NoEalInit _, const Config* const config = nullptr);
    virtual ~Impl();

    // Interface Methods
    Driver::Packet* allocPacket();
    void sendPacket(Driver::Packet* packet, IpAddress destination,
                    int priority);
    void cork();
    void uncork();
    uint32_t receivePackets(uint32_t maxPackets,
                            Driver::Packet* receivedPackets[],
                            IpAddress sourceAddresses[]);
    void releasePackets(Driver::Packet* packets[], uint16_t numPackets);
    int getHighestPacketPriority();
    uint32_t getMaxPayloadSize();
    uint32_t getBandwidth();
    IpAddress getLocalAddress();
    uint32_t getQueuedBytes();

  private:
    void _eal_init(int argc, char* argv[]);
    void _init();
    static uint16_t txBurstCallback(uint16_t port_id, uint16_t queue,
                                    struct rte_mbuf* pkts[], uint16_t nb_pkts,
                                    void* user_param);

    /// Name of the Linux network interface to be used by DPDK.
    std::string ifname;

    /// Stores the NIC's physical port id addressed by the instantiated
    /// driver.
    uint16_t port;

    /// Address resolution table that translates IP addresses to MAC addresses.
    std::unordered_map<IpAddress, MacAddress, IpAddress::Hasher> arpTable;

    /// Stores the IpAddress of the driver.
    IpAddress localIp;

    /// Stores the HW address of the NIC (either native or set by override).
    MacAddress localMac;

    /// Stores the driver's maximum network packet priority (either default or
    /// set by override).
    const int HIGHEST_PACKET_PRIORITY;

    /// Protects access to the packetPool.
    SpinLock packetLock;

    /// Provides memory allocation for the DPDK specific implementation of a
    /// Driver Packet.
    ObjectPool<Packet> packetPool;

    /// Provides memory allocation for packet storage when mbuf are running out.
    ObjectPool<OverflowBuffer> overflowBufferPool;

    /// The number of mbufs that have been given out to callers in Packets.
    uint32_t mbufsOutstanding;

    /// Holds packet buffers that are dequeued from the NIC's HW queues
    /// via DPDK.
    struct rte_mempool* mbufPool;

    /// Holds packets that are addressed to localhost instead of going through
    /// the HW queues.
    struct rte_ring* loopbackRing;

    /// Members involved with receive (rx) operations.
    struct Rx {
        /**
         * Basic Constructor.
         */
        Rx()
            : mutex()
        {}

        /// Provides thread safety for receive (rx) operations.
        SpinLock mutex;
    } rx;

    /// Members involved with transmit (tx) operations.
    struct Tx {
        /**
         * Basic Constructor.
         */
        Tx()
            : mutex()
            , buffer(nullptr)
            , stats()
        {}

        /// Provides thread safety for transmit (tx) operations.
        SpinLock mutex;
        /// Contains the packets buffered for sending when the driver is corked.
        struct rte_eth_dev_tx_buffer* buffer;
        /// Contains the transmit statistics.
        struct Stats {
            /**
             * Basic Constructor.
             */
            Stats()
                : mutex()
                , bufferedBytes(0)
                , queueEstimator(0)
            {}

            /// Provides thread safe access to the stats block.
            SpinLock mutex;
            /// Number of bytes buffered but not sent.
            uint64_t bufferedBytes;
            /// Estimates the number of bytes waiting to be transmitted in the
            /// NICs transmit queue.
            Util::QueueEstimator<std::chrono::steady_clock> queueEstimator;
        } stats;
    } tx;

    /// Hardware packet filter is provided by the NIC
    std::atomic<bool> hasHardwareFilter;

    /// True if the Driver should buffer sends for batched transmission. False,
    /// if the Driver should
    std::atomic<int> corked;

    /// Effective network bandwidth, in Mbits/second.
    std::atomic<uint32_t> bandwidthMbps;
};

}  // namespace DPDK
}  // namespace Drivers
}  // namespace Homa

#endif  // HOMA_DRIVERS_DPDK_DPDKDRIVERIMPL_H
