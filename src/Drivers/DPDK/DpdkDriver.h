/* Copyright (c) 2019, Stanford University
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

#ifndef HOMA_DRIVERS_DPDK_DPDKDRIVER_H
#define HOMA_DRIVERS_DPDK_DPDKDRIVER_H

#include <Homa/Drivers/DPDK/DpdkDriver.h>

#include <rte_common.h>
#include <rte_config.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>
#include <rte_ring.h>
#include <rte_version.h>

#include "ObjectPool.h"
#include "SpinLock.h"
#include "Tub.h"

#include "MacAddress.h"

namespace Homa {
namespace Drivers {
namespace DPDK {

/// Default number of arguments for EAL init.
const int default_eal_argc = 1;
/// Default arguments for EAL init.
const char* default_eal_argv[] = {"homa", NULL};

// Number of descriptors to allocate for the tx/rx rings
const int NDESC = 256;

// Maximum number of packet buffers that the memory pool can hold. The
// documentation of `rte_mempool_create` suggests that the optimum value
// (in terms of memory usage) of this number is a power of two minus one.
const int NB_MBUF = 8191;

// If cache_size is non-zero, the rte_mempool library will try to limit the
// accesses to the common lockless pool, by maintaining a per-lcore object
// cache. It is advised to choose cache_size to have "NB_MBUF modulo cache_size
// == 0": if this is not the case, some elements will always stay in the pool
// and will never be used. See DPDK rte_mempool_create()
const int MEMPOOL_CACHE_SIZE = 32;

// The number of mbufs the driver should try to reserve for receiving packets.
// Prevents applications from claiming more mbufs once the number of available
// mbufs reaches this level.
const uint32_t NB_MBUF_RESERVED = 1024;

/// Size of VLAN tag, in bytes. We are using the PCP (Priority Code Point)
/// field defined in the VLAN tag to specify the packet priority.
const uint32_t VLAN_TAG_LEN = 4;

// Size of Ethernet header including VLAN tag, in bytes.
const uint32_t PACKET_HDR_LEN = ETHER_HDR_LEN + VLAN_TAG_LEN;

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
struct Internal {
    /**
     * Dpdk specific Packet object used to track a its lifetime and
     * contents.
     */
    class Packet : public Driver::Packet {
      public:
        explicit Packet(struct rte_mbuf* mbuf, void* data);
        explicit Packet(OverflowBuffer* overflowBuf);

        /// see Driver::Packet::getMaxPayloadSize()
        virtual uint16_t getMaxPayloadSize()
        {
            return MAX_PAYLOAD_SIZE;
        }

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

      private:
        Packet(const Packet&) = delete;
        Packet& operator=(const Packet&) = delete;
    };

    Internal();
    void _eal_init(int argc, char* argv[]);
    void _init(int port);
    Packet* _allocMbufPacket();
    void _sendPackets(struct rte_mbuf* tx_pkts[], uint16_t nb_pkts);

    /// Provides thread safety for Packet management operations.
    SpinLock packetLock;

    /// Provides memory allocation for the DPDK specific implementation of a
    /// Driver Packet.
    ObjectPool<Packet> packetPool;

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
};

}  // namespace DPDK
}  // namespace Drivers
}  // namespace Homa

#endif  // HOMA_DRIVERS_DPDK_DPDKDRIVER_H
