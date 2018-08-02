/* Copyright (c) 2015-2018, Stanford University
 * Copyright (c) 2014-2015, Huawei Technologies Co. Ltd.
 * Copyright (c) 2014-2016, NEC Corporation
 * The original version of this module was contributed by Anthony Iliopoulos
 * at DBERC, Huawei
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

#include "DpdkDriver.h"

#include "Util.h"

#include <rte_common.h>
#include <rte_config.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>
#include <rte_ring.h>
#include <rte_version.h>

#include <mutex>

#include <unistd.h>

namespace Homa {

namespace {
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
};  // namespace

/**
 * Allocated to store packet data when mbufs are not available.
 */
struct DpdkDriver::OverflowBuffer {
    char* header[PACKET_HDR_LEN];
    char* data[MAX_PAYLOAD_SIZE];
};

/**
 * DpdkDriver specific Packet object used to track a its lifetime and contents.
 */
class DpdkDriver::DpdkPacket : public Driver::Packet {
  public:
    explicit DpdkPacket(struct rte_mbuf* mbuf, void* header, void* data);
    explicit DpdkPacket(OverflowBuffer* overflowBuf);

    /// see Driver::Packet::getMaxPayloadSize()
    virtual uint16_t getMaxPayloadSize()
    {
        return MAX_PAYLOAD_SIZE;
    }

    /// Indicates whether the packet is backed by an DPDK mbuf or a driver-level
    /// OverflowBuffer.
    enum BufferType { MBUF, OVERFLOW_BUF } bufType;

    /// A reference to the buffer that backs this packet.
    union {
        struct rte_mbuf* mbuf;
        OverflowBuffer* overflowBuf;
    } bufRef;

    /// The memory location of this packet's header. The header should be
    /// PACKET_HDR_LEN in length.
    void* header;

  private:
    DpdkPacket(const DpdkPacket&) = delete;
    DpdkPacket& operator=(const DpdkPacket&) = delete;
};

/**
 * Construct a DpdkPacket backed by a DPDK mbuf.
 *
 * @param mbuf
 *      Pointer to the DPDK mbuf that holds this packet.
 * @param header
 *      Memory location in the mbuf where the packet header should be stored.
 * @param data
 *      Memory location in the mbuf where the packet data should be stored.
 */
DpdkDriver::DpdkPacket::DpdkPacket(struct rte_mbuf* mbuf, void* header,
                                   void* data)
    : Packet(data, 0)
    , bufType(MBUF)
    , bufRef()
    , header(header)
{
    bufRef.mbuf = mbuf;
}

/**
 * Construct a DpdkPacket backed by an OverflowBuffer.
 *
 * @parm overflowBuf
 *      Overflow buffer that holds this packet.
 */
DpdkDriver::DpdkPacket::DpdkPacket(OverflowBuffer* overflowBuf)
    : Packet(overflowBuf->data, 0)
    , bufType(OVERFLOW_BUF)
    , bufRef()
    , header(overflowBuf->header)
{
    bufRef.overflowBuf = overflowBuf;
}

DpdkDriver::DpdkDriver(int port)
    : DpdkDriver(port, default_eal_argc, const_cast<char**>(default_eal_argv))
{}

DpdkDriver::DpdkDriver(int port, int argc, char* argv[])
    : addressLock()
    , addressCache()
    , packetLock()
    , packetPool()
    , overflowBufferPool()
    , localMac()
    , portId(0)
    , mbufPool(nullptr)
    , loopbackRing(nullptr)
    , rxLock()
    , txLock()
    , hasTxLockFreeSupport(false)  // Set later if applicable
    , hasHardwareFilter(true)      // Cleared later if not applicable
    , bandwidthMbps(10000)         // Default bandwidth = 10 gbs
{
    // DPDK during initialization (rte_eal_init()) the running thread is pinned
    // to a single processor which may be not be what the applications wants.
    // Rememeber the current thread affinity so that we can restore it after
    // initialization is complete.
    int s;
    cpu_set_t cpuset;
    pthread_t thread;
    thread = pthread_self();
    CPU_ZERO(&cpuset);
    s = pthread_getaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
    if (s != 0) {
        throw DriverInitFailure(HERE, "Unable to get existing thread affinity");
    }

    _eal_init(argc, argv);
    _init(port);

    // restore the original thread affinity
    s = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
    if (s != 0) {
        throw DriverInitFailure(HERE,
                                "Unable to restore original thread affinity");
    }
}

DpdkDriver::DpdkDriver(int port, NoEalInit _)
    : addressLock()
    , addressCache()
    , packetLock()
    , packetPool()
    , overflowBufferPool()
    , localMac()
    , portId(0)
    , mbufPool(nullptr)
    , loopbackRing(nullptr)
    , rxLock()
    , txLock()
    , hasTxLockFreeSupport(false)  // Set later if applicable
    , hasHardwareFilter(true)      // Cleared later if not applicable
    , bandwidthMbps(10000)         // Default bandwidth = 10 gbs
{
    _init(port);
}

DpdkDriver::~DpdkDriver()
{
    // Free the various allocated resources (e.g. ring, mempool) and close
    // the NIC.
    rte_ring_free(loopbackRing);
    rte_eth_dev_stop(portId);
    rte_eth_dev_close(portId);
    rte_mempool_free(mbufPool);
}

Driver::Address*
DpdkDriver::getAddress(std::string const* const addressString)
{
    std::lock_guard<SpinLock> lock(addressLock);

    Driver::Address* addr;

    auto it = addressCache.find(*addressString);
    if (it == addressCache.end()) {
        MacAddress* macAddr = new MacAddress(addressString->c_str());
        addressCache[*addressString] = macAddr;
        addr = macAddr;
    } else {
        addr = it->second;
    }

    return addr;
}

// See Driver::allocPacket()
Driver::Packet*
DpdkDriver::allocPacket()
{
    DpdkPacket* packet = _allocMbufPacket();
    if (unlikely(packet == nullptr)) {
        std::lock_guard<SpinLock> lock(packetLock);
        OverflowBuffer* buf = overflowBufferPool.construct();
        packet = packetPool.construct(buf);
        LOG(NOTICE, "OverflowBuffer used.");
    }
    return packet;
}

// See Driver::sendPackets()
void
DpdkDriver::sendPackets(Packet* packets[], uint16_t numPackets)
{
    constexpr uint16_t MAX_BURST = 32;
    uint16_t nb_pkts;
    struct rte_mbuf* tx_pkts[MAX_BURST];

    // Process each packet
    for (uint16_t i = 0; i < numPackets; ++i) {
        DpdkPacket* packet = static_cast<DpdkPacket*>(packets[i]);

        struct rte_mbuf* mbuf = nullptr;
        char* header = nullptr;
        // If the packet is held in an Overflow buffer, we need to copy it out
        // into a new mbuf.
        if (unlikely(packet->bufType == DpdkPacket::OVERFLOW_BUF)) {
            mbuf = rte_pktmbuf_alloc(mbufPool);
            if (unlikely(NULL == mbuf)) {
                uint32_t numMbufsAvail = rte_mempool_avail_count(mbufPool);
                uint32_t numMbufsInUse = rte_mempool_in_use_count(mbufPool);
                LOG(WARNING,
                    "Failed to allocate a packet buffer; dropping packet; "
                    "%u mbufs available, %u mbufs in use",
                    numMbufsAvail, numMbufsInUse);
                continue;
            }
            header = rte_pktmbuf_append(
                mbuf, Util::downCast<uint16_t>(PACKET_HDR_LEN + packet->len));
            if (unlikely(NULL == header)) {
                LOG(WARNING, "rte_pktmbuf_append call failed; dropping packet");
                rte_pktmbuf_free(mbuf);
                continue;
            }
            char* data = header + PACKET_HDR_LEN;
            rte_memcpy(data, packet->payload, packet->len);
        } else {
            mbuf = packet->bufRef.mbuf;
            header = static_cast<char*>(packet->header);
        }

        // Fill out the destination and source MAC addresses plus the Ethernet
        // frame type (i.e., IEEE 802.1Q VLAN tagging).
        struct ether_hdr* ethHdr = reinterpret_cast<struct ether_hdr*>(header);
        rte_memcpy(&ethHdr->d_addr,
                   static_cast<const MacAddress*>(packet->address)->address,
                   ETHER_ADDR_LEN);
        rte_memcpy(&ethHdr->s_addr, localMac->address, ETHER_ADDR_LEN);
        ethHdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_VLAN);

        // Fill out the PCP field and the Ethernet frame type of the
        // encapsulated frame (DEI and VLAN ID are not relevant and trivially
        // set to 0).
        struct vlan_hdr* vlanHdr =
            reinterpret_cast<struct vlan_hdr*>(ethHdr + 1);
        vlanHdr->vlan_tci = rte_cpu_to_be_16(PRIORITY_TO_PCP[packet->priority]);
        vlanHdr->eth_proto = rte_cpu_to_be_16(EthPayloadType::HOMA);

        // In the normal case, we pre-allocate a pakcet's mbuf with enough
        // storage to hold the MAX_PAYLOAD_SIZE.  If the actual payload is
        // smaller, trim the mbuf to size to avoid sending unecessary bits.
        uint32_t actualLength = PACKET_HDR_LEN + packet->len;
        uint32_t mbufDataLength = rte_pktmbuf_pkt_len(mbuf);
        if (actualLength < mbufDataLength) {
            if (rte_pktmbuf_trim(mbuf, mbufDataLength - actualLength) < 0) {
                LOG(WARNING,
                    "Couldn't trim packet from length %u to %u; sending "
                    "anyway.",
                    mbufDataLength, actualLength);
            }
        }

        // loopback if src mac == dst mac
        if (!memcmp(static_cast<const MacAddress*>(packet->address)->address,
                    localMac->address, 6)) {
            struct rte_mbuf* mbuf_clone = rte_pktmbuf_clone(mbuf, mbufPool);
            if (unlikely(mbuf_clone == NULL)) {
                LOG(WARNING,
                    "Failed to clone packet for loopback; dropping packet");
            }
            int ret = rte_ring_enqueue(loopbackRing, mbuf_clone);
            if (unlikely(ret != 0)) {
                LOG(WARNING,
                    "rte_ring_enqueue returned %d; packet may be lost?", ret);
                rte_pktmbuf_free(mbuf_clone);
            }
            continue;
        }

        // If the packet is held in an mbuf, retain access to it so that the
        // processing of sending the mbuf won't free it.
        if (likely(packet->bufType == DpdkPacket::MBUF)) {
            rte_pktmbuf_refcnt_update(mbuf, 1);
        }

        // Add the packet to the burst.
        // If the tx_pkts is already full, send out a burst now before
        // processing more packets.
        if (nb_pkts >= MAX_BURST) {
            _sendPackets(tx_pkts, nb_pkts);
            nb_pkts = 0;
        }
        tx_pkts[nb_pkts++] = mbuf;
    }

    // Send out the packets once we finished processing them.
    _sendPackets(tx_pkts, nb_pkts);
}

// See Driver::receivePackets()
uint32_t
DpdkDriver::receivePackets(uint32_t maxPackets, Packet* receivedPackets[])
{
    uint32_t numPacketsReceived = 0;

    constexpr uint32_t MAX_PACKETS_AT_ONCE = 32;
    if (maxPackets > MAX_PACKETS_AT_ONCE) {
        maxPackets = MAX_PACKETS_AT_ONCE;
    }
    struct rte_mbuf* mPkts[MAX_PACKETS_AT_ONCE];

    // attempt to dequeue a batch of received packets from the NIC
    // as well as from the loopback ring.
    uint32_t incomingPkts = 0;
    {
        std::lock_guard<SpinLock> lock(rxLock);
        incomingPkts = rte_eth_rx_burst(portId, 0, mPkts,
                                        Util::downCast<uint16_t>(maxPackets));
    }
    LOG(DEBUG, "rte_eth_rx_burst returned %u packets", incomingPkts);

    uint32_t loopbackPkts = rte_ring_count(loopbackRing);
    if (incomingPkts + loopbackPkts > maxPackets) {
        loopbackPkts = maxPackets - incomingPkts;
    }
    for (uint32_t i = 0; i < loopbackPkts; i++) {
        rte_ring_dequeue(loopbackRing,
                         reinterpret_cast<void**>(&mPkts[incomingPkts + i]));
    }
    LOG(DEBUG, "loopback returned %u packets", loopbackPkts);
    uint32_t totalPkts = incomingPkts + loopbackPkts;

    // Process received packets by constructing appropriate Received objects.
    for (uint32_t i = 0; i < totalPkts; i++) {
        struct rte_mbuf* m = mPkts[i];
        rte_prefetch0(rte_pktmbuf_mtod(m, void*));
        if (unlikely(m->nb_segs > 1)) {
            LOG(WARNING, "Can't handle packet with %u segments; discarding",
                m->nb_segs);
            rte_pktmbuf_free(m);
            continue;
        }

        struct ether_hdr* ethHdr = rte_pktmbuf_mtod(m, struct ether_hdr*);
        uint16_t ether_type = ethHdr->ether_type;
        uint32_t headerLength = ETHER_HDR_LEN;
        char* payload = reinterpret_cast<char*>(ethHdr + 1);
        if (ether_type == rte_cpu_to_be_16(ETHER_TYPE_VLAN)) {
            struct vlan_hdr* vlanHdr =
                reinterpret_cast<struct vlan_hdr*>(payload);
            ether_type = vlanHdr->eth_proto;
            headerLength += VLAN_TAG_LEN;
            payload += VLAN_TAG_LEN;
        }
        if (!hasHardwareFilter) {
            // Perform packet filtering by software to skip irrelevant
            // packets such as ipmi or kernel TCP/IP traffics.
            if (ether_type != rte_cpu_to_be_16(EthPayloadType::HOMA)) {
                LOG(DEBUG, "packet filtered; ether_type = %x", ether_type);
                rte_pktmbuf_free(m);
                continue;
            }
        }

        // Store the incomming packet's source Address object in the headroom
        // of the incoming mbuf. This Address will be pointed to in the returned
        // Packet object.
        // See http://dpdk.org/doc/guides/prog_guide/mbuf_lib.html for the
        // diagram of rte_mbuf's internal structure.
        MacAddress* sender = reinterpret_cast<MacAddress*>(m->buf_addr);
        if (unlikely(reinterpret_cast<char*>(sender + 1) >
                     rte_pktmbuf_mtod(m, char*))) {
            LOG(ERROR,
                "Not enough headroom in the packet mbuf; "
                "dropping packet");
            rte_pktmbuf_free(m);
            continue;
        }
        new (sender) MacAddress(ethHdr->s_addr.addr_bytes);
        uint32_t length = rte_pktmbuf_pkt_len(m) - headerLength;
        assert(length <= MAX_PAYLOAD_SIZE);

        DpdkPacket* packet = nullptr;
        {
            std::lock_guard<SpinLock> lock(packetLock);
            packet = packetPool.construct(m, ethHdr, payload);
        }
        packet->address = sender;
        packet->len = length;

        receivedPackets[numPacketsReceived++] = packet;
    }

    return numPacketsReceived;
}

// See Driver::releasePackets()
void
DpdkDriver::releasePackets(Packet* packets[], uint16_t numPackets)
{
    for (uint16_t i = 0; i < numPackets; ++i) {
        std::lock_guard<SpinLock> lock(packetLock);
        DpdkPacket* packet = static_cast<DpdkPacket*>(packets[i]);
        if (likely(packet->bufType == DpdkPacket::MBUF)) {
            rte_pktmbuf_free(packet->bufRef.mbuf);
        } else {
            overflowBufferPool.destroy(packet->bufRef.overflowBuf);
        }
        packetPool.destroy(packet);
    }
}

// See Driver::getHighestPacketPriority()
int
DpdkDriver::getHighestPacketPriority()
{
    return Util::arrayLength(PRIORITY_TO_PCP) - 1;
}

// See Driver::getMaxPayloadSize()
uint32_t
DpdkDriver::getMaxPayloadSize()
{
    return MAX_PAYLOAD_SIZE;
}

// See Driver::getBandwidth()
uint32_t
DpdkDriver::getBandwidth()
{
    return bandwidthMbps;
}

// See Driver::getLocalAddress()
Driver::Address*
DpdkDriver::getLocalAddress()
{
    return localMac.get();
}

/**
 * Initilized DPDK EAL.
 *
 * @param argc
 *      Parameter passed to rte_eal_init().
 * @param argv
 *      Parameter passed to rte_eal_init().
 * @throw DriverInitFailure
 *      Thrown if EAL initilization fails.
 */
void
DpdkDriver::_eal_init(int argc, char* argv[])
{
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        throw DriverInitFailure(HERE,
                                "rte_eal_init failed; Invalid EAL arguments");
    }
}

/**
 * Does most of the real work on initilizing the DpdkDriver during
 * construction.
 *
 * Seperated out to be used by different constructor methods.
 *
 * @param port
 *      Selects which physical port to use for communication.
 */
void
DpdkDriver::_init(int port)
{
    struct ether_addr mac;
    uint8_t numPorts;
    struct rte_eth_conf portConf;
    struct rte_eth_dev_info devInfo;
    int ret;
    uint16_t mtu;

    portId = Util::downCast<uint8_t>(port);
    std::string poolName = Util::format("homa_mbuf_pool_%u", portId);
    std::string ringName = Util::format("homa_loopback_ring_%u", portId);

    LOG(NOTICE, "Using DPDK version %s", rte_version());

    // create an memory pool for accommodating packet buffers
    mbufPool =
        rte_pktmbuf_pool_create(poolName.c_str(), NB_MBUF, MEMPOOL_CACHE_SIZE,
                                0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!mbufPool) {
        throw DriverInitFailure(
            HERE,
            Util::format("Failed to allocate memory for packet buffers: %s",
                         rte_strerror(rte_errno)));
    }

    // ensure that DPDK was able to detect a compatible and available NIC
    numPorts = rte_eth_dev_count();

    if (numPorts <= portId) {
        throw DriverInitFailure(
            HERE,
            Util::format("Ethernet port %u doesn't exist (%u ports available)",
                         portId, numPorts));
    }

    // Read the MAC address from the NIC via DPDK.
    rte_eth_macaddr_get(portId, &mac);
    localMac.construct(mac.addr_bytes);

    // configure some default NIC port parameters
    memset(&portConf, 0, sizeof(portConf));
    portConf.rxmode.max_rx_pkt_len = ETHER_MAX_VLAN_FRAME_LEN;
    rte_eth_dev_configure(portId, 1, 1, &portConf);

    // Set up a NIC/HW-based filter on the ethernet type so that only
    // traffic to a particular port is received by this driver.
    struct rte_eth_ethertype_filter filter;
    ret = rte_eth_dev_filter_supported(portId, RTE_ETH_FILTER_ETHERTYPE);
    if (ret < 0) {
        LOG(NOTICE, "ethertype filter is not supported on port %u.", portId);
        hasHardwareFilter = false;
    } else {
        memset(&filter, 0, sizeof(filter));
        ret = rte_eth_dev_filter_ctrl(portId, RTE_ETH_FILTER_ETHERTYPE,
                                      RTE_ETH_FILTER_ADD, &filter);
        if (ret < 0) {
            LOG(WARNING, "failed to add ethertype filter\n");
            hasHardwareFilter = false;
        }
    }

    // Check if packets can be sent without locks.
    rte_eth_dev_info_get(portId, &devInfo);
    if (devInfo.tx_offload_capa & DEV_TX_OFFLOAD_MT_LOCKFREE) {
        hasTxLockFreeSupport = true;
    }

    // setup and initialize the receive and transmit NIC queues,
    // and activate the port.
    rte_eth_rx_queue_setup(portId, 0, NDESC, rte_eth_dev_socket_id(portId),
                           NULL, mbufPool);
    rte_eth_tx_queue_setup(portId, 0, NDESC, rte_eth_dev_socket_id(portId),
                           NULL);

    // get the current MTU.
    ret = rte_eth_dev_get_mtu(portId, &mtu);
    if (ret < 0) {
        throw DriverInitFailure(
            HERE, Util::format("rte_eth_dev_get_mtu on port %u returned "
                               "ENODEV; unable to read current mtu",
                               portId));
    }
    // set the MTU that the NIC port should support
    if (mtu != MAX_PAYLOAD_SIZE) {
        ret = rte_eth_dev_set_mtu(portId, MAX_PAYLOAD_SIZE);
        if (ret != 0) {
            throw DriverInitFailure(
                HERE, Util::format("Failed to set the MTU on Ethernet port %u: "
                                   "%s; current MTU is %u",
                                   portId, strerror(ret), mtu));
        }
        mtu = MAX_PAYLOAD_SIZE;
    }

    ret = rte_eth_dev_start(portId);
    if (ret != 0) {
        throw DriverInitFailure(
            HERE, Util::format("Couldn't start port %u, error %d (%s)", portId,
                               ret, strerror(ret)));
    }

    // Retrieve the link speed and compute information based on it.
    struct rte_eth_link link;
    rte_eth_link_get(portId, &link);
    if (!link.link_status) {
        throw DriverInitFailure(
            HERE, Util::format("Failed to detect a link on Ethernet port %u",
                               portId));
    }
    if (link.link_speed != ETH_SPEED_NUM_NONE) {
        // Be conservative about the link speed. We use bandwidth in
        // QueueEstimator to estimate # bytes outstanding in the NIC's
        // TX queue. If we overestimate the bandwidth, under high load,
        // we may keep queueing packets faster than the NIC can consume,
        // and build up a queue in the TX queue.
        bandwidthMbps = (uint32_t)(link.link_speed * 0.98);
    } else {
        LOG(WARNING,
            "Can't retrieve network bandwidth from DPDK; "
            "using default of %d Mbps",
            bandwidthMbps);
    }

    // create an in-memory ring, used as a software loopback in order to
    // handle packets that are addressed to the localhost.
    loopbackRing = rte_ring_create(ringName.c_str(), 4096, SOCKET_ID_ANY, 0);
    if (NULL == loopbackRing) {
        throw DriverInitFailure(
            HERE, Util::format("Failed to allocate loopback ring: %s",
                               rte_strerror(rte_errno)));
    }

    LOG(NOTICE,
        "DpdkDriver address: %s, bandwidth: %d Mbits/sec, MTU: %u, lock-free "
        "tx support: %s",
        localMac->toString().c_str(), bandwidthMbps, mtu,
        hasTxLockFreeSupport ? "YES" : "NO");
}

/**
 * Helper function to try to allocation a new DpdkPacket backed by an mbuf.
 *
 * @return
 *      The newly allocated DpdkPacket; nullptr if the mbuf allocation
 * failed.
 */
DpdkDriver::DpdkPacket*
DpdkDriver::_allocMbufPacket()
{
    DpdkPacket* packet = nullptr;
    uint32_t numMbufsAvail = rte_mempool_avail_count(mbufPool);
    if (unlikely(numMbufsAvail <= NB_MBUF_RESERVED)) {
        uint32_t numMbufsInUse = rte_mempool_in_use_count(mbufPool);
        LOG(NOTICE,
            "Driver is running low on mbuf packet buffers; "
            "%u mbufs available, %u mbufs in use",
            numMbufsAvail, numMbufsInUse);
        return nullptr;
    }

    struct rte_mbuf* mbuf = rte_pktmbuf_alloc(mbufPool);

    if (unlikely(NULL == mbuf)) {
        uint32_t numMbufsAvail = rte_mempool_avail_count(mbufPool);
        uint32_t numMbufsInUse = rte_mempool_in_use_count(mbufPool);
        LOG(NOTICE,
            "Failed to allocate an mbuf packet buffer; "
            "%u mbufs available, %u mbufs in use",
            numMbufsAvail, numMbufsInUse);
        return nullptr;
    }

    char* buf = rte_pktmbuf_append(
        mbuf, Util::downCast<uint16_t>(PACKET_HDR_LEN + MAX_PAYLOAD_SIZE));

    if (unlikely(NULL == buf)) {
        LOG(NOTICE, "rte_pktmbuf_append call failed; dropping packet");
        rte_pktmbuf_free(mbuf);
        return nullptr;
    }

    // Perform packet operations with the lock held.
    {
        std::lock_guard<SpinLock> _(packetLock);
        packet = packetPool.construct(mbuf, buf, buf + PACKET_HDR_LEN);
    }
    return packet;
}

/**
 * Queue a set of mbuf packets to be sent by the NIC.
 *
 * @param tx_pkts
 *      Array of mbuf packets to be sent.
 * @param nb_pkts
 *      Number of packets to send.
 */
void
DpdkDriver::_sendPackets(struct rte_mbuf* tx_pkts[], uint16_t nb_pkts)
{
    uint16_t pkts_sent = 0;
    uint32_t attempts = 0;
    uint16_t ret = 0;
    while (pkts_sent < nb_pkts) {
        if (unlikely(attempts++ > 0)) {
            LOG(NOTICE,
                "rte_eth_tx_burst sent %u packets on attempt %u; %u of %u "
                "packets sent; trying again on remaining packets",
                ret, attempts, pkts_sent, nb_pkts);
        }
        // calls to rte_eth_tx_burst() may require a software lock.
        std::unique_lock<SpinLock> lock(txLock, std::defer_lock);
        if (!hasTxLockFreeSupport) {
            lock.lock();
        }

        ret = rte_eth_tx_burst(portId, 0, &(tx_pkts[pkts_sent]),
                               nb_pkts - pkts_sent);
        pkts_sent += ret;
    }
}

}  // namespace Homa
