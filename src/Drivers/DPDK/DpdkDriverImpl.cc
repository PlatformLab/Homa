/* Copyright (c) 2015-2020, Stanford University
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

#include "DpdkDriverImpl.h"

#include <net/if.h>
#include <netinet/in.h>
#include <rte_malloc.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <fstream>

#include "CodeLocation.h"
#include "Homa/Util.h"
#include "StringUtil.h"

namespace Homa {

namespace Drivers {
namespace DPDK {

/// Default number of arguments for EAL init.
const int default_eal_argc = 1;

/// Default arguments for EAL init.
const char* default_eal_argv[] = {"homa", NULL};

/**
 * Construct a DPDK Packet backed by a DPDK mbuf.
 *
 * @param mbuf
 *      Pointer to the DPDK mbuf that holds this packet.
 * @param data
 *      Memory location in the mbuf where the packet data should be stored.
 */
DpdkDriver::Impl::Packet::Packet(struct rte_mbuf* mbuf, void* data)
    : base{.payload = data, .length = 0}
    , bufType(MBUF)
    , bufRef()
{
    bufRef.mbuf = mbuf;
}

/**
 * Construct a DPDK Packet backed by an OverflowBuffer.
 *
 * @param overflowBuf
 *      Overflow buffer that holds this packet.
 */
DpdkDriver::Impl::Packet::Packet(OverflowBuffer* overflowBuf)
    : base{.payload = overflowBuf->data, .length = 0}
    , bufType(OVERFLOW_BUF)
    , bufRef()
{
    bufRef.overflowBuf = overflowBuf;
}

/**
 * See DpdkDriver::DpdkDriver()
 */
DpdkDriver::Impl::Impl(const char* ifname, const Config* const config)
    : Impl(ifname, default_eal_argc, const_cast<char**>(default_eal_argv),
           config)
{}

/**
 * See DpdkDriver::DpdkDriver()
 */
DpdkDriver::Impl::Impl(const char* ifname, int argc, char* argv[],
                       const Config* const config)
    : ifname(ifname)
    , port()
    , arpTable()
    , localIp()
    , localMac("00:00:00:00:00:00")
    , HIGHEST_PACKET_PRIORITY(
          (config == nullptr || config->HIGHEST_PACKET_PRIORITY_OVERRIDE < 0)
              ? Homa::Util::arrayLength(PRIORITY_TO_PCP) - 1
              : config->HIGHEST_PACKET_PRIORITY_OVERRIDE)
    , packetLock()
    , packetPool()
    , overflowBufferPool()
    , mbufsOutstanding(0)
    , mbufPool(nullptr)
    , loopbackRing(nullptr)
    , rx()
    , tx()
    , hasHardwareFilter(true)  // Cleared later if not applicable
    , corked(0)
    , bandwidthMbps(10000)  // Default bandwidth = 10 gbs
{
    // DPDK during initialization (rte_eal_init()) the running thread is pinned
    // to a single processor which may be not be what the applications wants.
    // Remember the current thread affinity so that we can restore it after
    // initialization is complete.
    int s;
    cpu_set_t cpuset;
    pthread_t thread;
    thread = pthread_self();
    CPU_ZERO(&cpuset);
    s = pthread_getaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
    if (s != 0) {
        throw DriverInitFailure(HERE_STR,
                                "Unable to get existing thread affinity");
    }

    _eal_init(argc, argv);
    _init();

    // restore the original thread affinity
    s = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
    if (s != 0) {
        throw DriverInitFailure(HERE_STR,
                                "Unable to restore original thread affinity");
    }
}

/**
 * See DpdkDriver::DpdkDriver()
 */
DpdkDriver::Impl::Impl(const char* ifname,
                       __attribute__((__unused__)) NoEalInit _,
                       const Config* const config)
    : ifname(ifname)
    , port()
    , arpTable()
    , localIp()
    , localMac("00:00:00:00:00:00")
    , HIGHEST_PACKET_PRIORITY(
          (config == nullptr || config->HIGHEST_PACKET_PRIORITY_OVERRIDE < 0)
              ? Homa::Util::arrayLength(PRIORITY_TO_PCP) - 1
              : config->HIGHEST_PACKET_PRIORITY_OVERRIDE)
    , packetLock()
    , packetPool()
    , overflowBufferPool()
    , mbufPool(nullptr)
    , loopbackRing(nullptr)
    , rx()
    , tx()
    , hasHardwareFilter(true)  // Cleared later if not applicable
    , corked(0)
    , bandwidthMbps(10000)  // Default bandwidth = 10 gbs
{
    _init();
}

/**
 * DpdkDriver::Impl destructor.
 */
DpdkDriver::Impl::~Impl()
{
    // Free the various allocated resources (e.g. ring, mempool) and close
    // the NIC.
    rte_ring_free(loopbackRing);
    rte_eth_dev_stop(port);
    rte_eth_dev_close(port);
    rte_mempool_free(mbufPool);
}

// See Driver::allocPacket()
Driver::Packet*
DpdkDriver::Impl::allocPacket()
{
    DpdkDriver::Impl::Packet* packet = nullptr;
    SpinLock::Lock lock(packetLock);
    static const int MBUF_ALLOC_LIMIT = NB_MBUF - NB_MBUF_RESERVED;
    if (mbufsOutstanding < MBUF_ALLOC_LIMIT) {
        struct rte_mbuf* mbuf = rte_pktmbuf_alloc(mbufPool);
        if (unlikely(NULL == mbuf)) {
            uint32_t numMbufsAvail = rte_mempool_avail_count(mbufPool);
            uint32_t numMbufsInUse = rte_mempool_in_use_count(mbufPool);
            NOTICE(
                "Failed to allocate an mbuf packet buffer; "
                "%u mbufs available, %u mbufs in use, %u mbufs held by app",
                numMbufsAvail, numMbufsInUse, mbufsOutstanding);
        } else {
            char* buf = rte_pktmbuf_append(
                mbuf, Homa::Util::downCast<uint16_t>(PACKET_HDR_LEN +
                                                     MAX_PAYLOAD_SIZE));
            if (unlikely(NULL == buf)) {
                NOTICE("rte_pktmbuf_append call failed; dropping packet");
                rte_pktmbuf_free(mbuf);
            } else {
                packet = packetPool.construct(mbuf, buf + PACKET_HDR_LEN);
                mbufsOutstanding++;
            }
        }
    }
    if (packet == nullptr) {
        OverflowBuffer* buf = overflowBufferPool.construct();
        packet = packetPool.construct(buf);
        NOTICE("OverflowBuffer used.");
    }
    return &packet->base;
}

// See Driver::sendPacket()
void
DpdkDriver::Impl::sendPacket(Driver::Packet* packet, IpAddress destination,
                             int priority)
{
    ;
    DpdkDriver::Impl::Packet* pkt =
        container_of(packet, DpdkDriver::Impl::Packet, base);
    struct rte_mbuf* mbuf = nullptr;
    // If the packet is held in an Overflow buffer, we need to copy it out
    // into a new mbuf.
    if (unlikely(pkt->bufType == DpdkDriver::Impl::Packet::OVERFLOW_BUF)) {
        mbuf = rte_pktmbuf_alloc(mbufPool);
        if (unlikely(NULL == mbuf)) {
            uint32_t numMbufsAvail = rte_mempool_avail_count(mbufPool);
            uint32_t numMbufsInUse = rte_mempool_in_use_count(mbufPool);
            WARNING(
                "Failed to allocate a packet buffer; dropping packet; "
                "Failed to allocate a packet buffer; dropping packet; "
                "%u mbufs available, %u mbufs in use",
                numMbufsAvail, numMbufsInUse);
            return;
        }
        char* buf = rte_pktmbuf_append(
            mbuf,
            Homa::Util::downCast<uint16_t>(PACKET_HDR_LEN + pkt->base.length));
        if (unlikely(NULL == buf)) {
            WARNING("rte_pktmbuf_append call failed; dropping packet");
            rte_pktmbuf_free(mbuf);
            return;
        }
        char* data = buf + PACKET_HDR_LEN;
        rte_memcpy(data, pkt->base.payload, pkt->base.length);
    } else {
        mbuf = pkt->bufRef.mbuf;

        // If the mbuf is still transmitting from a previous call to send,
        // we don't want to modify the buffer when the send is occuring.
        // Thus if the mbuf is in use and drop this send request.
        if (unlikely(rte_mbuf_refcnt_read(mbuf) > 1)) {
            NOTICE("Packet still sending; dropping resend request");
            return;
        }
    }

    // Fill out the destination and source MAC addresses plus the Ethernet
    // frame type (i.e., IEEE 802.1Q VLAN tagging).
    auto it = arpTable.find(destination);
    if (it == arpTable.end()) {
        WARNING("Failed to find ARP record for packet; dropping packet");
        return;
    }
    MacAddress& destMac = it->second;
    struct ether_hdr* ethHdr = rte_pktmbuf_mtod(mbuf, struct ether_hdr*);
    rte_memcpy(&ethHdr->d_addr, destMac.address, ETHER_ADDR_LEN);
    rte_memcpy(&ethHdr->s_addr, localMac.address, ETHER_ADDR_LEN);
    ethHdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_VLAN);

    // Fill out the PCP field and the Ethernet frame type of the
    // encapsulated frame (DEI and VLAN ID are not relevant and trivially
    // set to 0).
    struct vlan_hdr* vlanHdr = reinterpret_cast<struct vlan_hdr*>(ethHdr + 1);
    vlanHdr->vlan_tci = rte_cpu_to_be_16(PRIORITY_TO_PCP[priority]);
    vlanHdr->eth_proto = rte_cpu_to_be_16(EthPayloadType::HOMA);

    // Store our local IP address right before the payload.
    *rte_pktmbuf_mtod_offset(mbuf, uint32_t*, PACKET_HDR_LEN - 4) =
        (uint32_t)localIp;

    // In the normal case, we pre-allocate a pakcet's mbuf with enough
    // storage to hold the MAX_PAYLOAD_SIZE.  If the actual payload is
    // smaller, trim the mbuf to size to avoid sending unecessary bits.
    uint32_t actualLength = PACKET_HDR_LEN + pkt->base.length;
    uint32_t mbufDataLength = rte_pktmbuf_pkt_len(mbuf);
    if (actualLength < mbufDataLength) {
        if (rte_pktmbuf_trim(mbuf, mbufDataLength - actualLength) < 0) {
            WARNING(
                "Couldn't trim packet from length %u to %u; sending "
                "anyway.",
                mbufDataLength, actualLength);
        }
    }

    // loopback if src mac == dst mac
    if (localMac == destMac) {
        struct rte_mbuf* mbuf_clone = rte_pktmbuf_clone(mbuf, mbufPool);
        if (unlikely(mbuf_clone == NULL)) {
            WARNING("Failed to clone packet for loopback; dropping packet");
            return;
        }
        int ret = rte_ring_enqueue(loopbackRing, mbuf_clone);
        if (unlikely(ret != 0)) {
            WARNING(
                "rte_ring_enqueue returned %d with %u packets queued; "
                "packet may be lost?",
                ret, rte_ring_count(loopbackRing));
            rte_pktmbuf_free(mbuf_clone);
        }
        return;
    }

    // If the packet is held in an mbuf, retain access to it so that the
    // processing of sending the mbuf won't free it.
    if (likely(pkt->bufType == DpdkDriver::Impl::Packet::MBUF)) {
        rte_pktmbuf_refcnt_update(mbuf, 1);
    }

    // Add the packet to the burst.
    SpinLock::Lock txLock(tx.mutex);
    {
        SpinLock::Lock statsLock(tx.stats.mutex);
        tx.stats.bufferedBytes += rte_pktmbuf_pkt_len(mbuf);
    }
    rte_eth_tx_buffer(port, 0, tx.buffer, mbuf);

    // Flush packets now if the driver is not corked.
    if (corked.load() < 1) {
        rte_eth_tx_buffer_flush(port, 0, tx.buffer);
    }
}

// See Driver::cork()
void
DpdkDriver::Impl::cork()
{
    corked.fetch_add(1);
}

// See Driver::uncork()
void
DpdkDriver::Impl::uncork()
{
    if (corked.fetch_sub(1) == 1) {
        SpinLock::Lock txLock(tx.mutex);
        rte_eth_tx_buffer_flush(port, 0, tx.buffer);
    }
}

// See Driver::receivePackets()
uint32_t
DpdkDriver::Impl::receivePackets(uint32_t maxPackets,
                                 Driver::Packet* receivedPackets[],
                                 IpAddress sourceAddresses[])
{
    uint32_t numPacketsReceived = 0;

    constexpr uint32_t MAX_PACKETS_AT_ONCE = 32;
    if (maxPackets > MAX_PACKETS_AT_ONCE) {
        maxPackets = MAX_PACKETS_AT_ONCE;
    }
    uint32_t maxLoopbackPkts = maxPackets / 2;

    struct rte_mbuf* mPkts[MAX_PACKETS_AT_ONCE];

    // attempt to dequeue a batch of received packets from the NIC
    // as well as from the loopback ring.
    uint32_t loopbackPkts = 0;
    uint32_t incomingPkts = 0;
    {
        SpinLock::Lock lock(rx.mutex);

        loopbackPkts = rte_ring_count(loopbackRing);
        loopbackPkts = std::min(loopbackPkts, maxLoopbackPkts);
        for (uint32_t i = 0; i < loopbackPkts; i++) {
            rte_ring_dequeue(loopbackRing, reinterpret_cast<void**>(&mPkts[i]));
        }

        incomingPkts = rte_eth_rx_burst(
            port, 0, &(mPkts[loopbackPkts]),
            Homa::Util::downCast<uint16_t>(maxPackets - loopbackPkts));
    }
    uint32_t totalPkts = incomingPkts + loopbackPkts;

    // Process received packets by constructing appropriate Received objects.
    for (uint32_t i = 0; i < totalPkts; i++) {
        struct rte_mbuf* m = mPkts[i];
        rte_prefetch0(rte_pktmbuf_mtod(m, void*));
        if (unlikely(m->nb_segs > 1)) {
            WARNING("Can't handle packet with %u segments; discarding",
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
            // packets such as ipmi or kernel TCP/IP traffic.
            if (ether_type != rte_cpu_to_be_16(EthPayloadType::HOMA)) {
                VERBOSE("packet filtered; ether_type = %x", ether_type);
                rte_pktmbuf_free(m);
                continue;
            }
        }

        uint32_t srcIp = *rte_pktmbuf_mtod_offset(m, uint32_t*, headerLength);
        headerLength += sizeof(srcIp);
        payload += sizeof(srcIp);
        assert(rte_pktmbuf_pkt_len(m) >= headerLength);
        uint32_t length = rte_pktmbuf_pkt_len(m) - headerLength;
        assert(length <= MAX_PAYLOAD_SIZE);

        DpdkDriver::Impl::Packet* packet = nullptr;
        {
            SpinLock::Lock lock(packetLock);
            static const int MBUF_ALLOC_LIMIT = NB_MBUF - NB_MBUF_RESERVED;
            if (mbufsOutstanding < MBUF_ALLOC_LIMIT) {
                packet = packetPool.construct(m, payload);
                mbufsOutstanding++;
            } else {
                OverflowBuffer* buf = overflowBufferPool.construct();
                rte_memcpy(payload, buf->data, length);
                packet = packetPool.construct(buf);
            }
        }
        packet->base.length = length;

        receivedPackets[numPacketsReceived] = &packet->base;
        sourceAddresses[numPacketsReceived] = {srcIp};
        ++numPacketsReceived;
    }

    return numPacketsReceived;
}

// See Driver::releasePackets()
void
DpdkDriver::Impl::releasePackets(Driver::Packet* packets[], uint16_t numPackets)
{
    for (uint16_t i = 0; i < numPackets; ++i) {
        SpinLock::Lock lock(packetLock);
        DpdkDriver::Impl::Packet* packet =
            container_of(packets[i], DpdkDriver::Impl::Packet, base);
        if (likely(packet->bufType == DpdkDriver::Impl::Packet::MBUF)) {
            rte_pktmbuf_free(packet->bufRef.mbuf);
            mbufsOutstanding--;
        } else {
            overflowBufferPool.destroy(packet->bufRef.overflowBuf);
        }
        packetPool.destroy(packet);
    }
}

// See Driver::getHighestPacketPriority()
int
DpdkDriver::Impl::getHighestPacketPriority()
{
    return HIGHEST_PACKET_PRIORITY;
}

// See Driver::getMaxPayloadSize()
uint32_t
DpdkDriver::Impl::getMaxPayloadSize()
{
    return MAX_PAYLOAD_SIZE;
}

// See Driver::getBandwidth()
uint32_t
DpdkDriver::Impl::getBandwidth()
{
    return bandwidthMbps;
}

// See Driver::getLocalAddress()
IpAddress
DpdkDriver::Impl::getLocalAddress()
{
    return localIp;
}

// See Driver::getQueuedBytes();
uint32_t
DpdkDriver::Impl::getQueuedBytes()
{
    SpinLock::Lock lock(tx.stats.mutex);
    return tx.stats.bufferedBytes + tx.stats.queueEstimator.getQueuedBytes();
}

/**
 * Initialized DPDK EAL.
 *
 * @param argc
 *      Parameter passed to rte_eal_init().
 * @param argv
 *      Parameter passed to rte_eal_init().
 * @throw DriverInitFailure
 *      Thrown if EAL initilization fails.
 */
void
DpdkDriver::Impl::_eal_init(int argc, char* argv[])
{
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        throw DriverInitFailure(HERE_STR,
                                "rte_eal_init failed; Invalid EAL arguments");
    }
}

/**
 * Does most of the real work on initializing the DpdkDriver during
 * construction.
 *
 * Separated out to be used by different constructor methods.
 */
void
DpdkDriver::Impl::_init()
{
    struct rte_eth_conf portConf;
    int ret;
    uint16_t mtu;

    // Populate the ARP table with records in /proc/net/arp (inspired by
    // net-tools/arp.c)
    std::ifstream input("/proc/net/arp");
    for (std::string line; getline(input, line);) {
        char ip[100];
        char hwa[100];
        char mask[100];
        char dev[100];
        int type, flags;
        int cols = sscanf(line.c_str(), "%s 0x%x 0x%x %99s %99s %99s\n", ip,
                          &type, &flags, hwa, mask, dev);
        if (cols != 6)
            continue;
        arpTable.emplace(IpAddress::fromString(ip), hwa);
    }

    // Use ioctl to obtain the IP and MAC addresses of the network interface.
    struct ifreq ifr;
    ifname.copy(ifr.ifr_name, ifname.length());
    ifr.ifr_name[ifname.length() + 1] = 0;
    if (ifname.length() >= sizeof(ifr.ifr_name)) {
        throw DriverInitFailure(
            HERE_STR,
            StringUtil::format("Interface name %s too long", ifname.c_str()));
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        throw DriverInitFailure(
            HERE_STR,
            StringUtil::format("Failed to create socket: %s", strerror(errno)));
    }

    if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
        char* error = strerror(errno);
        close(fd);
        throw DriverInitFailure(
            HERE_STR,
            StringUtil::format("Failed to obtain IP address: %s", error));
    }
    localIp = {be32toh(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr)};

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
        char* error = strerror(errno);
        close(fd);
        throw DriverInitFailure(
            HERE_STR,
            StringUtil::format("Failed to obtain MAC address: %s", error));
    }
    close(fd);
    memcpy(localMac.address, ifr.ifr_hwaddr.sa_data, 6);

    // Iterate over ethernet devices to locate the port identifier.
    int p;
    RTE_ETH_FOREACH_DEV(p)
    {
        struct ether_addr mac;
        rte_eth_macaddr_get(p, &mac);
        if (MacAddress(mac.addr_bytes) == localMac) {
            port = p;
            break;
        }
    }
    NOTICE("Using interface %s, ip %s, mac %s, port %u", ifname.c_str(),
           IpAddress::toString(localIp).c_str(), localMac.toString().c_str(),
           port);

    std::string poolName = StringUtil::format("homa_mbuf_pool_%u", port);
    std::string ringName = StringUtil::format("homa_loopback_ring_%u", port);

    NOTICE("Using DPDK version %s", rte_version());

    // create an memory pool for accommodating packet buffers
    mbufPool =
        rte_pktmbuf_pool_create(poolName.c_str(), NB_MBUF, MEMPOOL_CACHE_SIZE,
                                0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!mbufPool) {
        throw DriverInitFailure(
            HERE_STR, StringUtil::format(
                          "Failed to allocate memory for packet buffers: %s",
                          rte_strerror(rte_errno)));
    }

    // ensure that DPDK was able to detect a compatible and available NIC
    if (!rte_eth_dev_is_valid_port(port)) {
        throw DriverInitFailure(
            HERE_STR,
            StringUtil::format("Ethernet port %u doesn't exist", port));
    }

    // configure some default NIC port parameters
    memset(&portConf, 0, sizeof(portConf));
    portConf.rxmode.max_rx_pkt_len = ETHER_MAX_VLAN_FRAME_LEN;
    rte_eth_dev_configure(port, 1, 1, &portConf);

    // Set up a NIC/HW-based filter on the ethernet type so that only
    // traffic to a particular port is received by this driver.
    struct rte_eth_ethertype_filter filter;
    ret = rte_eth_dev_filter_supported(port, RTE_ETH_FILTER_ETHERTYPE);
    if (ret < 0) {
        NOTICE("ethertype filter is not supported on port %u.", port);
        hasHardwareFilter = false;
    } else {
        memset(&filter, 0, sizeof(filter));
        ret = rte_eth_dev_filter_ctrl(port, RTE_ETH_FILTER_ETHERTYPE,
                                      RTE_ETH_FILTER_ADD, &filter);
        if (ret < 0) {
            WARNING("failed to add ethertype filter\n");
            hasHardwareFilter = false;
        }
    }

    // setup and initialize the receive and transmit NIC queues,
    // and activate the port.
    rte_eth_rx_queue_setup(port, 0, NDESC, rte_eth_dev_socket_id(port), NULL,
                           mbufPool);
    rte_eth_tx_queue_setup(port, 0, NDESC, rte_eth_dev_socket_id(port), NULL);

    // Install tx callback to track NIC queue length.
    if (rte_eth_add_tx_callback(port, 0, txBurstCallback, &tx.stats) == NULL) {
        throw DriverInitFailure(
            HERE_STR,
            StringUtil::format("Cannot set tx callback on port %u", port));
    }

    // Initialize TX buffers
    tx.buffer = static_cast<rte_eth_dev_tx_buffer*>(
        rte_zmalloc_socket("tx_buffer", RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST),
                           0, rte_eth_dev_socket_id(port)));
    if (tx.buffer == NULL) {
        throw DriverInitFailure(
            HERE_STR, StringUtil::format(
                          "Cannot allocate buffer for tx on port %u", port));
    }
    rte_eth_tx_buffer_init(tx.buffer, MAX_PKT_BURST);

    // get the current MTU.
    ret = rte_eth_dev_get_mtu(port, &mtu);
    if (ret < 0) {
        throw DriverInitFailure(
            HERE_STR,
            StringUtil::format("rte_eth_dev_get_mtu on port %u returned "
                               "ENODEV; unable to read current mtu",
                               port));
    }
    // set the MTU that the NIC port should support
    if (mtu != MAX_PAYLOAD_SIZE) {
        ret = rte_eth_dev_set_mtu(port, MAX_PAYLOAD_SIZE);
        if (ret != 0) {
            throw DriverInitFailure(
                HERE_STR,
                StringUtil::format("Failed to set the MTU on Ethernet port %u: "
                                   "%s; current MTU is %u",
                                   port, strerror(ret), mtu));
        }
        mtu = MAX_PAYLOAD_SIZE;
    }

    ret = rte_eth_dev_start(port);
    if (ret != 0) {
        throw DriverInitFailure(
            HERE_STR,
            StringUtil::format("Couldn't start port %u, error %d (%s)", port,
                               ret, strerror(ret)));
    }

    // Retrieve the link speed and compute information based on it.
    struct rte_eth_link link;
    rte_eth_link_get(port, &link);
    if (!link.link_status) {
        throw DriverInitFailure(
            HERE_STR, StringUtil::format(
                          "Failed to detect a link on Ethernet port %u", port));
    }
    if (link.link_speed != ETH_SPEED_NUM_NONE) {
        // Be conservative about the link speed. We use bandwidth in
        // QueueEstimator to estimate # bytes outstanding in the NIC's
        // TX queue. If we overestimate the bandwidth, under high load,
        // we may keep queueing packets faster than the NIC can consume,
        // and build up a queue in the TX queue.
        bandwidthMbps = (uint32_t)(link.link_speed * 0.98);
    } else {
        WARNING(
            "Can't retrieve network bandwidth from DPDK; "
            "using default of %d Mbps",
            bandwidthMbps.load());
    }
    // Reset the queueEstimator with the updated bandwidth.
    new (&tx.stats.queueEstimator)
        Util::QueueEstimator<std::chrono::steady_clock>(bandwidthMbps);

    // create an in-memory ring, used as a software loopback in order to
    // handle packets that are addressed to the localhost.
    loopbackRing =
        rte_ring_create(ringName.c_str(), NB_LOOPBACK_SLOTS, SOCKET_ID_ANY, 0);
    if (NULL == loopbackRing) {
        throw DriverInitFailure(
            HERE_STR, StringUtil::format("Failed to allocate loopback ring: %s",
                                         rte_strerror(rte_errno)));
    }

    NOTICE("DpdkDriver address: %s, bandwidth: %d Mbits/sec, MTU: %u",
           localMac.toString().c_str(), bandwidthMbps.load(), mtu);
}

/**
 * Called before a burst of packets is transmitted to update the transmit stats.
 *
 * This callback's signature is defined by DPDK.
 *
 * @param port_id
 *      The Ethernet port on which TX is being performed.
 * @param queue
 *      The queue on the Ethernet port which is being used to transmit the
 *      packets.
 * @param pkts
 *      The burst of packets that are about to be transmitted.
 * @param nb_pkts
 *      The number of packets in the burst pointed to by "pkts".
 * @param user_param
 *      The arbitrary user parameter passed in by the application when the
 *      callback was originally configured.
 * @return
 *      The number of packets to be written to the NIC.
 */
uint16_t
DpdkDriver::Impl::txBurstCallback(uint16_t port_id, uint16_t queue,
                                  struct rte_mbuf* pkts[], uint16_t nb_pkts,
                                  void* user_param)
{
    (void)port_id;
    (void)queue;
    uint64_t bytesToSend = 0;
    for (uint16_t i = 0; i < nb_pkts; ++i) {
        bytesToSend += rte_pktmbuf_pkt_len(pkts[i]);
    }
    Tx::Stats* stats = static_cast<Tx::Stats*>(user_param);
    SpinLock::Lock lock(stats->mutex);
    assert(bytesToSend <= stats->bufferedBytes);
    stats->bufferedBytes -= bytesToSend;
    stats->queueEstimator.signalBytesSent(bytesToSend);
    return nb_pkts;
}

}  // namespace DPDK
}  // namespace Drivers
}  // namespace Homa
