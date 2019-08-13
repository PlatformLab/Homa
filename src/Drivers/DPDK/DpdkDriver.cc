/* Copyright (c) 2015-2019, Stanford University
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

#include <unistd.h>

#include <rte_malloc.h>

#include "CodeLocation.h"
#include "StringUtil.h"

namespace Homa {

namespace Drivers {
namespace DPDK {

/**
 * Construct a DPDK Packet backed by a DPDK mbuf.
 *
 * @param mbuf
 *      Pointer to the DPDK mbuf that holds this packet.
 * @param data
 *      Memory location in the mbuf where the packet data should be stored.
 */
Internal::Packet::Packet(struct rte_mbuf* mbuf, void* data)
    : Driver::Packet(data, 0)
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
Internal::Packet::Packet(OverflowBuffer* overflowBuf)
    : Driver::Packet(overflowBuf->data, 0)
    , bufType(OVERFLOW_BUF)
    , bufRef()
{
    bufRef.overflowBuf = overflowBuf;
}

/**
 * Constructor for the internal state of a DpdkDriver.
 */
Internal::Internal(uint16_t port)
    : port(port)
    , localMac(MacAddress(Driver::Address(0)))
    , packetLock()
    , packetPool()
    , overflowBufferPool()
    , mbufPool(nullptr)
    , loopbackRing(nullptr)
    , rx()
    , tx()
    , hasHardwareFilter(true)  // Cleared later if not applicable
    , corked(false)
    , bandwidthMbps(10000)  // Default bandwidth = 10 gbs
{}

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
DpdkDriver::DpdkDriver(int port)
    : DpdkDriver(port, default_eal_argc, const_cast<char**>(default_eal_argv))
{}

/**
 * Construct a DpdkDriver and initialize the DPDK EAL using the provided
 * _argc_ and _argv_. [Advanced Usage]
 *
 * This constructor should be used if the caller wants to control what
 * parameters are provided to DPDK EAL initialization. The input parameters
 * _argc_ and _argv_ will be provided to rte_eal_init() directly. See the
 * DPDK documentation for initialization options.
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
DpdkDriver::DpdkDriver(int port, int argc, char* argv[])
    : members()
{
    // Construct the private members;
    static_assert(sizeof(members) == sizeof(Internal));
    Internal* d = new (members) Internal(Homa::Util::downCast<uint16_t>(port));

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

    d->_eal_init(argc, argv);
    d->_init();

    // restore the original thread affinity
    s = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
    if (s != 0) {
        throw DriverInitFailure(HERE_STR,
                                "Unable to restore original thread affinity");
    }
}

/**
 * Construct a DpdkDriver without DPDK EAL initialization. [Advanced Usage]
 *
 * This constructor is used when parts of the application other than the
 * DpdkDriver are using DPDK and the caller wants to take responsibility for
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
DpdkDriver::DpdkDriver(int port, __attribute__((__unused__)) NoEalInit _)
    : members()
{
    // Construct the private members;
    Internal* d = new (members) Internal(Homa::Util::downCast<uint16_t>(port));
    d->_init();
}

/**
 * DpdkDriver destructor.
 */
DpdkDriver::~DpdkDriver()
{
    Internal* d = reinterpret_cast<Internal*>(members);
    // Free the various allocated resources (e.g. ring, mempool) and close
    // the NIC.
    rte_ring_free(d->loopbackRing);
    rte_eth_dev_stop(d->port);
    rte_eth_dev_close(d->port);
    rte_mempool_free(d->mbufPool);
}

// See Driver::getAddress()
Driver::Address
DpdkDriver::getAddress(std::string const* const addressString)
{
    return MacAddress(addressString->c_str()).toAddress();
}

// See Driver::getAddress()
Driver::Address
DpdkDriver::getAddress(Driver::WireFormatAddress const* const wireAddress)
{
    return MacAddress(wireAddress).toAddress();
}

/// See Driver::addressToString()
std::string
DpdkDriver::addressToString(const Driver::Address address)
{
    return MacAddress(address).toString();
}

/// See Driver::addressToWireFormat()
void
DpdkDriver::addressToWireFormat(const Driver::Address address,
                                Driver::WireFormatAddress* wireAddress)
{
    MacAddress(address).toWireFormat(wireAddress);
}

// See Driver::allocPacket()
Driver::Packet*
DpdkDriver::allocPacket()
{
    Internal* d = reinterpret_cast<Internal*>(members);
    Internal::Packet* packet = d->_allocMbufPacket();
    if (unlikely(packet == nullptr)) {
        SpinLock::Lock lock(d->packetLock);
        OverflowBuffer* buf = d->overflowBufferPool.construct();
        packet = d->packetPool.construct(buf);
        NOTICE("OverflowBuffer used.");
    }
    return packet;
}

// See Driver::sendPacket()
void
DpdkDriver::sendPacket(Driver::Packet* packet)
{
    Internal* d = reinterpret_cast<Internal*>(members);

    Internal::Packet* pkt = static_cast<Internal::Packet*>(packet);
    struct rte_mbuf* mbuf = nullptr;
    // If the packet is held in an Overflow buffer, we need to copy it out
    // into a new mbuf.
    if (unlikely(pkt->bufType == Internal::Packet::OVERFLOW_BUF)) {
        mbuf = rte_pktmbuf_alloc(d->mbufPool);
        if (unlikely(NULL == mbuf)) {
            uint32_t numMbufsAvail = rte_mempool_avail_count(d->mbufPool);
            uint32_t numMbufsInUse = rte_mempool_in_use_count(d->mbufPool);
            WARNING(
                "Failed to allocate a packet buffer; dropping packet; "
                "Failed to allocate a packet buffer; dropping packet; "
                "%u mbufs available, %u mbufs in use",
                numMbufsAvail, numMbufsInUse);
            return;
        }
        char* buf = rte_pktmbuf_append(
            mbuf, Homa::Util::downCast<uint16_t>(PACKET_HDR_LEN + pkt->length));
        if (unlikely(NULL == buf)) {
            WARNING("rte_pktmbuf_append call failed; dropping packet");
            rte_pktmbuf_free(mbuf);
            return;
        }
        char* data = buf + PACKET_HDR_LEN;
        rte_memcpy(data, pkt->payload, pkt->length);
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
    MacAddress macAddr(pkt->address);
    struct ether_hdr* ethHdr = rte_pktmbuf_mtod(mbuf, struct ether_hdr*);
    rte_memcpy(&ethHdr->d_addr, macAddr.address, ETHER_ADDR_LEN);
    rte_memcpy(&ethHdr->s_addr, d->localMac.load().address, ETHER_ADDR_LEN);
    ethHdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_VLAN);

    // Fill out the PCP field and the Ethernet frame type of the
    // encapsulated frame (DEI and VLAN ID are not relevant and trivially
    // set to 0).
    struct vlan_hdr* vlanHdr = reinterpret_cast<struct vlan_hdr*>(ethHdr + 1);
    vlanHdr->vlan_tci = rte_cpu_to_be_16(PRIORITY_TO_PCP[pkt->priority]);
    vlanHdr->eth_proto = rte_cpu_to_be_16(EthPayloadType::HOMA);

    // In the normal case, we pre-allocate a pakcet's mbuf with enough
    // storage to hold the MAX_PAYLOAD_SIZE.  If the actual payload is
    // smaller, trim the mbuf to size to avoid sending unecessary bits.
    uint32_t actualLength = PACKET_HDR_LEN + pkt->length;
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
    if (d->localMac.load().toAddress() == pkt->address) {
        struct rte_mbuf* mbuf_clone = rte_pktmbuf_clone(mbuf, d->mbufPool);
        if (unlikely(mbuf_clone == NULL)) {
            WARNING("Failed to clone packet for loopback; dropping packet");
        }
        int ret = rte_ring_enqueue(d->loopbackRing, mbuf_clone);
        if (unlikely(ret != 0)) {
            WARNING("rte_ring_enqueue returned %d; packet may be lost?", ret);
            rte_pktmbuf_free(mbuf_clone);
        }
        return;
    }

    // If the packet is held in an mbuf, retain access to it so that the
    // processing of sending the mbuf won't free it.
    if (likely(pkt->bufType == Internal::Packet::MBUF)) {
        rte_pktmbuf_refcnt_update(mbuf, 1);
    }

    // Add the packet to the burst.
    SpinLock::Lock txLock(d->tx.mutex);
    d->tx.stats.bufferedBytes += rte_pktmbuf_pkt_len(mbuf);
    rte_eth_tx_buffer(d->port, 0, d->tx.buffer, mbuf);

    // Flush packets now if the driver is not corked.
    if (!d->corked) {
        rte_eth_tx_buffer_flush(d->port, 0, d->tx.buffer);
    }
}

// See Driver::cork()
void
DpdkDriver::cork()
{
    Internal* d = reinterpret_cast<Internal*>(members);
    d->corked.store(true);
}

// See Driver::uncork()
void
DpdkDriver::uncork()
{
    Internal* d = reinterpret_cast<Internal*>(members);
    SpinLock::Lock txLock(d->tx.mutex);
    d->corked.store(false);
    rte_eth_tx_buffer_flush(d->port, 0, d->tx.buffer);
}

// See Driver::receivePackets()
uint32_t
DpdkDriver::receivePackets(uint32_t maxPackets,
                           Driver::Packet* receivedPackets[])
{
    Internal* d = reinterpret_cast<Internal*>(members);
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
        SpinLock::Lock lock(d->rx.mutex);
        incomingPkts = rte_eth_rx_burst(
            d->port, 0, mPkts, Homa::Util::downCast<uint16_t>(maxPackets));
    }

    uint32_t loopbackPkts = rte_ring_count(d->loopbackRing);
    if (incomingPkts + loopbackPkts > maxPackets) {
        loopbackPkts = maxPackets - incomingPkts;
    }
    for (uint32_t i = 0; i < loopbackPkts; i++) {
        rte_ring_dequeue(d->loopbackRing,
                         reinterpret_cast<void**>(&mPkts[incomingPkts + i]));
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
        if (!d->hasHardwareFilter) {
            // Perform packet filtering by software to skip irrelevant
            // packets such as ipmi or kernel TCP/IP traffic.
            if (ether_type != rte_cpu_to_be_16(EthPayloadType::HOMA)) {
                VERBOSE("packet filtered; ether_type = %x", ether_type);
                rte_pktmbuf_free(m);
                continue;
            }
        }

        uint32_t length = rte_pktmbuf_pkt_len(m) - headerLength;
        assert(length <= MAX_PAYLOAD_SIZE);

        Internal::Packet* packet = nullptr;
        {
            SpinLock::Lock lock(d->packetLock);
            packet = d->packetPool.construct(m, payload);
        }
        packet->address = MacAddress(ethHdr->s_addr.addr_bytes).toAddress();
        packet->length = length;

        receivedPackets[numPacketsReceived++] = packet;
    }

    return numPacketsReceived;
}

// See Driver::releasePackets()
void
DpdkDriver::releasePackets(Driver::Packet* packets[], uint16_t numPackets)
{
    Internal* d = reinterpret_cast<Internal*>(members);
    for (uint16_t i = 0; i < numPackets; ++i) {
        SpinLock::Lock lock(d->packetLock);
        Internal::Packet* packet = static_cast<Internal::Packet*>(packets[i]);
        if (likely(packet->bufType == Internal::Packet::MBUF)) {
            rte_pktmbuf_free(packet->bufRef.mbuf);
        } else {
            d->overflowBufferPool.destroy(packet->bufRef.overflowBuf);
        }
        d->packetPool.destroy(packet);
    }
}

// See Driver::getHighestPacketPriority()
int
DpdkDriver::getHighestPacketPriority()
{
    return Homa::Util::arrayLength(PRIORITY_TO_PCP) - 1;
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
    Internal* d = reinterpret_cast<Internal*>(members);
    return d->bandwidthMbps;
}

// See Driver::getLocalAddress()
Driver::Address
DpdkDriver::getLocalAddress()
{
    Internal* d = reinterpret_cast<Internal*>(members);
    return d->localMac.load().toAddress();
}

void
DpdkDriver::setLocalAddress(std::string const* const addressString)
{
    Internal* d = reinterpret_cast<Internal*>(members);
    d->localMac.store(MacAddress(addressString->c_str()));
    NOTICE("Driver address override; new address: %s",
           d->localMac.load().toString().c_str());
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
Internal::_eal_init(int argc, char* argv[])
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
Internal::_init()
{
    struct ether_addr mac;
    struct rte_eth_conf portConf;
    int ret;
    uint16_t mtu;

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

    // Read the MAC address from the NIC via DPDK.
    rte_eth_macaddr_get(port, &mac);
    localMac.store(MacAddress(mac.addr_bytes));

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
    ret = rte_eth_tx_buffer_set_err_callback(tx.buffer, txBurstErrorCallback,
                                             &tx.stats);
    if (ret < 0) {
        throw DriverInitFailure(
            HERE_STR,
            StringUtil::format(
                "Cannot set error callback for tx buffer on port %u", port));
    }

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

    // create an in-memory ring, used as a software loopback in order to
    // handle packets that are addressed to the localhost.
    loopbackRing = rte_ring_create(ringName.c_str(), 4096, SOCKET_ID_ANY, 0);
    if (NULL == loopbackRing) {
        throw DriverInitFailure(
            HERE_STR, StringUtil::format("Failed to allocate loopback ring: %s",
                                         rte_strerror(rte_errno)));
    }

    NOTICE("DpdkDriver address: %s, bandwidth: %d Mbits/sec, MTU: %u",
           localMac.load().toString().c_str(), bandwidthMbps.load(), mtu);
}

/**
 * Helper function to try to allocation a new Dpdk Packet backed by an mbuf.
 *
 * @return
 *      The newly allocated Dpdk Packet; nullptr if the mbuf allocation
 * failed.
 */
Internal::Packet*
Internal::_allocMbufPacket()
{
    Internal::Packet* packet = nullptr;
    uint32_t numMbufsAvail = rte_mempool_avail_count(mbufPool);
    if (unlikely(numMbufsAvail <= NB_MBUF_RESERVED)) {
        uint32_t numMbufsInUse = rte_mempool_in_use_count(mbufPool);
        NOTICE(
            "Driver is running low on mbuf packet buffers; "
            "%u mbufs available, %u mbufs in use",
            numMbufsAvail, numMbufsInUse);
        return nullptr;
    }

    struct rte_mbuf* mbuf = rte_pktmbuf_alloc(mbufPool);

    if (unlikely(NULL == mbuf)) {
        uint32_t numMbufsAvail = rte_mempool_avail_count(mbufPool);
        uint32_t numMbufsInUse = rte_mempool_in_use_count(mbufPool);
        NOTICE(
            "Failed to allocate an mbuf packet buffer; "
            "%u mbufs available, %u mbufs in use",
            numMbufsAvail, numMbufsInUse);
        return nullptr;
    }

    char* buf = rte_pktmbuf_append(
        mbuf,
        Homa::Util::downCast<uint16_t>(PACKET_HDR_LEN + MAX_PAYLOAD_SIZE));

    if (unlikely(NULL == buf)) {
        NOTICE("rte_pktmbuf_append call failed; dropping packet");
        rte_pktmbuf_free(mbuf);
        return nullptr;
    }

    // Perform packet operations with the lock held.
    {
        SpinLock::Lock _(packetLock);
        packet = packetPool.construct(mbuf, buf + PACKET_HDR_LEN);
    }
    return packet;
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
Internal::txBurstCallback(uint16_t port_id, uint16_t queue,
                          struct rte_mbuf* pkts[], uint16_t nb_pkts,
                          void* user_param)
{
    (void)port_id;
    (void)queue;
    // This method should only be called while processing a tx_burst which would
    // only be called during a tx_buffer or tx_buffer_flush.  The tx.mutex is
    // assumed to be held during this call.
    Tx::Stats* stats = static_cast<Tx::Stats*>(user_param);
    uint64_t bytesToSend = 0;
    for (uint16_t i = 0; i < nb_pkts; ++i) {
        bytesToSend += rte_pktmbuf_pkt_len(pkts[i]);
    }
    assert(bytesToSend <= stats->bufferedBytes);
    stats->bufferedBytes -= bytesToSend;
    return nb_pkts;
}

/**
 * Called to process the packets cannot be sent.
 */
void
Internal::txBurstErrorCallback(struct rte_mbuf* pkts[], uint16_t unsent,
                               void* userdata)
{
    // This method should only be called while processing a tx_burst which would
    // only be called during a tx_buffer or tx_buffer_flush.  The tx.mutex is
    // assumed to be held during this call.
    Tx::Stats* stats = static_cast<Tx::Stats*>(userdata);
    uint64_t bytesDropped = 0;
    for (int i = 0; i < unsent; ++i) {
        bytesDropped += rte_pktmbuf_pkt_len(pkts[i]);
        rte_pktmbuf_free(pkts[i]);
    }
    assert(bytesDropped <= stats->bufferedBytes);
    stats->bufferedBytes -= bytesDropped;
}

}  // namespace DPDK
}  // namespace Drivers
}  // namespace Homa
